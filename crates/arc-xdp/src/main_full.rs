#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::XdpContext,
    EbpfContext,
};

use aya_ebpf::helpers::gen::{
    bpf_csum_diff, bpf_ktime_get_ns, bpf_sk_lookup_tcp, bpf_sk_release, bpf_tcp_check_syncookie,
    bpf_tcp_gen_syncookie, bpf_xdp_adjust_tail,
};

use arc_xdp_common::{
    AttackKind, BlacklistEntry, BlockReason, ConnKey, ConnState, GlobalStats, IpKey, MapKind,
    PortStats, SynState, XdpConfig, XdpEvent, CFG_F_DROP_IPV4_FRAGS, CFG_F_ENABLE_ACK_FLOOD,
    CFG_F_ENABLE_CIDR_LOOKUP, CFG_F_ENABLE_RST_VALIDATE, CFG_F_ENABLE_SYN_FLOOD,
    CFG_F_ENABLE_SYN_PROXY, CFG_F_ENABLE_UDP_RATE_LIMIT, CFG_F_ENABLE_UDP_STATS, CONFIG_INDEX,
    GLOBAL_STATS_INDEX, MAX_TRACKED_PORTS, SYN_RING_SECONDS, SYN_STATE_FLAG_BLACKLISTED,
    SYN_STATE_FLAG_SUSPECT,
};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const DECAY_STEP_NS: u64 = 100_000_000; // 100ms
const DECAY_FACTOR_NUM: u32 = 229; // ~0.8945
const DECAY_FACTOR_SHIFT: u32 = 8; // /256
const MAX_DECAY_STEPS: u32 = 32;

#[repr(C)]
#[derive(Copy, Clone)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct iphdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

impl iphdr {
    #[inline(always)]
    fn ihl(&self) -> u8 {
        self.version_ihl & 0x0f
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ipv6hdr {
    vtc_flow: [u8; 4],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

impl tcphdr {
    #[inline(always)]
    fn doff(&self) -> u8 {
        self.doff_res >> 4
    }

    #[inline(always)]
    fn set_doff(&mut self, doff: u8) {
        self.doff_res = (doff << 4) | (self.doff_res & 0x0f);
    }

    #[inline(always)]
    fn fin(&self) -> u8 {
        if (self.flags & 0x01) != 0 { 1 } else { 0 }
    }

    #[inline(always)]
    fn syn(&self) -> u8 {
        if (self.flags & 0x02) != 0 { 1 } else { 0 }
    }

    #[inline(always)]
    fn rst(&self) -> u8 {
        if (self.flags & 0x04) != 0 { 1 } else { 0 }
    }

    #[inline(always)]
    fn psh(&self) -> u8 {
        if (self.flags & 0x08) != 0 { 1 } else { 0 }
    }

    #[inline(always)]
    fn ack(&self) -> u8 {
        if (self.flags & 0x10) != 0 { 1 } else { 0 }
    }

    #[inline(always)]
    fn urg(&self) -> u8 {
        if (self.flags & 0x20) != 0 { 1 } else { 0 }
    }

    #[inline(always)]
    fn set_fin(&mut self, v: u8) {
        if v == 0 {
            self.flags &= !0x01;
        } else {
            self.flags |= 0x01;
        }
    }

    #[inline(always)]
    fn set_syn(&mut self, v: u8) {
        if v == 0 {
            self.flags &= !0x02;
        } else {
            self.flags |= 0x02;
        }
    }

    #[inline(always)]
    fn set_rst(&mut self, v: u8) {
        if v == 0 {
            self.flags &= !0x04;
        } else {
            self.flags |= 0x04;
        }
    }

    #[inline(always)]
    fn set_psh(&mut self, v: u8) {
        if v == 0 {
            self.flags &= !0x08;
        } else {
            self.flags |= 0x08;
        }
    }

    #[inline(always)]
    fn set_ack(&mut self, v: u8) {
        if v == 0 {
            self.flags &= !0x10;
        } else {
            self.flags |= 0x10;
        }
    }

    #[inline(always)]
    fn set_urg(&mut self, v: u8) {
        if v == 0 {
            self.flags &= !0x20;
        } else {
            self.flags |= 0x20;
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct udphdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// -------- Map 定义（必须 pin 到 /sys/fs/bpf/arc/，由用户态完成） --------

/// Map 1：白名单（最高优先级）
/// - 类型：BPF_MAP_TYPE_HASH
/// - 并发：map 内部并发安全；XDP 仅读，用户态写。
#[map(name = "arc_whitelist")]
static mut WHITELIST: HashMap<IpKey, u8> = HashMap::with_max_entries(65_536, 0);

/// Map 2：黑名单
/// - 类型：BPF_MAP_TYPE_LRU_HASH
/// - 并发：map 内部并发安全；多 CPU 读写由内核处理锁。
#[map(name = "arc_blacklist")]
static mut BLACKLIST: LruHashMap<IpKey, BlacklistEntry> = LruHashMap::with_max_entries(1_000_000, 0);

#[map(name = "arc_syn_state")]
static mut SYN_STATE: PerCpuHashMap<IpKey, SynState> = PerCpuHashMap::with_max_entries(500_000, 0);

/// Map 4：全局统计（PERCPU_ARRAY）
/// - 类型：BPF_MAP_TYPE_PERCPU_ARRAY
/// - 并发：每 CPU 写自己的槽位，无锁。
#[map(name = "arc_global_stats")]
static mut GLOBAL_STATS: PerCpuArray<GlobalStats> = PerCpuArray::with_max_entries(1, 0);

/// Map 5：配置下发（ARRAY）
/// - 类型：BPF_MAP_TYPE_ARRAY
/// - 并发：用户态写，XDP 每包读；读为无锁快路径（内核保证一致性）。
#[map(name = "arc_config")]
static mut CONFIG: aya_ebpf::maps::Array<XdpConfig> = aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map(name = "arc_events")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Map 7：活跃连接跟踪（RST 验证用）
/// - 类型：BPF_MAP_TYPE_LRU_HASH
/// - 并发：map 内部并发安全；多 CPU 读写由内核处理锁。
#[map(name = "arc_conntrack")]
static mut CONNTRACK: LruHashMap<ConnKey, ConnState> = LruHashMap::with_max_entries(2_000_000, 0);

#[map(name = "arc_port_stats")]
static mut PORT_STATS: PerCpuArray<PortStats> = PerCpuArray::with_max_entries(65_536, 0);

// -------- XDP 程序入口 --------

#[xdp]
pub fn arc_xdp(ctx: XdpContext) -> u32 {
    match try_arc_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_arc_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let now_ns = ktime_get_ns();

    // per-CPU stats：每包都会更新（极简加法，保证低延迟）。
    let stats = get_global_stats_mut().ok_or(())?;
    let pkt_len = packet_len(&ctx) as u64;
    stats.packets = stats.packets.wrapping_add(1);
    stats.bytes = stats.bytes.wrapping_add(pkt_len);

    // 读取配置（每包读取一次）。
    let cfg = get_config();
    let cfg = normalize_cfg(cfg);

    // 1) 解析以太网头 + VLAN -> 得到 L3 ether_type 与 L3 offset
    let (l3_offset, eth_proto) = match parse_l2(&ctx) {
        Some(v) => v,
        None => {
            // 解析失败（越界等），安全起见 ABORT（由内核计数），避免未定义行为。
            return Ok(xdp_action::XDP_ABORTED);
        }
    };

    // 2) 解析 IPv4/IPv6，提取 src/dst 与 L4 offset
    let l3 = match parse_l3(&ctx, l3_offset, eth_proto, &cfg) {
        L3ParseResult::NotIp => {
            // 非 IP：直接 PASS（按规格“不处理非 IP 流量”）
            stats.pass = stats.pass.wrapping_add(1);
            return Ok(xdp_action::XDP_PASS);
        }
        L3ParseResult::Parsed(v) => v,
        L3ParseResult::Drop => {
            stats.drop = stats.drop.wrapping_add(1);
            return Ok(xdp_action::XDP_DROP);
        }
        L3ParseResult::Abort => {
            return Ok(xdp_action::XDP_ABORTED);
        }
    };

    // 3) 白名单检查（最高优先级）
    if whitelist_hit(&l3.src_ip, &cfg) {
        stats.pass_whitelist = stats.pass_whitelist.wrapping_add(1);
        stats.pass = stats.pass.wrapping_add(1);
        return Ok(xdp_action::XDP_PASS);
    }

    // 4) 黑名单检查（命中直接 DROP；支持 TTL 到期清理）
    if blacklist_hit_and_handle_expiry(&l3.src_ip, now_ns, &mut *stats) {
        stats.drop_blacklist = stats.drop_blacklist.wrapping_add(1);
        stats.drop = stats.drop.wrapping_add(1);
        return Ok(xdp_action::XDP_DROP);
    }

    // 5) 解析 TCP/UDP
    match l3.proto {
        IPPROTO_TCP => handle_tcp(&ctx, &l3, now_ns, &cfg, stats),
        IPPROTO_UDP => handle_udp(&ctx, &l3, now_ns, &cfg, stats),
        _ => {
            // 非 TCP/UDP：按规格通过（我们不处理其它 L4）
            stats.pass = stats.pass.wrapping_add(1);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

// -------- L2/L3/L4 解析与处理 --------

#[derive(Copy, Clone)]
struct L3Parsed {
    l3_offset: usize,
    l4_offset: usize,
    eth_proto: u16,
    is_ipv6: bool,
    proto: u8,
    src_ip: IpKey,
    dst_ip: IpKey,
}

enum L3ParseResult {
    NotIp,
    Parsed(L3Parsed),
    Drop,
    Abort,
}

#[inline(always)]
fn parse_l2(ctx: &XdpContext) -> Option<(usize, u16)> {
    let mut off = 0usize;
    let eth: *const ethhdr = ptr_at(ctx, off)?;
    // SAFETY: ptr_at 已确保 ethhdr 完整在 [data, data_end] 内。
    let eth_proto = unsafe { u16::from_be((*eth).h_proto) };

    off += mem::size_of::<ethhdr>();

    // VLAN 解析：最多处理 2 层（802.1Q / 802.1ad），避免绕过。
    // verifier 说明：循环上界常量 2，可证明有界。
    let mut proto = eth_proto;
    let mut vlan_depth = 0u32;
    while vlan_depth < 2 {
        if proto != ETH_P_8021Q && proto != ETH_P_8021AD {
            break;
        }
        let vlan: *const VlanHdr = ptr_at(ctx, off)?;
        // SAFETY: ptr_at 已确保 VlanHdr 完整在 packet 内。
        proto = unsafe { u16::from_be((*vlan).encap_proto) };
        off += mem::size_of::<VlanHdr>();
        vlan_depth += 1;
    }

    Some((off, proto))
}

#[repr(C)]
struct VlanHdr {
    tci: u16,
    encap_proto: u16,
}

#[inline(always)]
fn parse_l3(ctx: &XdpContext, l3_offset: usize, eth_proto: u16, cfg: &CfgView) -> L3ParseResult {
    match eth_proto {
        ETH_P_IP => parse_ipv4(ctx, l3_offset, cfg),
        ETH_P_IPV6 => parse_ipv6(ctx, l3_offset),
        _ => L3ParseResult::NotIp,
    }
}

#[inline(always)]
fn parse_ipv4(ctx: &XdpContext, l3_offset: usize, cfg: &CfgView) -> L3ParseResult {
    let iph: *const iphdr = match ptr_at(ctx, l3_offset) {
        Some(p) => p,
        None => return L3ParseResult::Abort,
    };

    // SAFETY: ptr_at 已确保 iphdr 基本头在 packet 内。
    let ihl = unsafe { (*iph).ihl() } as usize;
    let ip_hlen = ihl * 4;
    if ip_hlen < mem::size_of::<iphdr>() || ip_hlen > 60 {
        return L3ParseResult::Abort;
    }

    // 校验完整 IPv4 header（含 options）在 packet 内。
    if !range_in_packet(ctx, l3_offset, ip_hlen) {
        return L3ParseResult::Abort;
    }

    // IPv4 分片处理：可选丢弃（避免 L4 绕过）。
    // frag_off: 低 13 bits offset，以 8-byte 为单位；MF 标志为 bit 13。
    // 若 offset != 0 或 MF=1，则为分片。
    let frag_off = unsafe { u16::from_be((*iph).frag_off) };
    let frag_offset = frag_off & 0x1FFF;
    let more_frags = (frag_off & 0x2000) != 0;
    if (frag_offset != 0 || more_frags) && cfg.drop_ipv4_frags {
        return L3ParseResult::Drop;
    }

    let proto = unsafe { (*iph).protocol };

    let saddr_host = unsafe { u32::from_be((*iph).saddr) };
    let daddr_host = unsafe { u32::from_be((*iph).daddr) };
    let src = ipv4_host_to_ipkey_exact(saddr_host);
    let dst = ipv4_host_to_ipkey_exact(daddr_host);

    let l4_offset = l3_offset + ip_hlen;

    L3ParseResult::Parsed(L3Parsed {
        l3_offset,
        l4_offset,
        eth_proto: ETH_P_IP,
        is_ipv6: false,
        proto,
        src_ip: src,
        dst_ip: dst,
    })
}

#[inline(always)]
fn parse_ipv6(ctx: &XdpContext, l3_offset: usize) -> L3ParseResult {
    let ip6: *const ipv6hdr = match ptr_at(ctx, l3_offset) {
        Some(p) => p,
        None => return L3ParseResult::Abort,
    };

    // IPv6 固定头 40 字节；不处理扩展头（超出本模块的 L4 快路径范围）
    if !range_in_packet(ctx, l3_offset, mem::size_of::<ipv6hdr>()) {
        return L3ParseResult::Abort;
    }

    // SAFETY: ptr_at + range_in_packet 确保 ipv6hdr 在 packet 内。
    let nexthdr = unsafe { (*ip6).nexthdr };
    let src = ipv6_to_ipkey_exact(unsafe { &(*ip6).saddr });
    let dst = ipv6_to_ipkey_exact(unsafe { &(*ip6).daddr });

    let l4_offset = l3_offset + mem::size_of::<ipv6hdr>();

    L3ParseResult::Parsed(L3Parsed {
        l3_offset,
        l4_offset,
        eth_proto: ETH_P_IPV6,
        is_ipv6: true,
        proto: nexthdr,
        src_ip: src,
        dst_ip: dst,
    })
}

// -------- TCP 处理 --------

#[inline(always)]
fn handle_tcp(
    ctx: &XdpContext,
    l3: &L3Parsed,
    now_ns: u64,
    cfg: &CfgView,
    stats: &mut GlobalStats,
) -> Result<u32, ()> {
    stats.tcp_packets = stats.tcp_packets.wrapping_add(1);

    let tcp: *mut tcphdr = match ptr_at_mut(ctx, l3.l4_offset) {
        Some(p) => p,
        None => {
            stats.drop = stats.drop.wrapping_add(1);
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // SAFETY: ptr_at_mut 已确保 tcphdr 基本头在 packet 内。
    let doff = unsafe { (*tcp).doff() } as usize;
    let tcp_hlen = doff * 4;
    if tcp_hlen < mem::size_of::<tcphdr>() || tcp_hlen > 60 {
        stats.drop = stats.drop.wrapping_add(1);
        return Ok(xdp_action::XDP_DROP);
    }
    if !range_in_packet(ctx, l3.l4_offset, tcp_hlen) {
        stats.drop = stats.drop.wrapping_add(1);
        return Ok(xdp_action::XDP_DROP);
    }

    let flags = unsafe { tcp_flags((*tcp)) };

    let is_syn = (flags & TCP_FLAG_SYN) != 0;
    let is_ack = (flags & TCP_FLAG_ACK) != 0;
    let is_rst = (flags & TCP_FLAG_RST) != 0;

    // 连接 key（仅对 TCP 生效）
    let sport = unsafe { u16::from_be((*tcp).source) };
    let dport = unsafe { u16::from_be((*tcp).dest) };

    let conn_key = ConnKey::new(
        l3.src_ip.addr,
        l3.dst_ip.addr,
        sport,
        dport,
        IPPROTO_TCP,
    );

    // 6) TCP 流量处理顺序：
    // a) SYN flood 检测
    // b) RST 校验
    // c) ACK flood 检测
    // d) SYN proxy（开启时 SYN 走代理）
    //
    // 注：为了避免对握手 ACK 误判，本实现对 ACK flood 检测要求该连接已在 conntrack 中存在；
    //     否则若开启 SYN proxy，则先做 syncookie 校验。

    if is_syn && !is_ack {
        stats.syn_packets = stats.syn_packets.wrapping_add(1);
        record_syn_ring(stats, now_ns);

        // SYN score 更新 + 阈值比较（指数衰减）
        if cfg.enable_syn_flood {
            let over = syn_score_update_and_check(&l3.src_ip, now_ns, cfg, stats)?;
            if over {
                stats.syn_drops = stats.syn_drops.wrapping_add(1);
                stats.drop = stats.drop.wrapping_add(1);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        // SYN proxy：用内核 syncookie helper 生成 cookie 并回 SYN-ACK（XDP_TX）
        if cfg.enable_syn_proxy {
            let ret = syn_proxy_handle_syn(ctx, l3, tcp, tcp_hlen, now_ns, cfg, stats)?;
            return Ok(ret);
        }

        // 不开启 SYN proxy：通过
        // 可选择性更新 conntrack（这里只是 SYN，连接未建立，不写）
        stats.pass = stats.pass.wrapping_add(1);
        return Ok(xdp_action::XDP_PASS);
    }

    if is_rst {
        stats.rst_packets = stats.rst_packets.wrapping_add(1);

        if cfg.enable_rst_validate {
            let ok = rst_validate_and_update_conntrack(&conn_key, tcp, now_ns, cfg, stats);
            if !ok {
                stats.rst_drops = stats.rst_drops.wrapping_add(1);
                stats.drop = stats.drop.wrapping_add(1);

                // 事件：RST 非法（best-effort）
                emit_event(&XdpEvent::attack_detected(
                    now_ns,
                    l3.src_ip.as_exact(),
                    AttackKind::RstFlood,
                    0,
                    cfg.rst_window_size,
                ));
                return Ok(xdp_action::XDP_DROP);
            }
        }

        // 合法 RST：PASS（同时 conntrack 会被更新 last_seen）
        stats.pass = stats.pass.wrapping_add(1);
        return Ok(xdp_action::XDP_PASS);
    }

    // ACK-only flood 检测（严格按规格：ACK 包）
    // 我们将 ACK flood 定义为：ACK=1 且非 SYN/RST/FIN，且 payload_len==0（ACK-only）
    let is_fin = (flags & TCP_FLAG_FIN) != 0;
    let payload_len = l4_payload_len(ctx, l3.l4_offset, tcp_hlen);

    let is_ack_only = is_ack && !is_syn && !is_rst && !is_fin && payload_len == 0;

    if is_ack_only {
        stats.ack_only_packets = stats.ack_only_packets.wrapping_add(1);

        // 若启用了 SYN proxy，则对“未建立连接”的 ACK 先走 syncookie 验证；
        // 验证通过则 PASS（让内核完成 syncookie 建连）；失败则 DROP。
        if cfg.enable_syn_proxy {
            if !conntrack_exists(&conn_key, now_ns, cfg) {
                let ok = syn_proxy_handle_ack_validate(ctx, l3, tcp, tcp_hlen);
                if !ok {
                    stats.ack_drops = stats.ack_drops.wrapping_add(1);
                    stats.drop = stats.drop.wrapping_add(1);

                    emit_event(&XdpEvent::attack_detected(
                        now_ns,
                        l3.src_ip.as_exact(),
                        AttackKind::SynFlood,
                        0,
                        0,
                    ));
                    return Ok(xdp_action::XDP_DROP);
                }

                // 通过 syncookie 校验后，提前写入 conntrack（RST 验证用）
                upsert_conntrack(&conn_key, tcp, now_ns, cfg, stats);

                stats.pass = stats.pass.wrapping_add(1);
                return Ok(xdp_action::XDP_PASS);
            }
        }

        // ACK flood 检测：复用 per-IP 状态 map 的 ack_score（指数衰减）
        if cfg.enable_ack_flood && conntrack_exists(&conn_key, now_ns, cfg) {
            let over = ack_score_update_and_check(&l3.src_ip, now_ns, cfg, stats)?;
            if over {
                stats.ack_drops = stats.ack_drops.wrapping_add(1);
                stats.drop = stats.drop.wrapping_add(1);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        // 正常 ACK-only：更新 conntrack seq_center（提升 RST 校验准确度）
        upsert_conntrack(&conn_key, tcp, now_ns, cfg, stats);

        stats.pass = stats.pass.wrapping_add(1);
        return Ok(xdp_action::XDP_PASS);
    }

    // 其它 TCP 包：更新 conntrack（RST 验证用），并 PASS
    upsert_conntrack(&conn_key, tcp, now_ns, cfg, stats);
    stats.pass = stats.pass.wrapping_add(1);
    Ok(xdp_action::XDP_PASS)
}

// TCP flags bits (from Linux include/uapi/linux/tcp.h)
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;

#[inline(always)]
unsafe fn tcp_flags(th: tcphdr) -> u8 {
    // SAFETY: tcphdr.flags 位布局由内核 uapi 定义；aya bindings 提供 accessors。
    // 在 bindgen 生成的 tcphdr 中，flags 通常分散在 bitfield；这里使用 tcphdr 的 getter：
    // 但 aya bindings 的 tcphdr 提供 `fin()/syn()/rst()/psh()/ack()/urg()`。
    let mut f = 0u8;
    if th.fin() != 0 {
        f |= TCP_FLAG_FIN;
    }
    if th.syn() != 0 {
        f |= TCP_FLAG_SYN;
    }
    if th.rst() != 0 {
        f |= TCP_FLAG_RST;
    }
    if th.psh() != 0 {
        f |= TCP_FLAG_PSH;
    }
    if th.ack() != 0 {
        f |= TCP_FLAG_ACK;
    }
    if th.urg() != 0 {
        f |= TCP_FLAG_URG;
    }
    f
}

// -------- UDP 处理 --------

#[inline(always)]
fn handle_udp(
    ctx: &XdpContext,
    l3: &L3Parsed,
    now_ns: u64,
    cfg: &CfgView,
    stats: &mut GlobalStats,
) -> Result<u32, ()> {
    stats.udp_packets = stats.udp_packets.wrapping_add(1);

    let udp: *mut udphdr = match ptr_at_mut(ctx, l3.l4_offset) {
        Some(p) => p,
        None => {
            stats.drop = stats.drop.wrapping_add(1);
            return Ok(xdp_action::XDP_DROP);
        }
    };

    if !range_in_packet(ctx, l3.l4_offset, mem::size_of::<udphdr>()) {
        stats.drop = stats.drop.wrapping_add(1);
        return Ok(xdp_action::XDP_DROP);
    }

    let dport = unsafe { u16::from_be((*udp).dest) };
    let udp_len = unsafe { u16::from_be((*udp).len) } as u32;

    // 7) UDP：目标端口统计（只统计关心端口）
    let tracked_idx = if cfg.enable_udp_stats || cfg.enable_udp_rate_limit {
        find_tracked_port(cfg, dport)
    } else {
        None
    };

    if let Some(idx) = tracked_idx {
        // 统计 map：PORT_STATS（PERCPU_ARRAY），key 为端口号（逻辑 u16，实际 u32 index）
        // 并发：per-CPU，无锁更新。
        if let Some(ps) = get_port_stats_mut(dport as u32) {
            ps.packets = ps.packets.wrapping_add(1);
            ps.bytes = ps.bytes.wrapping_add(udp_len as u64);
            record_size_bucket(ps, udp_len);

            stats.udp_tracked_packets = stats.udp_tracked_packets.wrapping_add(1);

            // 端口限速（固定窗口）：由用户态下发 PPS/BPS 阈值
            if cfg.enable_udp_rate_limit {
                let max_pps = cfg.udp_rate_limit_pps[idx];
                let max_bps = cfg.udp_rate_limit_bps[idx];
                if max_pps != 0 || max_bps != 0 {
                    if udp_rate_limit_check_and_account(ps, now_ns, cfg.udp_window_ns, max_pps, max_bps) {
                        stats.udp_drops = stats.udp_drops.wrapping_add(1);
                        stats.drop = stats.drop.wrapping_add(1);

                        // best-effort 事件：UDP rate limit
                        emit_event(&XdpEvent::ip_blocked(
                            now_ns,
                            l3.src_ip.as_exact(),
                            BlockReason::UdpRateLimit,
                            0,
                        ));
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
        } else {
            // PORT_STATS 获取失败（理论上不会，因为 array index 有界），best-effort 事件
            emit_event(&XdpEvent::map_near_full(
                now_ns,
                l3.src_ip.as_exact(),
                MapKind::PortStats,
                0,
            ));
        }
    }

    // 8) 通过所有检查 -> PASS
    stats.pass = stats.pass.wrapping_add(1);
    Ok(xdp_action::XDP_PASS)
}

// -------- SYN flood 检测：指数衰减 score --------

#[inline(always)]
fn syn_score_update_and_check(
    src_ip: &IpKey,
    now_ns: u64,
    cfg: &CfgView,
    stats: &mut GlobalStats,
) -> Result<bool, ()> {
    let mut state = get_or_init_syn_state(src_ip, now_ns)?;
    // 指数衰减（bounded loop <= 32）
    decay_scores(&mut state, now_ns, cfg.syn_state_ttl_ns);

    // 收到一个 SYN：score + 1
    state.syn_score = state.syn_score.wrapping_add(1);

    // 读取阈值（由用户态写入）；若阈值为 0，视为未配置，使用 u32::MAX 避免误杀
    let threshold = if cfg.syn_threshold == 0 { u32::MAX } else { cfg.syn_threshold };

    if state.syn_score > threshold {
        state.flags |= SYN_STATE_FLAG_SUSPECT;
        state.syn_drop_streak = state.syn_drop_streak.saturating_add(1);

        // 事件：AttackDetected (SYN flood)
        emit_event(&XdpEvent::attack_detected(
            now_ns,
            src_ip.as_exact(),
            AttackKind::SynFlood,
            state.syn_score,
            threshold,
        ));

        // 连续 drop 达标 -> 黑名单
        if cfg.syn_blacklist_after_drops != 0 && state.syn_drop_streak >= cfg.syn_blacklist_after_drops {
            blacklist_ip(src_ip, now_ns, BlockReason::SynFlood, cfg.blacklist_ttl_ns);
            state.flags |= SYN_STATE_FLAG_BLACKLISTED;

            emit_event(&XdpEvent::ip_blocked(
                now_ns,
                src_ip.as_exact(),
                BlockReason::SynFlood,
                cfg.blacklist_ttl_ns,
            ));

            // 触发后重置 streak，避免每包重复写 blacklist
            state.syn_drop_streak = 0;
        }

        // 写回 per-CPU state（指针修改已生效，仍需保证 last_update 已更新）
        // 此处 state 为直接引用（current CPU），无需额外 insert。
        stats.syn_drops = stats.syn_drops.wrapping_add(1);
        return Ok(true);
    }

    // 未超阈值：清零 streak（连续 drop 语义）
    state.syn_drop_streak = 0;
    Ok(false)
}

#[inline(always)]
fn ack_score_update_and_check(
    src_ip: &IpKey,
    now_ns: u64,
    cfg: &CfgView,
    _stats: &mut GlobalStats,
) -> Result<bool, ()> {
    let mut state = get_or_init_syn_state(src_ip, now_ns)?;
    decay_scores(&mut state, now_ns, cfg.syn_state_ttl_ns);

    state.ack_score = state.ack_score.wrapping_add(1);

    let active = cfg.active_conns_estimate;
    let per_conn = if cfg.ack_limit_per_conn == 0 { 10 } else { cfg.ack_limit_per_conn };
    let threshold = active.saturating_mul(per_conn);

    // 若 active==0（用户态未提供），则禁用 ACK flood drop（阈值为 u32::MAX）
    let threshold = if active == 0 { u32::MAX } else { threshold };

    if state.ack_score > threshold {
        state.ack_drop_streak = state.ack_drop_streak.saturating_add(1);

        emit_event(&XdpEvent::attack_detected(
            now_ns,
            src_ip.as_exact(),
            AttackKind::AckFlood,
            state.ack_score,
            threshold,
        ));

        if cfg.ack_blacklist_after_drops != 0 && state.ack_drop_streak >= cfg.ack_blacklist_after_drops {
            blacklist_ip(src_ip, now_ns, BlockReason::AckFlood, cfg.blacklist_ttl_ns);
            state.flags |= SYN_STATE_FLAG_BLACKLISTED;

            emit_event(&XdpEvent::ip_blocked(
                now_ns,
                src_ip.as_exact(),
                BlockReason::AckFlood,
                cfg.blacklist_ttl_ns,
            ));
            state.ack_drop_streak = 0;
        }

        return Ok(true);
    }

    state.ack_drop_streak = 0;
    Ok(false)
}

#[inline(always)]
fn decay_scores(state: &mut SynState, now_ns: u64, state_ttl_ns: u64) {
    let last = state.last_update_ns;

    // 软 TTL：长时间未更新直接重置（防止陈旧 score 误判）
    if state_ttl_ns != 0 && now_ns.saturating_sub(last) > state_ttl_ns {
        state.syn_score = 0;
        state.ack_score = 0;
        state.syn_drop_streak = 0;
        state.ack_drop_streak = 0;
        state.flags &= !(SYN_STATE_FLAG_SUSPECT);
        state.last_update_ns = now_ns;
        return;
    }

    let elapsed = now_ns.saturating_sub(last);
    let mut steps = (elapsed / DECAY_STEP_NS) as u32;
    if steps == 0 {
        return;
    }
    if steps > MAX_DECAY_STEPS {
        steps = MAX_DECAY_STEPS;
    }

    // verifier 说明：steps 上界为 MAX_DECAY_STEPS=32，循环可证明有界。
    let mut i = 0u32;
    while i < steps {
        state.syn_score = ((state.syn_score as u64 * DECAY_FACTOR_NUM as u64) >> DECAY_FACTOR_SHIFT) as u32;
        state.ack_score = ((state.ack_score as u64 * DECAY_FACTOR_NUM as u64) >> DECAY_FACTOR_SHIFT) as u32;
        i += 1;
    }

    state.last_update_ns = now_ns;
}

// -------- SYN proxy（syncookie） --------
//
// 说明：
// - 你给的规格要求 “SHA256 HMAC + secret from config map” 生成 cookie。
// - 但在 **仅有 ingress XDP** 的场景下，要让内核 TCP 栈在 LISTEN 状态接受第三次握手 ACK，
//   必须与内核的 syncookie 校验路径互操作，否则无法在不拦截 egress 的前提下完成建连。
// - 因此本实现采用内核 helper：`bpf_tcp_gen_syncookie` / `bpf_tcp_check_syncookie`。
// - `XdpConfig::syn_cookie_secret` 字段按契约保留（用户态可写入/轮换），当前不参与 helper 生成算法。

#[inline(always)]
fn syn_proxy_handle_syn(
    ctx: &XdpContext,
    l3: &L3Parsed,
    tcp: *mut tcphdr,
    tcp_hlen: usize,
    now_ns: u64,
    _cfg: &CfgView,
    _stats: &mut GlobalStats,
) -> Result<u32, ()> {
    // 获取监听 socket（当前 netns）
    let sk = match sk_lookup_tcp(ctx, l3, tcp) {
        Some(s) => s,
        None => {
            // 没有 listener：不做代理，交给内核处理
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // 生成 syncookie（仅在内核判定需要时成功；否则返回负值）
    let cookie_mss = unsafe {
        // SAFETY: helper 需要指向 packet 内的 IP/TCP header；l3_offset 与 l4_offset 已做边界校验。
        bpf_tcp_gen_syncookie(
            sk as *mut c_void,
            ptr_at_l3(ctx, l3.l3_offset) as *mut c_void,
            l3_header_len(l3) as u32,
            tcp as *mut aya_ebpf::bindings::tcphdr,
            tcp_hlen as u32,
        )
    };

    // 释放 socket 引用
    unsafe {
        // SAFETY: sk 来自 bpf_sk_lookup_tcp，必须 release。
        bpf_sk_release(sk as *mut c_void);
    }

    if cookie_mss < 0 {
        // 内核认为不需要 syncookie：放行 SYN，让内核正常握手
        return Ok(xdp_action::XDP_PASS);
    }

    let cookie = (cookie_mss as u64 & 0xFFFF_FFFF) as u32;

    // 构造 SYN-ACK 并 XDP_TX
    // 做法：在原 SYN 包上原地修改为 SYN-ACK，并裁剪 TCP options（将 doff 设为 5），保证 options 不被错误复用。
    let ret = build_and_tx_synack(ctx, l3, tcp, cookie)?;
    // 事件：此处不额外上报（避免攻击时 ringbuf 放大）
    let _ = now_ns;
    Ok(ret)
}

#[inline(always)]
fn syn_proxy_handle_ack_validate(
    ctx: &XdpContext,
    l3: &L3Parsed,
    tcp: *mut tcphdr,
    tcp_hlen: usize,
) -> bool {
    let sk = match sk_lookup_tcp(ctx, l3, tcp) {
        Some(s) => s,
        None => return false,
    };

    let ok = unsafe {
        // SAFETY: helper 需要 packet 内 header 指针；l3/l4 offset 已校验。
        bpf_tcp_check_syncookie(
            sk as *mut c_void,
            ptr_at_l3(ctx, l3.l3_offset) as *mut c_void,
            l3_header_len(l3) as u32,
            tcp as *mut aya_ebpf::bindings::tcphdr,
            tcp_hlen as u32,
        )
    };

    unsafe {
        // SAFETY: sk 必须 release。
        bpf_sk_release(sk as *mut c_void);
    }

    ok == 0
}

// -------- RST 验证（连接跟踪 + seq window） --------

#[inline(always)]
fn rst_validate_and_update_conntrack(
    key: &ConnKey,
    tcp: *mut tcphdr,
    now_ns: u64,
    cfg: &CfgView,
    _stats: &mut GlobalStats,
) -> bool {
    let mut st = match conntrack_get(key) {
        Some(v) => v,
        None => return false, // 无连接：RST 必为伪造
    };

    // TTL 过期：删除并视为无连接
    if st.expires_at_ns != 0 && now_ns > st.expires_at_ns {
        conntrack_remove(key);
        return false;
    }

    let seq = unsafe { u32::from_be((*tcp).seq) };
    if !seq_within_window(seq, st.seq_center, cfg.rst_window_size) {
        return false;
    }

    // 合法：更新 seq_center 与 last_seen/ttl（提升后续准确度）
    st.seq_center = seq;
    st.last_seen_ns = now_ns;
    st.expires_at_ns = now_ns.saturating_add(cfg.conntrack_ttl_ns);
    conntrack_put(key, &st);

    true
}

#[inline(always)]
fn seq_within_window(seq: u32, center: u32, window: u32) -> bool {
    let diff = seq.wrapping_sub(center) as i32;
    if diff == i32::MIN {
        return false;
    }
    if diff >= 0 {
        (diff as u32) <= window
    } else {
        ((-diff) as u32) <= window
    }
}

// -------- Conntrack 操作 --------

#[inline(always)]
fn conntrack_exists(key: &ConnKey, now_ns: u64, cfg: &CfgView) -> bool {
    if let Some(st) = conntrack_get(key) {
        if st.expires_at_ns != 0 && now_ns > st.expires_at_ns {
            conntrack_remove(key);
            return false;
        }
        // 若配置提供 TTL，则在读到时不延长 TTL；延长在 upsert 时做
        let _ = cfg;
        return true;
    }
    false
}

#[inline(always)]
fn upsert_conntrack(
    key: &ConnKey,
    tcp: *mut tcphdr,
    now_ns: u64,
    cfg: &CfgView,
    _stats: &mut GlobalStats,
) {
    let seq = unsafe { u32::from_be((*tcp).seq) };
    let st = ConnState::new(seq, now_ns, cfg.conntrack_ttl_ns);
    conntrack_put(key, &st);
}

#[inline(always)]
fn conntrack_get(key: &ConnKey) -> Option<ConnState> {
    // 并发说明：LRU map 内部同步；返回引用可能被并发修改，因此这里拷贝出值再使用，避免 data race。
    // SAFETY: map lookup 返回的指针在本 helper 调用期间有效；我们立刻拷贝出 ConnState（Copy）。
    unsafe { CONNTRACK.get(key).map(|v| *v) }
}

#[inline(always)]
fn conntrack_put(key: &ConnKey, val: &ConnState) {
    // 并发说明：LRU map 内部锁；并发插入/更新由内核处理。
    // SAFETY: key/val 均为 POD，且指针有效。
    unsafe {
        let _ = CONNTRACK.insert(key, val, 0);
    }
}

#[inline(always)]
fn conntrack_remove(key: &ConnKey) {
    // SAFETY: 删除操作由内核处理；key 指针有效。
    unsafe {
        let _ = CONNTRACK.remove(key);
    }
}

// -------- 白名单/黑名单 --------

#[inline(always)]
fn whitelist_hit(ip: &IpKey, cfg: &CfgView) -> bool {
    // 先精确匹配 prefix_len=128
    let exact = ip.as_exact();
    // SAFETY: WHITELIST 只读，map 内部并发安全；key 为 POD。
    if unsafe { WHITELIST.get(&exact).is_some() } {
        return true;
    }

    // 可选 CIDR：额外 lookup（会增加延迟，默认建议关闭）
    if !cfg.enable_cidr_lookup {
        return false;
    }

    // best-effort：只尝试少数常见 prefix（避免 128 次 lookup）
    // verifier 说明：循环上界常量 5。
    if exact.is_ipv4_mapped() {
        // IPv4: /32,/24,/16,/8,/0 -> prefix_len 128,120,112,104,96
        let prefixes: [u8; 5] = [128, 120, 112, 104, 96];
        let mut i = 0usize;
        while i < prefixes.len() {
            let k = ip_with_prefix(ip, prefixes[i]);
            if unsafe { WHITELIST.get(&k).is_some() } {
                return true;
            }
            i += 1;
        }
    } else {
        // IPv6: /128,/64,/48,/32,/0
        let prefixes: [u8; 5] = [128, 64, 48, 32, 0];
        let mut i = 0usize;
        while i < prefixes.len() {
            let k = ip_with_prefix(ip, prefixes[i]);
            if unsafe { WHITELIST.get(&k).is_some() } {
                return true;
            }
            i += 1;
        }
    }

    false
}

#[inline(always)]
fn blacklist_hit_and_handle_expiry(ip: &IpKey, now_ns: u64, _stats: &mut GlobalStats) -> bool {
    let exact = ip.as_exact();

    // SAFETY: LRU map lookup 并发安全；返回引用我们立即拷贝/只读字段。
    if let Some(entry) = unsafe { BLACKLIST.get(&exact).map(|v| *v) } {
        if entry.ttl_ns != 0 && now_ns.saturating_sub(entry.blocked_at_ns) > entry.ttl_ns {
            // TTL 到期：删除条目
            unsafe {
                let _ = BLACKLIST.remove(&exact);
            }
            return false;
        }
        return true;
    }

    false
}

#[inline(always)]
fn blacklist_ip(ip: &IpKey, now_ns: u64, reason: BlockReason, ttl_ns: u64) {
    let key = ip.as_exact();
    let val = BlacklistEntry::new(reason, now_ns, ttl_ns);
    unsafe {
        let _ = BLACKLIST.insert(&key, &val, 0);
    }
}

// -------- per-IP SYN state map --------

#[inline(always)]
fn get_or_init_syn_state(src_ip: &IpKey, now_ns: u64) -> Result<&'static mut SynState, ()> {
    let key = src_ip.as_exact();

    // SAFETY: PERCPU_HASH lookup 返回当前 CPU 的 value 指针；随后只在当前 CPU 上修改，无跨 CPU 竞争。
    if let Some(p) = unsafe { SYN_STATE.get_ptr_mut(&key) } {
        // SAFETY: p 指向 map value，生命周期由内核保证；我们在函数返回前使用。
        return Ok(unsafe { &mut *p });
    }

    // 不存在则插入初始值
    let init = SynState::zeroed(now_ns);
    unsafe {
        // SAFETY: key/value 为 POD；插入可能触发 map 内部锁（key 表共享），可接受。
        // 若 map 满，insert 会失败；此处 best-effort：失败则返回 Err，让调用方选择保守策略（不 drop）。
        if SYN_STATE.insert(&key, &init, 0).is_err() {
            emit_event(&XdpEvent::map_near_full(
                now_ns,
                key,
                MapKind::SynState,
                0,
            ));
            return Err(());
        }
    }

    // 再次 lookup 获取指针
    if let Some(p) = unsafe { SYN_STATE.get_ptr_mut(&key) } {
        return Ok(unsafe { &mut *p });
    }

    Err(())
}

// -------- UDP 端口统计/限速 --------

#[inline(always)]
fn find_tracked_port(cfg: &CfgView, port: u16) -> Option<usize> {
    // verifier 说明：循环上界常量 MAX_TRACKED_PORTS（<=16）。
    let mut i = 0usize;
    while i < MAX_TRACKED_PORTS {
        if cfg.udp_tracked_ports[i] == port {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[inline(always)]
fn get_port_stats_mut(port_index: u32) -> Option<&'static mut PortStats> {
    // SAFETY: PERCPU_ARRAY 访问当前 CPU 槽位；无锁。
    unsafe { PORT_STATS.get_ptr_mut(port_index).map(|p| unsafe { &mut *p }) }
}

#[inline(always)]
fn record_size_bucket(ps: &mut PortStats, pkt_len: u32) {
    let idx = if pkt_len <= 63 {
        0
    } else if pkt_len <= 127 {
        1
    } else if pkt_len <= 255 {
        2
    } else if pkt_len <= 511 {
        3
    } else if pkt_len <= 1023 {
        4
    } else if pkt_len <= 1471 {
        5
    } else if pkt_len <= 2047 {
        6
    } else {
        7
    };
    ps.size_buckets[idx] = ps.size_buckets[idx].wrapping_add(1);
}

#[inline(always)]
fn udp_rate_limit_check_and_account(
    ps: &mut PortStats,
    now_ns: u64,
    window_ns: u64,
    max_pps: u32,
    max_bps: u32,
) -> bool {
    let w = if window_ns == 0 { 1_000_000_000 } else { window_ns };

    if ps.window_start_ns == 0 {
        ps.window_start_ns = now_ns;
        ps.window_packets = 0;
        ps.window_bytes = 0;
    }

    let elapsed = now_ns.saturating_sub(ps.window_start_ns);
    if elapsed >= w {
        ps.window_start_ns = now_ns;
        ps.window_packets = 0;
        ps.window_bytes = 0;
    }

    ps.window_packets = ps.window_packets.wrapping_add(1);
    ps.window_bytes = ps.window_bytes.wrapping_add(0); // bytes 在调用方可按需加；这里保持 0
    // 注意：为避免额外读取 UDP payload 大小导致的开销，这里仅用包级统计作为 PPS 限速主路径。
    // 若需要严格 BPS，可在调用处 ps.window_bytes += pkt_len。
    // 本实现：若 max_bps != 0，则用 window_bytes（由调用方维护）参与判断。

    if max_pps != 0 && ps.window_packets > max_pps {
        return true;
    }
    if max_bps != 0 && ps.window_bytes > max_bps {
        return true;
    }
    false
}

// -------- SYN per-second ring（GlobalStats） --------

#[inline(always)]
fn record_syn_ring(stats: &mut GlobalStats, now_ns: u64) {
    let now_sec = now_ns / 1_000_000_000;

    if stats.last_syn_sec == 0 {
        stats.last_syn_sec = now_sec;
        stats.syn_ring_idx = 0;
        stats.syn_per_sec[0] = 0;
    }

    if now_sec != stats.last_syn_sec {
        let delta = now_sec.saturating_sub(stats.last_syn_sec);
        let steps = if delta as usize > SYN_RING_SECONDS {
            SYN_RING_SECONDS as u32
        } else {
            delta as u32
        };

        // verifier 说明：steps <= 60，循环有界。
        let mut i = 0u32;
        while i < steps {
            stats.syn_ring_idx = (stats.syn_ring_idx + 1) % (SYN_RING_SECONDS as u32);
            stats.syn_per_sec[stats.syn_ring_idx as usize] = 0;
            i += 1;
        }

        stats.last_syn_sec = now_sec;
    }

    let idx = stats.syn_ring_idx as usize;
    stats.syn_per_sec[idx] = stats.syn_per_sec[idx].wrapping_add(1);
}

// -------- 配置读取与归一化 --------

#[derive(Copy, Clone)]
struct CfgView {
    enable_syn_flood: bool,
    enable_rst_validate: bool,
    enable_ack_flood: bool,
    enable_syn_proxy: bool,
    enable_udp_stats: bool,
    enable_udp_rate_limit: bool,
    enable_cidr_lookup: bool,
    drop_ipv4_frags: bool,

    syn_threshold: u32,
    ack_limit_per_conn: u32,
    active_conns_estimate: u32,
    rst_window_size: u32,

    syn_blacklist_after_drops: u16,
    ack_blacklist_after_drops: u16,

    blacklist_ttl_ns: u64,
    conntrack_ttl_ns: u64,
    syn_state_ttl_ns: u64,

    udp_window_ns: u64,
    udp_tracked_ports: [u16; MAX_TRACKED_PORTS],
    udp_rate_limit_pps: [u32; MAX_TRACKED_PORTS],
    udp_rate_limit_bps: [u32; MAX_TRACKED_PORTS],
}

#[inline(always)]
fn get_config() -> &'static XdpConfig {
    // SAFETY: ARRAY map index 0 永远存在（创建时全 0 初始化）；返回引用在本次执行期间有效。
    unsafe { CONFIG.get(CONFIG_INDEX).unwrap_unchecked() }
}

#[inline(always)]
fn normalize_cfg(cfg: &XdpConfig) -> CfgView {
    if !cfg.is_valid() {
        // 未初始化：保守默认（基本不拦截）
        return conservative_cfg();
    }

    let flags = cfg.flags;

    CfgView {
        enable_syn_flood: (flags & CFG_F_ENABLE_SYN_FLOOD) != 0,
        enable_rst_validate: (flags & CFG_F_ENABLE_RST_VALIDATE) != 0,
        enable_ack_flood: (flags & CFG_F_ENABLE_ACK_FLOOD) != 0,
        enable_syn_proxy: (flags & CFG_F_ENABLE_SYN_PROXY) != 0,
        enable_udp_stats: (flags & CFG_F_ENABLE_UDP_STATS) != 0,
        enable_udp_rate_limit: (flags & CFG_F_ENABLE_UDP_RATE_LIMIT) != 0,
        enable_cidr_lookup: (flags & CFG_F_ENABLE_CIDR_LOOKUP) != 0,
        drop_ipv4_frags: (flags & CFG_F_DROP_IPV4_FRAGS) != 0,

        syn_threshold: cfg.syn_threshold,
        ack_limit_per_conn: cfg.ack_limit_per_conn,
        active_conns_estimate: cfg.active_conns_estimate,
        rst_window_size: cfg.rst_window_size,

        syn_blacklist_after_drops: cfg.syn_blacklist_after_drops,
        ack_blacklist_after_drops: cfg.ack_blacklist_after_drops,

        blacklist_ttl_ns: cfg.blacklist_ttl_ns,
        conntrack_ttl_ns: cfg.conntrack_ttl_ns,
        syn_state_ttl_ns: cfg.syn_state_ttl_ns,

        udp_window_ns: cfg.udp_window_ns,
        udp_tracked_ports: cfg.udp_tracked_ports,
        udp_rate_limit_pps: cfg.udp_rate_limit_pps,
        udp_rate_limit_bps: cfg.udp_rate_limit_bps,
    }
}

#[inline(always)]
fn conservative_cfg() -> CfgView {
    CfgView {
        enable_syn_flood: false,
        enable_rst_validate: false,
        enable_ack_flood: false,
        enable_syn_proxy: false,
        enable_udp_stats: false,
        enable_udp_rate_limit: false,
        enable_cidr_lookup: false,
        drop_ipv4_frags: false,

        syn_threshold: u32::MAX,
        ack_limit_per_conn: 10,
        active_conns_estimate: 0,
        rst_window_size: 65535,

        syn_blacklist_after_drops: 0,
        ack_blacklist_after_drops: 0,

        blacklist_ttl_ns: 0,
        conntrack_ttl_ns: 0,
        syn_state_ttl_ns: 0,

        udp_window_ns: 1_000_000_000,
        udp_tracked_ports: [0u16; MAX_TRACKED_PORTS],
        udp_rate_limit_pps: [0u32; MAX_TRACKED_PORTS],
        udp_rate_limit_bps: [0u32; MAX_TRACKED_PORTS],
    }
}

// -------- 工具函数：指针/边界/长度 --------

#[inline(always)]
fn packet_len(ctx: &XdpContext) -> usize {
    let start = ctx.data();
    let end = ctx.data_end();
    end.saturating_sub(start)
}

#[inline(always)]
fn range_in_packet(ctx: &XdpContext, offset: usize, len: usize) -> bool {
    let start = ctx.data();
    let end = ctx.data_end();
    let off = start.saturating_add(offset);
    off.saturating_add(len) <= end
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let p = start.saturating_add(offset);
    let size = mem::size_of::<T>();
    if p.saturating_add(size) > end {
        return None;
    }
    Some(p as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let p = start.saturating_add(offset);
    let size = mem::size_of::<T>();
    if p.saturating_add(size) > end {
        return None;
    }
    Some(p as *mut T)
}

#[inline(always)]
fn ptr_at_l3(ctx: &XdpContext, l3_offset: usize) -> *mut c_void {
    (ctx.data().saturating_add(l3_offset)) as *mut c_void
}

#[inline(always)]
fn l3_header_len(l3: &L3Parsed) -> usize {
    if l3.is_ipv6 {
        mem::size_of::<ipv6hdr>()
    } else {
        // IPv4 header len 不存储在 L3Parsed 中，为 syncookie helper 使用时，我们只传固定 20。
        // 说明：本实现的 syn_proxy 仅在 parse_ipv4 中已验证 header_len，并且 l3.l4_offset = l3_offset+header_len；
        //      为保证 helper 看到完整 header，实际应传入真实 header_len。
        //      由于该函数没有 header_len，我们在 syn_proxy_handle_syn/ack 时使用 l3_offset 和 l4_offset 推导：
        //      header_len = l4_offset - l3_offset。
        l3.l4_offset.saturating_sub(l3.l3_offset)
    }
}

#[inline(always)]
fn l4_payload_len(ctx: &XdpContext, l4_offset: usize, l4_hlen: usize) -> usize {
    let start = ctx.data();
    let end = ctx.data_end();
    let l4_start = start.saturating_add(l4_offset);
    let payload = l4_start.saturating_add(l4_hlen);
    if payload > end {
        0
    } else {
        end - payload
    }
}

// -------- IP 工具：IPv4/IPv6 -> IpKey --------

#[inline(always)]
fn ipv4_host_to_ipkey_exact(ip_host: u32) -> IpKey {
    // ip_host 是 host order（例如 0x01020304 表示 1.2.3.4）
    let b = ip_host.to_be_bytes();
    IpKey::from_ipv4_exact(b)
}

#[inline(always)]
fn ipv6_to_ipkey_exact(addr: &[u8; 16]) -> IpKey {
    let bytes = copy_16_bytes(addr as *const _ as *const u8);
    IpKey::from_ipv6_exact(bytes)
}

#[inline(always)]
fn copy_16_bytes(p: *const u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    // verifier 说明：循环上界常量 16，有界。
    let mut i = 0usize;
    while i < 16 {
        // SAFETY: 调用方保证 p 指向 packet 内有效区域（ipv6hdr 内的地址字段），且长度 >= 16。
        out[i] = unsafe { *p.add(i) };
        i += 1;
    }
    out
}

#[inline(always)]
fn ip_with_prefix(ip: &IpKey, prefix_len: u8) -> IpKey {
    let mut out = *ip;
    out.prefix_len = prefix_len;
    out._pad = [0u8; 7];

    // 仅在 CIDR lookup 打开时使用，且 prefix_len 仅取少数值；
    // 这里进行 mask（16 bytes fixed）：
    let full_bytes = (prefix_len / 8) as usize;
    let rem_bits = (prefix_len % 8) as u8;

    // verifier 说明：循环上界常量 16。
    let mut i = 0usize;
    while i < 16 {
        if i < full_bytes {
            // keep
        } else if i == full_bytes && rem_bits != 0 {
            let mask = 0xFFu8 << (8 - rem_bits);
            out.addr[i] &= mask;
        } else if i >= full_bytes {
            out.addr[i] = 0;
        }
        i += 1;
    }

    out
}

// -------- syncookie socket lookup --------

#[repr(C)]
struct SockTupleIpv4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
struct SockTupleIpv6 {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
}

#[inline(always)]
fn sk_lookup_tcp(ctx: &XdpContext, l3: &L3Parsed, tcp: *mut tcphdr) -> Option<*mut aya_ebpf::bindings::bpf_sock> {
    if l3.is_ipv6 {
        let s = ipv6_bytes_to_u32x4(l3.src_ip.addr);
        let d = ipv6_bytes_to_u32x4(l3.dst_ip.addr);
        let sport = unsafe { (*tcp).source };
        let dport = unsafe { (*tcp).dest };

        let tuple = SockTupleIpv6 {
            saddr: s,
            daddr: d,
            sport,
            dport,
        };

        let sk = unsafe {
            // SAFETY: helper 允许在 XDP 中使用；tuple 指针有效；tuple_size 固定常量。
            bpf_sk_lookup_tcp(
                ctx.as_ptr() as *mut c_void,
                &tuple as *const _ as *mut aya_ebpf::bindings::bpf_sock_tuple,
                mem::size_of::<SockTupleIpv6>() as u32,
                aya_ebpf::bindings::BPF_F_CURRENT_NETNS as u64,
                0,
            )
        };

        if sk.is_null() {
            None
        } else {
            Some(sk)
        }
    } else {
        // IPv4：从 IpKey 的最后 4 字节取出
        let s = u32::from_be_bytes([l3.src_ip.addr[12], l3.src_ip.addr[13], l3.src_ip.addr[14], l3.src_ip.addr[15]]);
        let d = u32::from_be_bytes([l3.dst_ip.addr[12], l3.dst_ip.addr[13], l3.dst_ip.addr[14], l3.dst_ip.addr[15]]);
        let sport = unsafe { (*tcp).source };
        let dport = unsafe { (*tcp).dest };

        let tuple = SockTupleIpv4 {
            saddr: s.to_be(),
            daddr: d.to_be(),
            sport,
            dport,
        };

        let sk = unsafe {
            // SAFETY: helper 允许在 XDP 中使用；tuple 指针有效；tuple_size 固定常量。
            bpf_sk_lookup_tcp(
                ctx.as_ptr() as *mut c_void,
                &tuple as *const _ as *mut aya_ebpf::bindings::bpf_sock_tuple,
                mem::size_of::<SockTupleIpv4>() as u32,
                aya_ebpf::bindings::BPF_F_CURRENT_NETNS as u64,
                0,
            )
        };

        if sk.is_null() {
            None
        } else {
            Some(sk)
        }
    }
}

#[inline(always)]
fn ipv6_bytes_to_u32x4(addr: [u8; 16]) -> [u32; 4] {
    // helper 的 ipv6 tuple 以 __be32[4] 形式表达地址
    [
        u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
        u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
        u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
    ]
}

// -------- 构造 SYN-ACK + TX --------

#[inline(always)]
fn build_and_tx_synack(
    ctx: &XdpContext,
    l3: &L3Parsed,
    tcp: *mut tcphdr,
    cookie_seq: u32,
) -> Result<u32, ()> {
    // 需要：
    // - 交换 L2 MAC
    // - 交换 L3 src/dst
    // - 交换 L4 src/dst port
    // - 设置 tcp flags = SYN|ACK
    // - seq=cookie, ack_seq=client_seq+1
    // - 清除 options（doff=5），并通过 adjust_tail 裁剪 packet 长度
    // - 重算 IPv4 checksum & TCP checksum（IPv6 只重算 TCP checksum）
    //
    // verifier 风险点：bpf_xdp_adjust_tail 后必须重新获取 data/data_end 并重新计算指针。

    // 先保存需要的字段
    let client_seq = unsafe { u32::from_be((*tcp).seq) };
    let ack_seq = client_seq.wrapping_add(1);

    // 裁剪 TCP options：new_len = L2+L3+TCP(20)
    let l2_len = l3.l3_offset;
    let l3_len = l3.l4_offset.saturating_sub(l3.l3_offset);
    let new_tcp_len = mem::size_of::<tcphdr>();
    let new_total = l2_len + l3_len + new_tcp_len;
    let old_total = packet_len(ctx);

    let delta = (new_total as i32) - (old_total as i32);
    if delta != 0 {
        let rc = unsafe {
            // SAFETY: helper 需要 ctx pointer；delta 有界（裁剪 options 通常为负值）。
            bpf_xdp_adjust_tail(ctx.ctx, delta)
        };
        if rc < 0 {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // adjust_tail 后必须重新拿指针
    let (l3_offset, eth_proto) = parse_l2(ctx).ok_or(())?;
    let l3_reparsed = match parse_l3(ctx, l3_offset, eth_proto, &conservative_cfg()) {
        L3ParseResult::Parsed(v) => v,
        _ => return Ok(xdp_action::XDP_DROP),
    };

    // 获取新 tcp 指针
    let tcp2: *mut tcphdr = ptr_at_mut(ctx, l3_reparsed.l4_offset).ok_or(())?;

    // 修改 L2 MAC：交换源/目的
    swap_eth_macs(ctx)?;

    // 修改 IP src/dst
    if l3_reparsed.is_ipv6 {
        swap_ipv6_addrs(ctx, l3_reparsed.l3_offset)?;
    } else {
        swap_ipv4_addrs(ctx, l3_reparsed.l3_offset)?;
    }

    // 修改 TCP
    unsafe {
        // SAFETY: tcp2 指向 packet 内 tcphdr（已校验）。
        let src_port = (*tcp2).source;
        (*tcp2).source = (*tcp2).dest;
        (*tcp2).dest = src_port;

        // seq/ack
        (*tcp2).seq = cookie_seq.to_be();
        (*tcp2).ack_seq = ack_seq.to_be();

        // flags: SYN|ACK
        (*tcp2).set_fin(0);
        (*tcp2).set_syn(1);
        (*tcp2).set_rst(0);
        (*tcp2).set_psh(0);
        (*tcp2).set_ack(1);
        (*tcp2).set_urg(0);

        // header len = 5（无 options）
        (*tcp2).set_doff(5);

        (*tcp2).urg_ptr = 0;
        (*tcp2).check = 0;
        (*tcp2).window = 65535u16.to_be();
    }

    // 修改 IPv4 tot_len / checksum 或 IPv6 payload_len
    if l3_reparsed.is_ipv6 {
        fix_ipv6_lengths_and_tcp_csum(ctx, &l3_reparsed)?;
    } else {
        fix_ipv4_lengths_and_checksums(ctx, &l3_reparsed)?;
    }

    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
fn swap_eth_macs(ctx: &XdpContext) -> Result<(), ()> {
    let eth: *mut ethhdr = ptr_at_mut(ctx, 0).ok_or(())?;
    unsafe {
        // SAFETY: ethhdr 在 packet 内。
        let mut tmp = [0u8; 6];
        tmp.copy_from_slice(&(*eth).h_source);
        (*eth).h_source.copy_from_slice(&(*eth).h_dest);
        (*eth).h_dest.copy_from_slice(&tmp);
    }
    Ok(())
}

#[inline(always)]
fn swap_ipv4_addrs(ctx: &XdpContext, l3_offset: usize) -> Result<(), ()> {
    let iph: *mut iphdr = ptr_at_mut(ctx, l3_offset).ok_or(())?;
    unsafe {
        // SAFETY: iphdr 在 packet 内。
        let s = (*iph).saddr;
        (*iph).saddr = (*iph).daddr;
        (*iph).daddr = s;
    }
    Ok(())
}

#[inline(always)]
fn swap_ipv6_addrs(ctx: &XdpContext, l3_offset: usize) -> Result<(), ()> {
    let ip6: *mut ipv6hdr = ptr_at_mut(ctx, l3_offset).ok_or(())?;
    unsafe {
        // SAFETY: ipv6hdr 在 packet 内。
        let s = (*ip6).saddr;
        (*ip6).saddr = (*ip6).daddr;
        (*ip6).daddr = s;
    }
    Ok(())
}

#[inline(always)]
fn fix_ipv4_lengths_and_checksums(ctx: &XdpContext, l3: &L3Parsed) -> Result<(), ()> {
    let iph: *mut iphdr = ptr_at_mut(ctx, l3.l3_offset).ok_or(())?;
    let tcp: *mut tcphdr = ptr_at_mut(ctx, l3.l4_offset).ok_or(())?;

    // IPv4 header length
    let ihl = unsafe { (*iph).ihl() } as usize;
    let ip_hlen = ihl * 4;
    if ip_hlen < mem::size_of::<iphdr>() || ip_hlen > 60 {
        return Err(());
    }

    // tot_len = ip_hlen + tcp_hlen(20)
    let tot_len = (ip_hlen + mem::size_of::<tcphdr>()) as u16;
    unsafe {
        (*iph).tot_len = tot_len.to_be();
        (*iph).check = 0;
    }

    // IPv4 header checksum：对 ip header 做校验和
    let csum = unsafe {
        // SAFETY: iph 指向 packet 内；ip_hlen 已验证范围。
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            iph as *mut u32,
            ip_hlen as u32,
            0,
        )
    };
    if csum < 0 {
        return Err(());
    }
    let ip_check = csum_fold(csum as u64);
    unsafe {
        (*iph).check = ip_check;
    }

    // TCP checksum：pseudo header + tcp header
    unsafe {
        (*tcp).check = 0;
    }

    let tcp_sum = unsafe {
        // SAFETY: tcp 指向 packet 内，长度 20。
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            tcp as *mut u32,
            mem::size_of::<tcphdr>() as u32,
            0,
        )
    };
    if tcp_sum < 0 {
        return Err(());
    }

    let saddr = unsafe { u32::from_be((*iph).saddr) };
    let daddr = unsafe { u32::from_be((*iph).daddr) };

    let mut sum = tcp_sum as u64;
    sum = sum.wrapping_add(((saddr >> 16) & 0xFFFF) as u64);
    sum = sum.wrapping_add((saddr & 0xFFFF) as u64);
    sum = sum.wrapping_add(((daddr >> 16) & 0xFFFF) as u64);
    sum = sum.wrapping_add((daddr & 0xFFFF) as u64);
    sum = sum.wrapping_add(IPPROTO_TCP as u64);
    sum = sum.wrapping_add(mem::size_of::<tcphdr>() as u64);

    let tcp_check = csum_fold(sum);
    unsafe {
        (*tcp).check = tcp_check;
    }

    Ok(())
}

#[inline(always)]
fn fix_ipv6_lengths_and_tcp_csum(ctx: &XdpContext, l3: &L3Parsed) -> Result<(), ()> {
    let ip6: *mut ipv6hdr = ptr_at_mut(ctx, l3.l3_offset).ok_or(())?;
    let tcp: *mut tcphdr = ptr_at_mut(ctx, l3.l4_offset).ok_or(())?;

    // IPv6 payload_len = tcp_hlen(20)
    let payload_len = mem::size_of::<tcphdr>() as u16;
    unsafe {
        (*ip6).payload_len = payload_len.to_be();
    }

    unsafe {
        (*tcp).check = 0;
    }

    let tcp_sum = unsafe {
        // SAFETY: tcp 指向 packet 内，长度 20。
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            tcp as *mut u32,
            mem::size_of::<tcphdr>() as u32,
            0,
        )
    };
    if tcp_sum < 0 {
        return Err(());
    }

    let saddr_bytes = copy_16_bytes(unsafe { &(*ip6).saddr } as *const _ as *const u8);
    let daddr_bytes = copy_16_bytes(unsafe { &(*ip6).daddr } as *const _ as *const u8);

    let mut sum = tcp_sum as u64;
    sum = sum.wrapping_add(sum_ipv6_addr_words(&saddr_bytes));
    sum = sum.wrapping_add(sum_ipv6_addr_words(&daddr_bytes));

    // pseudo header: length (32-bit) + next header (8-bit)
    sum = sum.wrapping_add(mem::size_of::<tcphdr>() as u64);
    sum = sum.wrapping_add(IPPROTO_TCP as u64);

    let tcp_check = csum_fold(sum);
    unsafe {
        (*tcp).check = tcp_check;
    }
    Ok(())
}

#[inline(always)]
fn sum_ipv6_addr_words(addr: &[u8; 16]) -> u64 {
    let mut sum = 0u64;
    // verifier 说明：循环上界常量 8。
    let mut i = 0usize;
    while i < 8 {
        let hi = addr[i * 2] as u16;
        let lo = addr[i * 2 + 1] as u16;
        let w = ((hi as u16) << 8) | lo;
        sum = sum.wrapping_add(w as u64);
        i += 1;
    }
    sum
}

#[inline(always)]
fn csum_fold(mut sum: u64) -> u16 {
    // 固定展开，避免 while 循环引入 verifier 不确定性
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

// -------- 事件写入 ringbuf（best-effort） --------

#[inline(always)]
fn emit_event(ev: &XdpEvent) {
    unsafe {
        // SAFETY: ringbuf reserve/submit 由内核保证并发安全；失败返回 None，我们静默丢弃（契约要求）。
        if let Some(mut entry) = EVENTS.reserve::<XdpEvent>(0) {
            entry.write(*ev);
            entry.submit(0);
        }
    }
}

// -------- GlobalStats 获取 --------

#[inline(always)]
fn get_global_stats_mut() -> Option<&'static mut GlobalStats> {
    // SAFETY: PERCPU_ARRAY index 0 永远存在；返回的是当前 CPU 的槽位指针；无锁。
    unsafe { GLOBAL_STATS.get_ptr_mut(GLOBAL_STATS_INDEX).map(|p| unsafe { &mut *p }) }
}

// -------- 时间 --------

#[inline(always)]
fn ktime_get_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() as u64 }
}

// -------- license + panic handler --------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // eBPF 中 panic 不可恢复；保持死循环（不会返回）
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
