#![no_std]

/// 所有 map pin 的基路径（用户态加载器使用）。
pub const ARC_BPF_PIN_BASE: &str = "/sys/fs/bpf/arc";

/// CONFIG map 的魔数，用于判断配置是否由用户态初始化。
pub const XDP_CONFIG_MAGIC: u32 = 0x4152_4358; // "ARCX"

/// arc-xdp ABI 版本号（用户态/内核态协商）。
pub const ARC_XDP_ABI_VERSION: u32 = 1;

/// 统计：SYN per-second 环形数组长度（60 秒窗口）。
pub const SYN_RING_SECONDS: usize = 60;

/// UDP 端口统计/限速：最多跟踪的端口数量（小常量，线性扫描可接受）。
pub const MAX_TRACKED_PORTS: usize = 16;

/// Map 名称常量（用户态通过这些 name 获取 map fd 并 pin）。
pub const MAP_NAME_WHITELIST: &str = "arc_whitelist";
pub const MAP_NAME_BLACKLIST: &str = "arc_blacklist";
pub const MAP_NAME_SYN_STATE: &str = "arc_syn_state";
pub const MAP_NAME_GLOBAL_STATS: &str = "arc_global_stats";
pub const MAP_NAME_CONFIG: &str = "arc_config";
pub const MAP_NAME_EVENTS: &str = "arc_events";
pub const MAP_NAME_CONNTRACK: &str = "arc_conntrack";
pub const MAP_NAME_PORT_STATS: &str = "arc_port_stats";

/// XDP Config map 固定索引：0。
pub const CONFIG_INDEX: u32 = 0;

/// GlobalStats map 固定索引：0。
pub const GLOBAL_STATS_INDEX: u32 = 0;

/// `SynState` flags：该 IP 被标记为可疑（超过阈值）。
pub const SYN_STATE_FLAG_SUSPECT: u32 = 1 << 0;

/// `SynState` flags：该 IP 已被拉黑（仅用于状态标记；真正封禁以 blacklist map 为准）。
pub const SYN_STATE_FLAG_BLACKLISTED: u32 = 1 << 1;

/// `XdpConfig::flags`：启用 SYN flood 检测。
pub const CFG_F_ENABLE_SYN_FLOOD: u32 = 1 << 0;

/// `XdpConfig::flags`：启用 RST 合法窗口校验。
pub const CFG_F_ENABLE_RST_VALIDATE: u32 = 1 << 1;

/// `XdpConfig::flags`：启用 ACK flood 检测。
pub const CFG_F_ENABLE_ACK_FLOOD: u32 = 1 << 2;

/// `XdpConfig::flags`：启用 SYN proxy（syncookie）模式。
pub const CFG_F_ENABLE_SYN_PROXY: u32 = 1 << 3;

/// `XdpConfig::flags`：全局防御模式（由用户态置位；XDP 仅读取）。
pub const CFG_F_GLOBAL_DEFENSE_MODE: u32 = 1 << 4;

/// `XdpConfig::flags`：启用 UDP 目标端口统计。
pub const CFG_F_ENABLE_UDP_STATS: u32 = 1 << 5;

/// `XdpConfig::flags`：启用 UDP 端口限速（固定窗口）。
pub const CFG_F_ENABLE_UDP_RATE_LIMIT: u32 = 1 << 6;

/// `XdpConfig::flags`：启用 CIDR 多前缀匹配（会增加 map lookup 次数；默认建议关闭）。
pub const CFG_F_ENABLE_CIDR_LOOKUP: u32 = 1 << 7;

/// `XdpConfig::flags`：丢弃 IPv4 分片包（无法可靠解析 L4，避免绕过）。
pub const CFG_F_DROP_IPV4_FRAGS: u32 = 1 << 8;

/// 封禁原因枚举。
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum BlockReason {
    /// 未知原因/保留。
    Unknown = 0,
    /// SYN flood（指数衰减 score 超过阈值且持续触发）。
    SynFlood = 1,
    /// ACK flood（ACK-only 速率超过阈值且持续触发）。
    AckFlood = 2,
    /// RST 非法（序列号不在窗口或无连接状态）。
    RstInvalid = 3,
    /// UDP 端口限速触发。
    UdpRateLimit = 4,
    /// 用户态手动封禁。
    Manual = 5,
}

/// 攻击类型枚举（用于事件上报）。
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum AttackKind {
    /// SYN flood。
    SynFlood = 1,
    /// ACK flood。
    AckFlood = 2,
    /// RST flood / RST spoof。
    RstFlood = 3,
    /// UDP 放大攻击相关（仅数据采集/限速触发事件）。
    Amplification = 4,
}

/// RingBuf 事件类型枚举。
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum XdpEventKind {
    /// 某 IP 被写入 blacklist。
    IpBlocked = 1,
    /// 检测到攻击/异常（例如 SYN score 超阈值、ACK flood 触发等）。
    AttackDetected = 2,
    /// Map 接近容量上限或写入失败（best-effort）。
    MapNearFull = 3,
    /// 全局防御模式被激活（由 XDP 观察到 config flag；best-effort）。
    GlobalDefenseActivated = 4,
}

/// 哪个 map 的告警（best-effort）。
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MapKind {
    Whitelist = 1,
    Blacklist = 2,
    SynState = 3,
    GlobalStats = 4,
    Config = 5,
    Events = 6,
    Conntrack = 7,
    PortStats = 8,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct IpKey {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub _pad: [u8; 7],
}

impl IpKey {
    /// 创建一个 IpKey（显式给出 16 字节地址与 prefix_len）。
    #[inline(always)]
    pub const fn new(addr: [u8; 16], prefix_len: u8) -> Self {
        Self {
            addr,
            prefix_len,
            _pad: [0u8; 7],
        }
    }

    /// IPv4 -> IPv6-mapped（精确 /32），prefix_len=128。
    #[inline(always)]
    pub const fn from_ipv4_exact(ipv4: [u8; 4]) -> Self {
        Self::from_ipv4_cidr(ipv4, 32)
    }

    /// IPv4 -> IPv6-mapped（CIDR）。
    #[inline(always)]
    pub const fn from_ipv4_cidr(ipv4: [u8; 4], prefix_len_v4: u8) -> Self {
        // ::ffff:a.b.c.d
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12] = ipv4[0];
        addr[13] = ipv4[1];
        addr[14] = ipv4[2];
        addr[15] = ipv4[3];

        // IPv4 prefix 映射到 128-bit：前 96 位固定 + v4 prefix
        let prefix_len = 96u8.saturating_add(prefix_len_v4);
        Self::new(addr, prefix_len)
    }

    /// IPv6（精确 /128）。
    #[inline(always)]
    pub const fn from_ipv6_exact(ipv6: [u8; 16]) -> Self {
        Self::new(ipv6, 128)
    }

    /// IPv6（CIDR）。
    #[inline(always)]
    pub const fn from_ipv6_cidr(ipv6: [u8; 16], prefix_len: u8) -> Self {
        Self::new(ipv6, prefix_len)
    }

    /// 判断是否为 IPv4-mapped 地址：`::ffff:a.b.c.d`
    #[inline(always)]
    pub fn is_ipv4_mapped(&self) -> bool {
        // 10 字节 0 + 2 字节 0xff
        let mut i = 0usize;
        while i < 10 {
            if self.addr[i] != 0 {
                return false;
            }
            i += 1;
        }
        self.addr[10] == 0xff && self.addr[11] == 0xff
    }

    /// 返回该 IpKey 的“精确匹配版本”（prefix_len=128）。
    #[inline(always)]
    pub fn as_exact(&self) -> Self {
        let mut k = *self;
        k.prefix_len = 128;
        k._pad = [0u8; 7];
        k
    }
}

/// 黑名单条目：原因 + 时间戳 + TTL。
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BlacklistEntry {
    pub reason: BlockReason,
    pub _pad0: u32,
    pub blocked_at_ns: u64,
    pub ttl_ns: u64,
}

impl BlacklistEntry {
    /// 创建黑名单条目。
    #[inline(always)]
    pub const fn new(reason: BlockReason, blocked_at_ns: u64, ttl_ns: u64) -> Self {
        Self {
            reason,
            _pad0: 0,
            blocked_at_ns,
            ttl_ns,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SynState {
    /// 指数衰减 SYN score（整数）。
    pub syn_score: u32,
    /// 指数衰减 ACK-only score（整数）。
    pub ack_score: u32,
    /// 上次更新时间（ns）。
    pub last_update_ns: u64,
    /// 状态 flags（SUSPECT 等）。
    pub flags: u32,
    /// 连续 SYN 超阈值 drop 次数（用于触发 blacklist）。
    pub syn_drop_streak: u16,
    /// 连续 ACK flood drop 次数（用于触发 blacklist）。
    pub ack_drop_streak: u16,
}

impl SynState {
    /// 创建初始状态（全 0）。
    #[inline(always)]
    pub const fn zeroed(now_ns: u64) -> Self {
        Self {
            syn_score: 0,
            ack_score: 0,
            last_update_ns: now_ns,
            flags: 0,
            syn_drop_streak: 0,
            ack_drop_streak: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GlobalStats {
    pub packets: u64,
    pub bytes: u64,

    pub pass: u64,
    pub drop: u64,

    pub pass_whitelist: u64,
    pub drop_blacklist: u64,

    pub tcp_packets: u64,
    pub udp_packets: u64,

    pub syn_packets: u64,
    pub syn_drops: u64,

    pub ack_only_packets: u64,
    pub ack_drops: u64,

    pub rst_packets: u64,
    pub rst_drops: u64,

    pub udp_tracked_packets: u64,
    pub udp_drops: u64,

    /// 过去 60 秒每秒 SYN 数（环形数组）。
    pub syn_per_sec: [u32; SYN_RING_SECONDS],
    /// 当前写入位置（0..59）。
    pub syn_ring_idx: u32,
    pub _pad0: u32,
    /// 上次写入的秒级时间戳（sec = now_ns / 1e9）。
    pub last_syn_sec: u64,
}

impl GlobalStats {
    /// 初始化（全 0）。
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            pass: 0,
            drop: 0,
            pass_whitelist: 0,
            drop_blacklist: 0,
            tcp_packets: 0,
            udp_packets: 0,
            syn_packets: 0,
            syn_drops: 0,
            ack_only_packets: 0,
            ack_drops: 0,
            rst_packets: 0,
            rst_drops: 0,
            udp_tracked_packets: 0,
            udp_drops: 0,
            syn_per_sec: [0u32; SYN_RING_SECONDS],
            syn_ring_idx: 0,
            _pad0: 0,
            last_syn_sec: 0,
        }
    }
}

/// UDP 目标端口统计（per-CPU array value）。
///
/// 注意：该 map 为 PERCPU_ARRAY，按端口索引（逻辑上 u16，实际 array key 为 u32）。
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PortStats {
    pub packets: u64,
    pub bytes: u64,
    /// 包大小分布桶（8 个区间）。
    pub size_buckets: [u64; 8],

    /// 固定窗口限速：窗口起始时间（ns）。
    pub window_start_ns: u64,
    /// 固定窗口内包计数（per-CPU）。
    pub window_packets: u32,
    /// 固定窗口内字节计数（per-CPU）。
    pub window_bytes: u32,
}

impl PortStats {
    /// 初始化。
    #[inline(always)]
    pub const fn zeroed() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            size_buckets: [0u64; 8],
            window_start_ns: 0,
            window_packets: 0,
            window_bytes: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ConnKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad0: [u8; 3],
}

impl ConnKey {
    #[inline(always)]
    pub const fn new(
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            proto,
            _pad0: [0u8; 3],
        }
    }
}

/// 活跃连接状态（LRU hash value）。
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnState {
    /// 最近观察到的客户端 -> 本机 seq（用于 RST 窗口验证中心值）。
    pub seq_center: u32,
    pub _pad0: u32,
    pub created_at_ns: u64,
    pub last_seen_ns: u64,
    pub expires_at_ns: u64,
}

impl ConnState {
    #[inline(always)]
    pub const fn new(seq_center: u32, now_ns: u64, ttl_ns: u64) -> Self {
        Self {
            seq_center,
            _pad0: 0,
            created_at_ns: now_ns,
            last_seen_ns: now_ns,
            expires_at_ns: now_ns.saturating_add(ttl_ns),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XdpConfig {
    /// 魔数：`XDP_CONFIG_MAGIC`
    pub magic: u32,
    /// ABI 版本：`ARC_XDP_ABI_VERSION`
    pub version: u32,
    /// 开关 flags：`CFG_F_*`
    pub flags: u32,
    pub _pad0: u32,

    /// 动态 SYN 阈值（由用户态计算写入；XDP 仅比较）。
    pub syn_threshold: u32,

    /// ACK flood：每连接允许的 ACK-only 倍数（默认 10，由用户态写入）。
    pub ack_limit_per_conn: u32,

    /// 当前活跃连接数估计（由用户态计算写入；XDP 仅读取）。
    pub active_conns_estimate: u32,

    /// RST 序列号窗口大小（默认 65535）。
    pub rst_window_size: u32,

    /// 连续 SYN drop 达到该次数后写入黑名单。
    pub syn_blacklist_after_drops: u16,
    /// 连续 ACK drop 达到该次数后写入黑名单。
    pub ack_blacklist_after_drops: u16,

    /// blacklist TTL（ns）。
    pub blacklist_ttl_ns: u64,
    /// conntrack TTL（ns）。
    pub conntrack_ttl_ns: u64,
    /// syn_state 软 TTL（ns）：超过该时间未更新则重置 score（节省内存/避免陈旧误判）。
    pub syn_state_ttl_ns: u64,

    /// UDP 固定窗口大小（ns），用于端口限速（per-CPU 固定窗口）。
    pub udp_window_ns: u64,

    /// 需要统计/限速的端口列表（最多 MAX_TRACKED_PORTS 个，0 表示 unused）。
    pub udp_tracked_ports: [u16; MAX_TRACKED_PORTS],
    pub _pad1: [u16; MAX_TRACKED_PORTS],

    /// UDP 限速：每端口最大 PPS（与 udp_tracked_ports 同 index，0 表示不限制）。
    pub udp_rate_limit_pps: [u32; MAX_TRACKED_PORTS],
    /// UDP 限速：每端口最大 BPS（与 udp_tracked_ports 同 index，0 表示不限制）。
    pub udp_rate_limit_bps: [u32; MAX_TRACKED_PORTS],

    pub syn_cookie_secret: [u8; 32],
    /// cookie key id / epoch（用户态维护）。
    pub syn_cookie_key_id: u64,
}

impl XdpConfig {
    /// 是否为有效配置（magic+version）。
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.magic == XDP_CONFIG_MAGIC && self.version == ARC_XDP_ABI_VERSION
    }

    /// 保守默认配置：不开启任何拦截功能，阈值设置为极大值以避免误杀。
    #[inline(always)]
    pub const fn conservative_default() -> Self {
        Self {
            magic: 0,
            version: 0,
            flags: 0,
            _pad0: 0,
            syn_threshold: u32::MAX,
            ack_limit_per_conn: 10,
            active_conns_estimate: 0,
            rst_window_size: 65535,
            syn_blacklist_after_drops: 0,
            ack_blacklist_after_drops: 0,
            blacklist_ttl_ns: 0,
            conntrack_ttl_ns: 0,
            syn_state_ttl_ns: 0,
            udp_window_ns: 1_000_000_000, // 1s
            udp_tracked_ports: [0u16; MAX_TRACKED_PORTS],
            _pad1: [0u16; MAX_TRACKED_PORTS],
            udp_rate_limit_pps: [0u32; MAX_TRACKED_PORTS],
            udp_rate_limit_bps: [0u32; MAX_TRACKED_PORTS],
            syn_cookie_secret: [0u8; 32],
            syn_cookie_key_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XdpEvent {
    pub kind: XdpEventKind,
    pub _pad0: u32,
    pub ts_ns: u64,
    pub ip: IpKey,
    pub arg0: u64,
    pub arg1: u64,
}

impl XdpEvent {
    /// 创建事件：IP 被封禁。
    #[inline(always)]
    pub const fn ip_blocked(ts_ns: u64, ip: IpKey, reason: BlockReason, ttl_ns: u64) -> Self {
        Self {
            kind: XdpEventKind::IpBlocked,
            _pad0: 0,
            ts_ns,
            ip,
            arg0: reason as u64,
            arg1: ttl_ns,
        }
    }

    /// 创建事件：攻击检测。
    #[inline(always)]
    pub const fn attack_detected(
        ts_ns: u64,
        ip: IpKey,
        kind: AttackKind,
        score: u32,
        threshold: u32,
    ) -> Self {
        let arg0 = (kind as u64) | ((score as u64) << 32);
        Self {
            kind: XdpEventKind::AttackDetected,
            _pad0: 0,
            ts_ns,
            ip,
            arg0,
            arg1: threshold as u64,
        }
    }

    /// 创建事件：map 接近满或写失败（best-effort）。
    #[inline(always)]
    pub const fn map_near_full(
        ts_ns: u64,
        ip: IpKey,
        map: MapKind,
        approx_usage_permille: u32,
    ) -> Self {
        let arg0 = (map as u64) | ((approx_usage_permille as u64) << 32);
        Self {
            kind: XdpEventKind::MapNearFull,
            _pad0: 0,
            ts_ns,
            ip,
            arg0,
            arg1: 0,
        }
    }

    /// 创建事件：全局防御模式状态变化（best-effort）。
    #[inline(always)]
    pub const fn global_defense(ts_ns: u64, enabled: bool) -> Self {
        Self {
            kind: XdpEventKind::GlobalDefenseActivated,
            _pad0: 0,
            ts_ns,
            ip: IpKey::new([0u8; 16], 0),
            arg0: if enabled { 1 } else { 0 },
            arg1: 0,
        }
    }
}

// ---- Pod 实现（feature gate） ----
//
// 说明：aya 用户态与 aya_ebpf 内核态的 Pod trait 位于不同 crate；
// 因此必须在 common crate 内用 feature gate 分别实现。
// 这些 unsafe impl 依赖于：
// - #[repr(C)]
// - 仅包含 Pod 字段
// - 所有 padding 字节在写入 map 前被初始化（本实现所有 struct 均显式 pad 字段，且构造函数写 0）

#[cfg(feature = "user")]
mod pod_user {
    use super::*;
    use aya::Pod;

    // SAFETY: 所有类型均为 #[repr(C)] 且仅包含标量/数组字段，且显式 pad 字段初始化为 0。
    unsafe impl Pod for IpKey {}
    unsafe impl Pod for BlacklistEntry {}
    unsafe impl Pod for SynState {}
    unsafe impl Pod for GlobalStats {}
    unsafe impl Pod for PortStats {}
    unsafe impl Pod for ConnKey {}
    unsafe impl Pod for ConnState {}
    unsafe impl Pod for XdpConfig {}
    unsafe impl Pod for XdpEvent {}
}

#[cfg(feature = "bpf")]
mod pod_bpf {
    // aya-ebpf 0.1.x 的 map API 不要求 Pod trait 约束；
    // bpf 侧无需额外实现，保留模块仅作为 feature 锚点。
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipkey_ipv4_mapping_and_prefix_are_correct() {
        let k = IpKey::from_ipv4_exact([1, 2, 3, 4]);
        assert!(k.is_ipv4_mapped());
        assert_eq!(k.prefix_len, 128);
        assert_eq!(k.addr[10], 0xff);
        assert_eq!(k.addr[11], 0xff);
        assert_eq!(&k.addr[12..16], &[1, 2, 3, 4]);

        let cidr = IpKey::from_ipv4_cidr([10, 0, 0, 1], 24);
        assert_eq!(cidr.prefix_len, 120);
    }

    #[test]
    fn ipkey_as_exact_sets_prefix_128() {
        let k = IpKey::from_ipv6_cidr([0u8; 16], 64);
        let exact = k.as_exact();
        assert_eq!(exact.prefix_len, 128);
        assert_eq!(exact.addr, k.addr);
    }

    #[test]
    fn xdp_config_conservative_default_and_validity() {
        let mut c = XdpConfig::conservative_default();
        assert!(!c.is_valid());
        assert_eq!(c.flags, 0);
        assert_eq!(c.syn_threshold, u32::MAX);

        c.magic = XDP_CONFIG_MAGIC;
        c.version = ARC_XDP_ABI_VERSION;
        assert!(c.is_valid());
    }

    #[test]
    fn xdp_event_constructors_encode_expected_fields() {
        let ip = IpKey::from_ipv4_exact([127, 0, 0, 1]);

        let e1 = XdpEvent::ip_blocked(10, ip, BlockReason::Manual, 99);
        assert_eq!(e1.kind as u32, XdpEventKind::IpBlocked as u32);
        assert_eq!(e1.arg0, BlockReason::Manual as u64);
        assert_eq!(e1.arg1, 99);

        let e2 = XdpEvent::attack_detected(11, ip, AttackKind::SynFlood, 7, 9);
        assert_eq!(e2.kind as u32, XdpEventKind::AttackDetected as u32);
        assert_eq!((e2.arg0 & 0xFFFF_FFFF) as u32, AttackKind::SynFlood as u32);
        assert_eq!((e2.arg0 >> 32) as u32, 7);
        assert_eq!(e2.arg1, 9);

        let e3 = XdpEvent::global_defense(12, true);
        assert_eq!(e3.kind as u32, XdpEventKind::GlobalDefenseActivated as u32);
        assert_eq!(e3.arg0, 1);
    }

    #[test]
    fn zeroed_structs_start_from_clean_state() {
        let gs = GlobalStats::zeroed();
        assert_eq!(gs.packets, 0);
        assert_eq!(gs.syn_ring_idx, 0);
        assert_eq!(gs.syn_per_sec.len(), SYN_RING_SECONDS);
        assert!(gs.syn_per_sec.iter().all(|v| *v == 0));

        let ps = PortStats::zeroed();
        assert_eq!(ps.packets, 0);
        assert_eq!(ps.window_packets, 0);
        assert!(ps.size_buckets.iter().all(|v| *v == 0));
    }
}
