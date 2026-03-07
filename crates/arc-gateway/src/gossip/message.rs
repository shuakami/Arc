use super::msgpack::{Decoder, Encoder, MsgPackError, MsgPackResult};
use arc_xdp_common::{BlockReason, IpKey};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Globally unique id: (node_id + sequence).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id {
    pub node_id: Arc<str>,
    pub seq: u64,
}

impl Id {
    #[inline]
    pub fn encode(&self, enc: &mut Encoder) {
        enc.write_array_len(2);
        enc.write_str(self.node_id.as_ref());
        enc.write_u64(self.seq);
    }

    #[inline]
    pub fn decode(dec: &mut Decoder<'_>) -> MsgPackResult<Self> {
        let len = dec.read_array_len()?;
        if len != 2 {
            return Err(MsgPackError::InvalidData("id must be array[2]"));
        }
        let node_id = Arc::<str>::from(dec.read_str()?);
        let seq = dec.read_u64()?;
        Ok(Self { node_id, seq })
    }
}

/// Node metadata attached to every wire message.
#[derive(Debug, Clone)]
pub struct NodeMeta {
    pub node_id: Arc<str>,
    pub addr: SocketAddr,
    pub incarnation: u64,
    pub config_version: u64,
}

impl NodeMeta {
    #[inline]
    pub fn encode(&self, enc: &mut Encoder) {
        enc.write_array_len(4);
        enc.write_str(self.node_id.as_ref());
        enc.write_str(&self.addr.to_string());
        enc.write_u64(self.incarnation);
        enc.write_u64(self.config_version);
    }

    #[inline]
    pub fn decode(dec: &mut Decoder<'_>) -> MsgPackResult<Self> {
        let len = dec.read_array_len()?;
        if len != 4 {
            return Err(MsgPackError::InvalidData("meta must be array[4]"));
        }
        let node_id = Arc::<str>::from(dec.read_str()?);
        let addr_s = dec.read_str()?;
        let addr = addr_s
            .parse::<SocketAddr>()
            .map_err(|_| MsgPackError::InvalidData("meta.addr must be socketaddr string"))?;
        let incarnation = dec.read_u64()?;
        let config_version = dec.read_u64()?;
        Ok(Self {
            node_id,
            addr,
            incarnation,
            config_version,
        })
    }
}

/// Member status for SWIM membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Alive = 0,
    Suspect = 1,
    Dead = 2,
}

impl MemberStatus {
    #[inline]
    pub fn from_u64(v: u64) -> MsgPackResult<Self> {
        match v {
            0 => Ok(MemberStatus::Alive),
            1 => Ok(MemberStatus::Suspect),
            2 => Ok(MemberStatus::Dead),
            _ => Err(MsgPackError::InvalidData("invalid member status")),
        }
    }

    #[inline]
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            MemberStatus::Alive => "alive",
            MemberStatus::Suspect => "suspect",
            MemberStatus::Dead => "dead",
        }
    }
}

/// Member rumor payload.
#[derive(Debug, Clone)]
pub struct MemberRumor {
    pub node_id: Arc<str>,
    pub addr: SocketAddr,
    pub status: MemberStatus,
    pub incarnation: u64,
    pub ts_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ConfigRumor {
    pub version: u64,
    pub raw_json: Arc<Vec<u8>>,
}

/// Circuit rumor payload (LWW per node).
#[derive(Debug, Clone)]
pub struct CircuitRumor {
    pub ts_ms: u64,
    pub open_until_ms: HashMap<String, u64>,
}

/// GCounter rumor payload (component update for the origin node).
#[derive(Debug, Clone)]
pub struct GCounterRumor {
    pub key: Arc<str>,
    pub value: u64,
}

/// XDP blacklist delta rumor payload.
#[derive(Clone)]
pub struct XdpBlockRumor {
    pub ip: IpKey,
    pub action: XdpBlockAction,
    pub reason: BlockReason,
    /// TTL in milliseconds. 0 means no-expire.
    pub ttl_ms: u64,
    /// Origin observation timestamp (ms).
    pub observed_at_ms: u64,
}

impl std::fmt::Debug for XdpBlockRumor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpBlockRumor")
            .field("ip_addr", &self.ip.addr)
            .field("ip_prefix_len", &self.ip.prefix_len)
            .field("action", &self.action.as_u64())
            .field("reason", &block_reason_to_u64(self.reason))
            .field("ttl_ms", &self.ttl_ms)
            .field("observed_at_ms", &self.observed_at_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpBlockAction {
    Add = 0,
    Remove = 1,
}

impl XdpBlockAction {
    #[inline]
    pub fn from_u64(v: u64) -> MsgPackResult<Self> {
        match v {
            0 => Ok(Self::Add),
            1 => Ok(Self::Remove),
            _ => Err(MsgPackError::InvalidData("invalid xdp block action")),
        }
    }

    #[inline]
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// Rumor kind.
#[derive(Debug, Clone)]
pub enum RumorKind {
    Member(MemberRumor),
    Config(ConfigRumor),
    Circuit(CircuitRumor),
    GCounter(GCounterRumor),
    XdpBlock(XdpBlockRumor),
}

/// A single rumor envelope (one rumor per UDP packet).
#[derive(Debug, Clone)]
pub struct RumorEnvelope {
    pub id: Id,
    pub hop: u8,
    pub kind: RumorKind,
}

impl RumorEnvelope {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.write_array_len(4);
        self.id.encode(enc);
        enc.write_u64(u64::from(self.hop));
        match &self.kind {
            RumorKind::Member(r) => {
                enc.write_u64(0);
                encode_member_rumor(enc, r);
            }
            RumorKind::Config(r) => {
                enc.write_u64(1);
                encode_config_rumor(enc, r);
            }
            RumorKind::Circuit(r) => {
                enc.write_u64(2);
                encode_circuit_rumor(enc, r);
            }
            RumorKind::GCounter(r) => {
                enc.write_u64(3);
                encode_gcounter_rumor(enc, r);
            }
            RumorKind::XdpBlock(r) => {
                enc.write_u64(4);
                encode_xdp_block_rumor(enc, r);
            }
        }
    }

    pub fn decode(dec: &mut Decoder<'_>) -> MsgPackResult<Self> {
        let len = dec.read_array_len()?;
        if len != 4 {
            return Err(MsgPackError::InvalidData("rumor must be array[4]"));
        }
        let id = Id::decode(dec)?;
        let hop_u = dec.read_u64()?;
        let hop = u8::try_from(hop_u).map_err(|_| MsgPackError::InvalidData("hop overflow"))?;
        let kind_code = dec.read_u64()?;
        let kind = match kind_code {
            0 => RumorKind::Member(decode_member_rumor(dec)?),
            1 => RumorKind::Config(decode_config_rumor(dec)?),
            2 => RumorKind::Circuit(decode_circuit_rumor(dec)?),
            3 => RumorKind::GCounter(decode_gcounter_rumor(dec)?),
            4 => RumorKind::XdpBlock(decode_xdp_block_rumor(dec)?),
            _ => return Err(MsgPackError::InvalidData("unknown rumor kind")),
        };
        Ok(Self { id, hop, kind })
    }
}

/// Wire message used for UDP gossip / SWIM.
#[derive(Debug, Clone)]
pub enum WireMsg {
    /// SWIM direct ping.
    Ping { meta: NodeMeta, probe: Id },

    /// Ack for ping (direct or forwarded). If forwarded, `target` is set.
    Ack {
        meta: NodeMeta,
        probe: Id,
        target: Option<NodeMeta>,
    },

    /// SWIM indirect probe request (ping-req).
    PingReq {
        meta: NodeMeta,
        probe: Id,
        target_id: Arc<str>,
        target_addr: SocketAddr,
        origin_addr: SocketAddr,
    },

    /// Join request (best-effort; initial full sync is done via TCP).
    Join { meta: NodeMeta },

    /// Join ack.
    JoinAck { meta: NodeMeta },

    /// A single rumor.
    Rumor {
        meta: NodeMeta,
        rumor: RumorEnvelope,
    },

    /// Fragment (for UDP size > max_message_size).
    Fragment {
        meta: NodeMeta,
        id: Id,
        idx: u16,
        total: u16,
        data: Vec<u8>,
    },
}

impl WireMsg {
    /// Encode to MessagePack bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::with_capacity(256);
        match self {
            WireMsg::Ping { meta, probe } => {
                enc.write_array_len(3);
                enc.write_u64(0);
                meta.encode(&mut enc);
                probe.encode(&mut enc);
            }
            WireMsg::Ack {
                meta,
                probe,
                target,
            } => {
                enc.write_array_len(4);
                enc.write_u64(1);
                meta.encode(&mut enc);
                probe.encode(&mut enc);
                match target {
                    Some(t) => t.encode(&mut enc),
                    None => enc.write_nil(),
                }
            }
            WireMsg::PingReq {
                meta,
                probe,
                target_id,
                target_addr,
                origin_addr,
            } => {
                enc.write_array_len(6);
                enc.write_u64(2);
                meta.encode(&mut enc);
                probe.encode(&mut enc);
                enc.write_str(target_id.as_ref());
                enc.write_str(&target_addr.to_string());
                enc.write_str(&origin_addr.to_string());
            }
            WireMsg::Join { meta } => {
                enc.write_array_len(2);
                enc.write_u64(3);
                meta.encode(&mut enc);
            }
            WireMsg::JoinAck { meta } => {
                enc.write_array_len(2);
                enc.write_u64(4);
                meta.encode(&mut enc);
            }
            WireMsg::Rumor { meta, rumor } => {
                enc.write_array_len(3);
                enc.write_u64(5);
                meta.encode(&mut enc);
                rumor.encode(&mut enc);
            }
            WireMsg::Fragment {
                meta,
                id,
                idx,
                total,
                data,
            } => {
                enc.write_array_len(6);
                enc.write_u64(8);
                meta.encode(&mut enc);
                id.encode(&mut enc);
                enc.write_u64(u64::from(*idx));
                enc.write_u64(u64::from(*total));
                enc.write_bin(data);
            }
        }
        enc.into_inner()
    }

    /// Decode MessagePack bytes.
    pub fn decode(buf: &[u8]) -> MsgPackResult<Self> {
        let mut dec = Decoder::new(buf);
        let arr_len = dec.read_array_len()?;
        if arr_len < 2 {
            return Err(MsgPackError::InvalidData("wire msg must be array"));
        }

        let typ = dec.read_u64()?;
        match typ {
            0 => {
                // Ping: [0, meta, probe]
                if arr_len != 3 {
                    return Err(MsgPackError::InvalidData("ping must be array[3]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                let probe = Id::decode(&mut dec)?;
                Ok(WireMsg::Ping { meta, probe })
            }
            1 => {
                // Ack: [1, meta, probe, target_or_nil]
                if arr_len != 4 {
                    return Err(MsgPackError::InvalidData("ack must be array[4]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                let probe = Id::decode(&mut dec)?;
                let peek = dec.peek_u8()?;
                let target = if peek == 0xc0 {
                    dec.read_nil()?;
                    None
                } else {
                    Some(NodeMeta::decode(&mut dec)?)
                };
                Ok(WireMsg::Ack {
                    meta,
                    probe,
                    target,
                })
            }
            2 => {
                // PingReq: [2, meta, probe, target_id, target_addr, origin_addr]
                if arr_len != 6 {
                    return Err(MsgPackError::InvalidData("ping-req must be array[6]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                let probe = Id::decode(&mut dec)?;
                let target_id = Arc::<str>::from(dec.read_str()?);
                let target_addr_s = dec.read_str()?;
                let origin_addr_s = dec.read_str()?;
                let target_addr = target_addr_s
                    .parse::<SocketAddr>()
                    .map_err(|_| MsgPackError::InvalidData("ping-req target_addr invalid"))?;
                let origin_addr = origin_addr_s
                    .parse::<SocketAddr>()
                    .map_err(|_| MsgPackError::InvalidData("ping-req origin_addr invalid"))?;
                Ok(WireMsg::PingReq {
                    meta,
                    probe,
                    target_id,
                    target_addr,
                    origin_addr,
                })
            }
            3 => {
                // Join: [3, meta]
                if arr_len != 2 {
                    return Err(MsgPackError::InvalidData("join must be array[2]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                Ok(WireMsg::Join { meta })
            }
            4 => {
                // JoinAck: [4, meta]
                if arr_len != 2 {
                    return Err(MsgPackError::InvalidData("join-ack must be array[2]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                Ok(WireMsg::JoinAck { meta })
            }
            5 => {
                // Rumor: [5, meta, rumor]
                if arr_len != 3 {
                    return Err(MsgPackError::InvalidData("rumor msg must be array[3]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                let rumor = RumorEnvelope::decode(&mut dec)?;
                Ok(WireMsg::Rumor { meta, rumor })
            }
            8 => {
                // Fragment: [8, meta, id, idx, total, data]
                if arr_len != 6 {
                    return Err(MsgPackError::InvalidData("fragment must be array[6]"));
                }
                let meta = NodeMeta::decode(&mut dec)?;
                let id = Id::decode(&mut dec)?;
                let idx_u = dec.read_u64()?;
                let total_u = dec.read_u64()?;
                let idx = u16::try_from(idx_u)
                    .map_err(|_| MsgPackError::InvalidData("frag idx overflow"))?;
                let total = u16::try_from(total_u)
                    .map_err(|_| MsgPackError::InvalidData("frag total overflow"))?;
                let data = dec.read_bin()?;
                Ok(WireMsg::Fragment {
                    meta,
                    id,
                    idx,
                    total,
                    data,
                })
            }
            _ => Err(MsgPackError::InvalidData("unknown wire msg type")),
        }
    }
}

/// TCP full sync request.
#[derive(Debug, Clone)]
pub struct SyncRequest {
    pub meta: NodeMeta,
}

/// TCP full sync response.
#[derive(Debug, Clone)]
pub struct SyncResponse {
    pub meta: NodeMeta,
    pub members: Vec<SyncMember>,
    pub config: SyncConfig,
    pub circuits: Vec<SyncCircuit>,
    pub gcounters: Vec<SyncGCounter>,
    pub xdp_blocks: Vec<SyncXdpBlock>,
}

/// Member snapshot used in TCP sync.
#[derive(Debug, Clone)]
pub struct SyncMember {
    pub node_id: Arc<str>,
    pub addr: SocketAddr,
    pub status: MemberStatus,
    pub incarnation: u64,
    pub last_seen_ms: u64,
    pub config_version: u64,
}

/// Config snapshot used in TCP sync.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub version: u64,
    pub origin: Arc<str>,
    pub raw_json: Arc<Vec<u8>>,
}

/// Circuit snapshot used in TCP sync.
#[derive(Debug, Clone)]
pub struct SyncCircuit {
    pub node_id: Arc<str>,
    pub ts_ms: u64,
    pub open_until_ms: HashMap<String, u64>,
}

/// GCounter snapshot used in TCP sync.
#[derive(Debug, Clone)]
pub struct SyncGCounter {
    pub key: String,
    pub per_node: HashMap<Arc<str>, u64>,
}

/// XDP blacklist snapshot item used in TCP sync.
#[derive(Clone)]
pub struct SyncXdpBlock {
    pub ip: IpKey,
    pub reason: BlockReason,
    /// TTL in milliseconds. 0 means no-expire.
    pub ttl_ms: u64,
    /// Origin observation timestamp (ms).
    pub observed_at_ms: u64,
}

impl std::fmt::Debug for SyncXdpBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncXdpBlock")
            .field("ip_addr", &self.ip.addr)
            .field("ip_prefix_len", &self.ip.prefix_len)
            .field("reason", &block_reason_to_u64(self.reason))
            .field("ttl_ms", &self.ttl_ms)
            .field("observed_at_ms", &self.observed_at_ms)
            .finish()
    }
}

impl SyncRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::with_capacity(128);
        enc.write_array_len(2);
        enc.write_u64(0);
        self.meta.encode(&mut enc);
        enc.into_inner()
    }

    pub fn decode(buf: &[u8]) -> MsgPackResult<Self> {
        let mut dec = Decoder::new(buf);
        let len = dec.read_array_len()?;
        if len != 2 {
            return Err(MsgPackError::InvalidData("sync req must be array[2]"));
        }
        let typ = dec.read_u64()?;
        if typ != 0 {
            return Err(MsgPackError::InvalidData("sync req type mismatch"));
        }
        let meta = NodeMeta::decode(&mut dec)?;
        Ok(Self { meta })
    }
}

impl SyncResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::with_capacity(1024);
        enc.write_array_len(7);
        enc.write_u64(1);
        self.meta.encode(&mut enc);

        // members
        enc.write_array_len(self.members.len());
        for m in self.members.iter() {
            enc.write_array_len(6);
            enc.write_str(m.node_id.as_ref());
            enc.write_str(&m.addr.to_string());
            enc.write_u64(m.status.as_u64());
            enc.write_u64(m.incarnation);
            enc.write_u64(m.last_seen_ms);
            enc.write_u64(m.config_version);
        }

        // config
        enc.write_array_len(3);
        enc.write_u64(self.config.version);
        enc.write_str(self.config.origin.as_ref());
        enc.write_bin(self.config.raw_json.as_ref());

        // circuits
        enc.write_array_len(self.circuits.len());
        for c in self.circuits.iter() {
            enc.write_array_len(3);
            enc.write_str(c.node_id.as_ref());
            enc.write_u64(c.ts_ms);
            encode_map_string_u64(&mut enc, &c.open_until_ms);
        }

        // gcounters
        enc.write_array_len(self.gcounters.len());
        for g in self.gcounters.iter() {
            enc.write_array_len(2);
            enc.write_str(g.key.as_str());
            encode_map_arcstr_u64(&mut enc, &g.per_node);
        }

        // xdp blocks
        enc.write_array_len(self.xdp_blocks.len());
        for b in self.xdp_blocks.iter() {
            encode_sync_xdp_block(&mut enc, b);
        }

        enc.into_inner()
    }

    pub fn decode(buf: &[u8]) -> MsgPackResult<Self> {
        let mut dec = Decoder::new(buf);
        let len = dec.read_array_len()?;
        if len != 6 && len != 7 {
            return Err(MsgPackError::InvalidData("sync resp must be array[6|7]"));
        }
        let typ = dec.read_u64()?;
        if typ != 1 {
            return Err(MsgPackError::InvalidData("sync resp type mismatch"));
        }
        let meta = NodeMeta::decode(&mut dec)?;

        // members
        let mlen = dec.read_array_len()?;
        let mut members = Vec::with_capacity(mlen);
        for _ in 0..mlen {
            let alen = dec.read_array_len()?;
            if alen != 6 {
                return Err(MsgPackError::InvalidData("sync member must be array[6]"));
            }
            let node_id = Arc::<str>::from(dec.read_str()?);
            let addr_s = dec.read_str()?;
            let addr = addr_s
                .parse::<SocketAddr>()
                .map_err(|_| MsgPackError::InvalidData("sync member addr invalid"))?;
            let status = MemberStatus::from_u64(dec.read_u64()?)?;
            let incarnation = dec.read_u64()?;
            let last_seen_ms = dec.read_u64()?;
            let config_version = dec.read_u64()?;
            members.push(SyncMember {
                node_id,
                addr,
                status,
                incarnation,
                last_seen_ms,
                config_version,
            });
        }

        // config
        let clen = dec.read_array_len()?;
        if clen != 3 {
            return Err(MsgPackError::InvalidData("sync config must be array[3]"));
        }
        let version = dec.read_u64()?;
        let origin = Arc::<str>::from(dec.read_str()?);
        let raw_json = Arc::new(dec.read_bin()?);
        let config = SyncConfig {
            version,
            origin,
            raw_json,
        };

        // circuits
        let ccount = dec.read_array_len()?;
        let mut circuits = Vec::with_capacity(ccount);
        for _ in 0..ccount {
            let alen = dec.read_array_len()?;
            if alen != 3 {
                return Err(MsgPackError::InvalidData("sync circuit must be array[3]"));
            }
            let node_id = Arc::<str>::from(dec.read_str()?);
            let ts_ms = dec.read_u64()?;
            let open_until_ms = decode_map_string_u64(&mut dec)?;
            circuits.push(SyncCircuit {
                node_id,
                ts_ms,
                open_until_ms,
            });
        }

        // gcounters
        let gcount = dec.read_array_len()?;
        let mut gcounters = Vec::with_capacity(gcount);
        for _ in 0..gcount {
            let alen = dec.read_array_len()?;
            if alen != 2 {
                return Err(MsgPackError::InvalidData("sync gcounter must be array[2]"));
            }
            let key = dec.read_str()?;
            let per_node = decode_map_arcstr_u64(&mut dec)?;
            gcounters.push(SyncGCounter { key, per_node });
        }

        // xdp blocks (added in newer protocol; optional for backward compatibility)
        let mut xdp_blocks = Vec::new();
        if len == 7 {
            let bcount = dec.read_array_len()?;
            xdp_blocks.reserve(bcount);
            for _ in 0..bcount {
                xdp_blocks.push(decode_sync_xdp_block(&mut dec)?);
            }
        }

        Ok(SyncResponse {
            meta,
            members,
            config,
            circuits,
            gcounters,
            xdp_blocks,
        })
    }
}

fn encode_member_rumor(enc: &mut Encoder, r: &MemberRumor) {
    enc.write_array_len(5);
    enc.write_str(r.node_id.as_ref());
    enc.write_str(&r.addr.to_string());
    enc.write_u64(r.status.as_u64());
    enc.write_u64(r.incarnation);
    enc.write_u64(r.ts_ms);
}

fn decode_member_rumor(dec: &mut Decoder<'_>) -> MsgPackResult<MemberRumor> {
    let len = dec.read_array_len()?;
    if len != 5 {
        return Err(MsgPackError::InvalidData("member rumor must be array[5]"));
    }
    let node_id = Arc::<str>::from(dec.read_str()?);
    let addr_s = dec.read_str()?;
    let addr = addr_s
        .parse::<SocketAddr>()
        .map_err(|_| MsgPackError::InvalidData("member rumor addr invalid"))?;
    let status = MemberStatus::from_u64(dec.read_u64()?)?;
    let incarnation = dec.read_u64()?;
    let ts_ms = dec.read_u64()?;
    Ok(MemberRumor {
        node_id,
        addr,
        status,
        incarnation,
        ts_ms,
    })
}

fn encode_config_rumor(enc: &mut Encoder, r: &ConfigRumor) {
    enc.write_array_len(2);
    enc.write_u64(r.version);
    enc.write_bin(r.raw_json.as_ref());
}

fn decode_config_rumor(dec: &mut Decoder<'_>) -> MsgPackResult<ConfigRumor> {
    let len = dec.read_array_len()?;
    if len != 2 {
        return Err(MsgPackError::InvalidData("config rumor must be array[2]"));
    }
    let version = dec.read_u64()?;
    let raw_json = Arc::new(dec.read_bin()?);
    Ok(ConfigRumor { version, raw_json })
}

fn encode_circuit_rumor(enc: &mut Encoder, r: &CircuitRumor) {
    enc.write_array_len(2);
    enc.write_u64(r.ts_ms);
    encode_map_string_u64(enc, &r.open_until_ms);
}

fn decode_circuit_rumor(dec: &mut Decoder<'_>) -> MsgPackResult<CircuitRumor> {
    let len = dec.read_array_len()?;
    if len != 2 {
        return Err(MsgPackError::InvalidData("circuit rumor must be array[2]"));
    }
    let ts_ms = dec.read_u64()?;
    let open_until_ms = decode_map_string_u64(dec)?;
    Ok(CircuitRumor {
        ts_ms,
        open_until_ms,
    })
}

fn encode_gcounter_rumor(enc: &mut Encoder, r: &GCounterRumor) {
    enc.write_array_len(2);
    enc.write_str(r.key.as_ref());
    enc.write_u64(r.value);
}

fn decode_gcounter_rumor(dec: &mut Decoder<'_>) -> MsgPackResult<GCounterRumor> {
    let len = dec.read_array_len()?;
    if len != 2 {
        return Err(MsgPackError::InvalidData("gcounter rumor must be array[2]"));
    }
    let key = Arc::<str>::from(dec.read_str()?);
    let value = dec.read_u64()?;
    Ok(GCounterRumor { key, value })
}

fn encode_xdp_block_rumor(enc: &mut Encoder, r: &XdpBlockRumor) {
    enc.write_array_len(5);
    encode_ip_key(enc, &r.ip);
    enc.write_u64(r.action.as_u64());
    enc.write_u64(block_reason_to_u64(r.reason));
    enc.write_u64(r.ttl_ms);
    enc.write_u64(r.observed_at_ms);
}

fn decode_xdp_block_rumor(dec: &mut Decoder<'_>) -> MsgPackResult<XdpBlockRumor> {
    let len = dec.read_array_len()?;
    if len != 5 {
        return Err(MsgPackError::InvalidData(
            "xdp block rumor must be array[5]",
        ));
    }
    let ip = decode_ip_key(dec)?;
    let action = XdpBlockAction::from_u64(dec.read_u64()?)?;
    let reason = block_reason_from_u64(dec.read_u64()?)?;
    let ttl_ms = dec.read_u64()?;
    let observed_at_ms = dec.read_u64()?;
    Ok(XdpBlockRumor {
        ip,
        action,
        reason,
        ttl_ms,
        observed_at_ms,
    })
}

fn encode_sync_xdp_block(enc: &mut Encoder, b: &SyncXdpBlock) {
    enc.write_array_len(4);
    encode_ip_key(enc, &b.ip);
    enc.write_u64(block_reason_to_u64(b.reason));
    enc.write_u64(b.ttl_ms);
    enc.write_u64(b.observed_at_ms);
}

fn decode_sync_xdp_block(dec: &mut Decoder<'_>) -> MsgPackResult<SyncXdpBlock> {
    let len = dec.read_array_len()?;
    if len != 4 {
        return Err(MsgPackError::InvalidData("sync xdp block must be array[4]"));
    }
    let ip = decode_ip_key(dec)?;
    let reason = block_reason_from_u64(dec.read_u64()?)?;
    let ttl_ms = dec.read_u64()?;
    let observed_at_ms = dec.read_u64()?;
    Ok(SyncXdpBlock {
        ip,
        reason,
        ttl_ms,
        observed_at_ms,
    })
}

fn encode_ip_key(enc: &mut Encoder, ip: &IpKey) {
    enc.write_array_len(2);
    enc.write_bin(&ip.addr);
    enc.write_u64(u64::from(ip.prefix_len));
}

fn decode_ip_key(dec: &mut Decoder<'_>) -> MsgPackResult<IpKey> {
    let len = dec.read_array_len()?;
    if len != 2 {
        return Err(MsgPackError::InvalidData("ip key must be array[2]"));
    }
    let bytes = dec.read_bin()?;
    if bytes.len() != 16 {
        return Err(MsgPackError::InvalidData("ip key addr must be 16 bytes"));
    }
    let mut addr = [0u8; 16];
    addr.copy_from_slice(bytes.as_slice());
    let prefix_u = dec.read_u64()?;
    let prefix_len =
        u8::try_from(prefix_u).map_err(|_| MsgPackError::InvalidData("ip key prefix overflow"))?;
    Ok(IpKey::new(addr, prefix_len))
}

fn block_reason_to_u64(v: BlockReason) -> u64 {
    match v {
        BlockReason::Unknown => 0,
        BlockReason::SynFlood => 1,
        BlockReason::AckFlood => 2,
        BlockReason::RstInvalid => 3,
        BlockReason::UdpRateLimit => 4,
        BlockReason::Manual => 5,
    }
}

fn block_reason_from_u64(v: u64) -> MsgPackResult<BlockReason> {
    match v {
        0 => Ok(BlockReason::Unknown),
        1 => Ok(BlockReason::SynFlood),
        2 => Ok(BlockReason::AckFlood),
        3 => Ok(BlockReason::RstInvalid),
        4 => Ok(BlockReason::UdpRateLimit),
        5 => Ok(BlockReason::Manual),
        _ => Err(MsgPackError::InvalidData("invalid block reason")),
    }
}

fn encode_map_string_u64(enc: &mut Encoder, map: &HashMap<String, u64>) {
    enc.write_map_len(map.len());
    for (k, v) in map.iter() {
        enc.write_str(k.as_str());
        enc.write_u64(*v);
    }
}

fn decode_map_string_u64(dec: &mut Decoder<'_>) -> MsgPackResult<HashMap<String, u64>> {
    let len = dec.read_map_len()?;
    let mut out = HashMap::with_capacity(len);
    for _ in 0..len {
        let k = dec.read_str()?;
        let v = dec.read_u64()?;
        out.insert(k, v);
    }
    Ok(out)
}

fn encode_map_arcstr_u64(enc: &mut Encoder, map: &HashMap<Arc<str>, u64>) {
    enc.write_map_len(map.len());
    for (k, v) in map.iter() {
        enc.write_str(k.as_ref());
        enc.write_u64(*v);
    }
}

fn decode_map_arcstr_u64(dec: &mut Decoder<'_>) -> MsgPackResult<HashMap<Arc<str>, u64>> {
    let len = dec.read_map_len()?;
    let mut out: HashMap<Arc<str>, u64> = HashMap::with_capacity(len);
    for _ in 0..len {
        let k = Arc::<str>::from(dec.read_str()?);
        let v = dec.read_u64()?;
        out.insert(k, v);
    }
    Ok(out)
}
