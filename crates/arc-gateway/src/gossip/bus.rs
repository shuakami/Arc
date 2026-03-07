use crate::cluster_circuit::{ClusterCircuit, NodeCircuitSnapshot};
use crate::gossip::config::GossipRuntimeConfig;
use crate::gossip::message::{
    CircuitRumor, ConfigRumor, GCounterRumor, Id, MemberRumor, MemberStatus, NodeMeta,
    RumorEnvelope, RumorKind, SyncCircuit, SyncConfig, SyncGCounter, SyncMember, SyncRequest,
    SyncResponse, SyncXdpBlock, WireMsg, XdpBlockAction, XdpBlockRumor,
};
use arc_common::{ArcError, Result};
use arc_config::{ConfigManager, ControlPlaneConfig};
use arc_swap::ArcSwap;
use arc_xdp_common::IpKey;
use arc_xdp_userspace::manager::global_xdp_manager;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{oneshot, Mutex};
use tokio::time::{self, Instant};

/// Control-plane member view (GET /cluster/members).
#[derive(Debug, Clone, Serialize)]
pub struct GossipMemberView {
    pub id: String,
    pub address: String,
    pub status: String,
    pub config_version: u64,
    pub last_seen_ms: u64,
}

/// Control-plane stats view (GET /cluster/gossip/stats).
#[derive(Debug, Clone, Serialize)]
pub struct GossipStatsView {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub convergence_time_ms_p99: u64,
    pub members_alive: usize,
    pub members_suspect: usize,
    pub members_dead: usize,
}

pub struct GossipBus {
    mgr: ConfigManager,
    cluster_circuit: Arc<ClusterCircuit>,

    node_id: Arc<str>,

    // Runtime config is swapped atomically on config reload.
    runtime: ArcSwap<GossipRuntimeConfig>,

    // "running" means sockets are bound and background tasks are started.
    running: AtomicBool,

    // local metadata
    local_incarnation: AtomicU64,
    local_config_version: AtomicU64,

    // membership list (lock-free reads, atomics for hot fields)
    members: MemberList,

    // outgoing rumors to disseminate
    outgoing: StdMutex<OutgoingQueue>,

    // dedup for rumor ids
    seen: Mutex<HashMap<Id, u64>>,
    seen_ttl: Duration,

    // fragment reassembly
    reassembly: Mutex<HashMap<Id, ReassemblyEntry>>,

    // pending pings (origin=self)
    pending_pings: Mutex<HashMap<u64, oneshot::Sender<()>>>,

    // relay forwards (origin != self)
    relay_forwards: Mutex<HashMap<Id, RelayForward>>,

    // local delta generation
    last_circuit_open_until: Mutex<HashMap<String, u64>>,
    last_xdp_blacklist: Mutex<HashMap<IpDigest, XdpBlockSnapshot>>,
    last_xdp_scan_ms: AtomicU64,
    suppress_xdp_broadcast: Mutex<HashMap<IpDigest, u64>>,

    // stored circuit snapshots (for TCP sync)
    circuit_store: Mutex<HashMap<Arc<str>, StoredCircuit>>,

    // stored gcounter snapshots (for TCP sync)
    gcounter_store: Mutex<HashMap<String, HashMap<Arc<str>, u64>>>,

    // config state comparator (for conflict resolution + TCP sync origin)
    config_state: Mutex<ConfigState>,

    // local broadcast suppression (when we applied config from gossip)
    suppress_config_broadcast: AtomicU64,

    // generation tracking (ConfigManager generation)
    last_observed_generation: AtomicU64,
    last_broadcast_generation: AtomicU64,

    // approximate convergence metric
    convergence: Mutex<ConvergenceTracker>,

    // seq for rumor id generation
    seq: AtomicU64,

    // network sockets
    udp: OnceLock<Arc<UdpSocket>>,
    tcp: OnceLock<Arc<TcpListener>>,

    // shutdown coordination
    shutdown: AtomicBool,
    shutdown_notify: tokio::sync::Notify,

    stats: GossipStats,
}

impl GossipBus {
    /// Build a gossip bus from bootstrap config.
    ///
    /// Returns `None` if `cluster.gossip.enabled` is false or absent.
    pub fn from_bootstrap(
        mgr: ConfigManager,
        boot_cp: &ControlPlaneConfig,
        cluster_circuit: Arc<ClusterCircuit>,
    ) -> Option<Arc<Self>> {
        let raw = mgr.current().raw_json.clone();
        let runtime = GossipRuntimeConfig::parse_from_raw_json(raw.as_ref());
        if !runtime.gossip.enabled {
            return None;
        }

        let node_id: Arc<str> = Arc::from(boot_cp.node_id.clone());
        let now = now_ms();

        let local_cfg_ver = mgr.current_generation();

        let meta_addr = normalize_advertise(runtime.gossip.advertise);
        let members = MemberList::new(node_id.clone(), meta_addr, now, local_cfg_ver);

        let bus = Arc::new(Self {
            mgr,
            cluster_circuit: cluster_circuit.clone(),
            node_id: node_id.clone(),
            runtime: ArcSwap::from_pointee(runtime),
            running: AtomicBool::new(false),
            local_incarnation: AtomicU64::new(now.max(1)),
            local_config_version: AtomicU64::new(local_cfg_ver),
            members,
            outgoing: StdMutex::new(OutgoingQueue::new()),
            seen: Mutex::new(HashMap::new()),
            seen_ttl: Duration::from_secs(120),
            reassembly: Mutex::new(HashMap::new()),
            pending_pings: Mutex::new(HashMap::new()),
            relay_forwards: Mutex::new(HashMap::new()),
            last_circuit_open_until: Mutex::new(HashMap::new()),
            last_xdp_blacklist: Mutex::new(HashMap::new()),
            last_xdp_scan_ms: AtomicU64::new(0),
            suppress_xdp_broadcast: Mutex::new(HashMap::new()),
            circuit_store: Mutex::new(HashMap::new()),
            gcounter_store: Mutex::new(HashMap::new()),
            config_state: Mutex::new(ConfigState {
                version: local_cfg_ver,
                origin: node_id.clone(),
                applying: None,
            }),
            suppress_config_broadcast: AtomicU64::new(0),
            last_observed_generation: AtomicU64::new(local_cfg_ver),
            last_broadcast_generation: AtomicU64::new(0),
            convergence: Mutex::new(ConvergenceTracker::new()),
            seq: AtomicU64::new(1),
            udp: OnceLock::new(),
            tcp: OnceLock::new(),
            shutdown: AtomicBool::new(false),
            shutdown_notify: tokio::sync::Notify::new(),
            stats: GossipStats::default(),
        });

        // Store initial self circuit snapshot.
        {
            // Best-effort: local snapshot may allocate; do not fail bus creation.
            let snap = cluster_circuit.local_snapshot();
            let mut store = bus.circuit_store.blocking_lock();
            store.insert(
                Arc::<str>::from(snap.node_id.clone()),
                StoredCircuit {
                    ts_ms: now,
                    open_until_ms: snap.open_until_ms,
                },
            );
        }

        Some(bus)
    }

    /// Start sockets and background tasks.
    pub async fn start(self: Arc<Self>) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let cfg = self.runtime.load().gossip.clone();

        let udp = UdpSocket::bind(cfg.bind)
            .await
            .map_err(|e| ArcError::io("gossip udp bind", e))?;
        let tcp = TcpListener::bind(cfg.bind)
            .await
            .map_err(|e| ArcError::io("gossip tcp bind", e))?;

        let udp = Arc::new(udp);
        let tcp = Arc::new(tcp);

        let _ = self.udp.set(udp);
        let _ = self.tcp.set(tcp);

        // Kick self member addr to advertise.
        let now = now_ms();
        let adv = normalize_advertise(self.runtime.load().gossip.advertise);
        self.members
            .set_self_addr(adv, now, self.local_config_version.load(Ordering::Relaxed));

        // Spawn UDP receiver.
        let recv_self = self.clone();
        tokio::spawn(async move {
            recv_self.udp_recv_loop().await;
        });

        // Spawn TCP accept loop.
        let tcp_self = self.clone();
        tokio::spawn(async move {
            tcp_self.tcp_accept_loop().await;
        });

        // Spawn gossip dissemination loop (fast).
        let gossip_self = self.clone();
        tokio::spawn(async move {
            gossip_self.gossip_loop().await;
        });

        // Spawn SWIM probe loop (may await for ping timeouts).
        let swim_self = self.clone();
        tokio::spawn(async move {
            swim_self.swim_loop().await;
        });

        // Join seed peers (best-effort).
        let join_self = self.clone();
        tokio::spawn(async move {
            join_self.join_seed_peers().await;
        });

        Ok(())
    }

    /// Whether the gossip bus is running (sockets bound + tasks spawned).
    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed) && self.udp.get().is_some() && self.tcp.get().is_some()
    }

    /// Whether HTTP push/pull should be kept as fallback.
    #[inline]
    pub fn http_push_fallback(&self) -> bool {
        self.runtime.load().fallback.http_push
    }

    pub fn notify_local_config_applied(&self, generation: u64) {
        if !self.is_running() {
            return;
        }
        self.last_broadcast_generation
            .store(generation, Ordering::Relaxed);

        let raw = self.mgr.current().raw_json.clone();
        let raw_bytes = Arc::new(raw.as_bytes().to_vec());

        // origin is always self for local apply
        let origin = self.node_id.clone();
        {
            if let Ok(mut st) = self.config_state.try_lock() {
                st.version = generation;
                st.origin = origin.clone();
                st.applying = None;
            }
        }

        self.enqueue_rumor(RumorEnvelope {
            id: self.next_id(),
            hop: 0,
            kind: RumorKind::Config(ConfigRumor {
                version: generation,
                raw_json: raw_bytes,
            }),
        });

        // Start convergence measurement for this local generation.
        {
            if let Ok(mut conv) = self.convergence.try_lock() {
                conv.start(generation, now_ms());
            }
        }
    }

    /// Get members view (relative last_seen_ms).
    pub fn members_view(&self) -> Vec<GossipMemberView> {
        let now = now_ms();
        let mut out = Vec::new();

        for m in self.members.snapshot() {
            let last_seen = if m.id.as_ref() == self.node_id.as_ref() {
                0
            } else {
                now.saturating_sub(m.last_seen_ms)
            };

            out.push(GossipMemberView {
                id: m.id.to_string(),
                address: m.addr.to_string(),
                status: m.status.as_str().to_string(),
                config_version: m.config_version,
                last_seen_ms: last_seen,
            });
        }

        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Get gossip bus stats view.
    pub fn stats_view(&self) -> GossipStatsView {
        let (alive, suspect, dead) = self.members.counts();

        let sent = self.stats.messages_sent_total();
        let recv = self.stats.messages_received_total();

        let p99 = {
            match self.convergence.try_lock() {
                Ok(conv) => conv.p99_ms(),
                Err(_) => 0,
            }
        };

        GossipStatsView {
            messages_sent: sent,
            messages_received: recv,
            convergence_time_ms_p99: p99,
            members_alive: alive,
            members_suspect: suspect,
            members_dead: dead,
        }
    }

    /// Join a peer manually (POST /cluster/gossip/join).
    pub async fn join_peer(&self, peer: &str) -> Result<()> {
        if !self.is_running() {
            return Err(ArcError::internal("gossip is not running"));
        }
        let addr: SocketAddr = peer
            .parse()
            .map_err(|_| ArcError::config(format!("invalid peer addr: {peer}")))?;

        // Send join request over UDP (best-effort).
        let meta = self.local_meta();
        let _ = self.send_udp(addr, &WireMsg::Join { meta }).await;

        // Full sync over TCP.
        self.tcp_full_sync(addr).await?;

        Ok(())
    }

    /// Graceful leave: broadcast `dead` and exit.
    pub async fn leave(&self) -> Result<()> {
        if !self.is_running() {
            return Err(ArcError::internal("gossip is not running"));
        }

        let now = now_ms();
        let adv = normalize_advertise(self.runtime.load().gossip.advertise);
        let incarnation = self.local_incarnation.load(Ordering::Relaxed);

        // Mark self dead locally.
        self.members.mark_dead(
            self.node_id.clone(),
            adv,
            incarnation,
            now,
            self.local_config_version.load(Ordering::Relaxed),
            "leave",
        );

        // Broadcast dead rumor to all alive peers (not just fanout) to speed up convergence.
        let rumor = RumorEnvelope {
            id: self.next_id(),
            hop: 0,
            kind: RumorKind::Member(MemberRumor {
                node_id: self.node_id.clone(),
                addr: adv,
                status: MemberStatus::Dead,
                incarnation,
                ts_ms: now,
            }),
        };

        let peers = self.members.alive_peers_except(self.node_id.as_ref());
        for p in peers {
            let meta = self.local_meta();
            let _ = self
                .send_udp(
                    p,
                    &WireMsg::Rumor {
                        meta,
                        rumor: rumor.clone(),
                    },
                )
                .await;
        }

        // Stop loops and exit process after a short delay (best-effort flush).
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();

        tokio::spawn(async move {
            time::sleep(Duration::from_millis(200)).await;
            std::process::exit(0);
        });

        Ok(())
    }

    async fn join_seed_peers(self: Arc<Self>) {
        let peers = self.runtime.load().gossip.peers.clone();
        for p in peers {
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }
            if p == normalize_advertise(self.runtime.load().gossip.advertise) {
                continue;
            }
            if let Err(e) = self.join_peer(&p.to_string()).await {
                eprintln!("gossip join seed {p} failed: {e}");
            }
        }
    }

    async fn udp_recv_loop(self: Arc<Self>) {
        let Some(sock) = self.udp.get().cloned() else {
            return;
        };

        let mut buf = vec![0u8; 65_535];
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }

            let recv = tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    return;
                }
                v = sock.recv_from(&mut buf) => v,
            };

            let (n, src) = match recv {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("gossip udp recv error: {e}");
                    continue;
                }
            };

            let pkt = &buf[..n];
            let msg = match WireMsg::decode(pkt) {
                Ok(v) => v,
                Err(_) => {
                    self.stats
                        .dropped_decode_error
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            let now = now_ms();
            self.stats.inc_received(&msg);

            // Touch sender member (for all message types).
            let sender_meta = msg_meta(&msg);
            if let Some(meta) = sender_meta {
                self.touch_member(&meta, src, now);
            }

            // Handle message (may be fragment -> reassemble -> inner msg).
            if let Err(e) = self.handle_msg(msg, src, now).await {
                // errors are best-effort in gossip layer; log and continue
                eprintln!("gossip handle msg error: {e}");
            }
        }
    }

    async fn handle_msg(&self, msg: WireMsg, src: SocketAddr, now: u64) -> Result<()> {
        let mut current = msg;
        loop {
            match current {
                WireMsg::Ping { meta: _, probe } => {
                    let meta = self.local_meta();
                    let ack = WireMsg::Ack {
                        meta,
                        probe,
                        target: None,
                    };
                    let _ = self.send_udp(src, &ack).await;
                }
                WireMsg::Ack {
                    meta: ack_sender,
                    probe,
                    target,
                } => {
                    if probe.node_id.as_ref() != self.node_id.as_ref() {
                        let mut fw = self.relay_forwards.lock().await;
                        if let Some(entry) = fw.remove(&probe) {
                            if now <= entry.expires_ms {
                                let meta = self.local_meta();
                                let fwd = WireMsg::Ack {
                                    meta,
                                    probe: probe.clone(),
                                    target: Some(ack_sender.clone()),
                                };
                                let _ = self.send_udp(entry.origin_addr, &fwd).await;
                            }
                        }
                    }

                    if probe.node_id.as_ref() == self.node_id.as_ref() {
                        let mut pending = self.pending_pings.lock().await;
                        if let Some(tx) = pending.remove(&probe.seq) {
                            let _ = tx.send(());
                        }
                    }

                    if let Some(t) = target {
                        self.touch_member(&t, src, now);
                    }
                }
                WireMsg::PingReq {
                    meta: _,
                    probe,
                    target_id: _,
                    target_addr,
                    origin_addr,
                } => {
                    let expires_ms = now.saturating_add(self.ping_timeout().as_millis() as u64);
                    {
                        let mut fw = self.relay_forwards.lock().await;
                        fw.insert(
                            probe.clone(),
                            RelayForward {
                                origin_addr,
                                expires_ms,
                            },
                        );
                    }

                    let meta = self.local_meta();
                    let ping = WireMsg::Ping {
                        meta,
                        probe: probe.clone(),
                    };
                    let _ = self.send_udp(target_addr, &ping).await;
                }
                WireMsg::Join { meta } => {
                    let ack = WireMsg::JoinAck {
                        meta: self.local_meta(),
                    };
                    let _ = self.send_udp(src, &ack).await;

                    let rumor = RumorEnvelope {
                        id: self.next_id(),
                        hop: 0,
                        kind: RumorKind::Member(MemberRumor {
                            node_id: meta.node_id.clone(),
                            addr: normalize_advertise(meta.addr),
                            status: MemberStatus::Alive,
                            incarnation: meta.incarnation,
                            ts_ms: now,
                        }),
                    };
                    self.enqueue_rumor(rumor);
                }
                WireMsg::JoinAck { meta: _ } => {}
                WireMsg::Rumor { meta: _, rumor } => {
                    self.handle_rumor(rumor, now).await?;
                }
                WireMsg::Fragment {
                    meta: _,
                    id,
                    idx,
                    total,
                    data,
                } => {
                    if let Some(assembled) = self.handle_fragment(id, idx, total, data, now).await?
                    {
                        let inner = match WireMsg::decode(&assembled) {
                            Ok(v) => v,
                            Err(_) => {
                                self.stats
                                    .dropped_decode_error
                                    .fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        };
                        self.stats.inc_received(&inner);
                        if let Some(meta) = msg_meta(&inner) {
                            self.touch_member(&meta, src, now);
                        }
                        current = inner;
                        continue;
                    }
                }
            }
            break;
        }
        Ok(())
    }

    async fn handle_fragment(
        &self,
        id: Id,
        idx: u16,
        total: u16,
        data: Vec<u8>,
        now: u64,
    ) -> Result<Option<Vec<u8>>> {
        if total == 0 {
            return Ok(None);
        }
        if usize::from(total) > 4096 {
            // hard cap
            self.stats.dropped_too_old.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        let mut table = self.reassembly.lock().await;
        let entry = table.entry(id.clone()).or_insert_with(|| ReassemblyEntry {
            created_ms: now,
            total,
            parts: vec![None; usize::from(total)],
            received: 0,
        });

        if entry.total != total {
            // mismatch => drop
            table.remove(&id);
            self.stats
                .dropped_decode_error
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        let pos = usize::from(idx);
        if pos >= entry.parts.len() {
            self.stats
                .dropped_decode_error
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        if entry.parts[pos].is_none() {
            entry.parts[pos] = Some(data);
            entry.received = entry.received.saturating_add(1);
        }

        if entry.received as usize == entry.parts.len() {
            let mut out = Vec::new();
            for p in entry.parts.iter() {
                let Some(chunk) = p.as_ref() else {
                    table.remove(&id);
                    return Ok(None);
                };
                out.extend_from_slice(chunk);
            }
            table.remove(&id);
            return Ok(Some(out));
        }

        Ok(None)
    }

    async fn handle_rumor(&self, rumor: RumorEnvelope, now: u64) -> Result<()> {
        // Dedup
        {
            let mut seen = self.seen.lock().await;
            if let Some(ts) = seen.get(&rumor.id).copied() {
                // duplicate
                let _ = ts;
                self.stats.dropped_duplicate.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            seen.insert(rumor.id.clone(), now);
        }

        // Hop-limit
        let n = self.members.len();
        let hop_limit = hop_limit(n);
        if rumor.hop > hop_limit {
            self.stats.dropped_too_old.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Merge & apply
        let updated = match &rumor.kind {
            RumorKind::Member(r) => self.merge_member_rumor(r, now),
            RumorKind::Config(r) => {
                self.merge_config_rumor(rumor.id.node_id.clone(), r.clone(), now)
                    .await?
            }
            RumorKind::Circuit(r) => {
                self.merge_circuit_rumor(rumor.id.node_id.clone(), r, now)
                    .await
            }
            RumorKind::GCounter(r) => {
                self.merge_gcounter_rumor(rumor.id.node_id.clone(), r, now)
                    .await
            }
            RumorKind::XdpBlock(r) => self.merge_xdp_block_rumor(r, now).await,
        };

        // Forward only if updated and within hop limit.
        if updated {
            let next_hop = rumor.hop.saturating_add(1);
            if next_hop <= hop_limit {
                let fwd = RumorEnvelope {
                    id: rumor.id,
                    hop: next_hop,
                    kind: rumor.kind,
                };
                self.enqueue_rumor(fwd);
            }
        }

        Ok(())
    }

    fn merge_member_rumor(&self, r: &MemberRumor, now: u64) -> bool {
        // Never allow remote member rumors to mutate local self status.
        if r.node_id.as_ref() == self.node_id.as_ref() {
            return false;
        }
        let config_ver = 0u64; // member rumor doesn't carry config; keep existing.
        self.members.merge_remote_status(
            r.node_id.clone(),
            normalize_advertise(r.addr),
            r.status,
            r.incarnation,
            r.ts_ms,
            now,
            config_ver,
        )
    }

    async fn merge_config_rumor(
        &self,
        origin: Arc<str>,
        r: ConfigRumor,
        _now: u64,
    ) -> Result<bool> {
        // Comparator: (version, origin_node_id)
        let should_apply = {
            let mut st = self.config_state.lock().await;

            // if already applying same or newer, skip
            if let Some((v, o)) = st.applying.as_ref() {
                if version_cmp(*v, o.as_ref(), r.version, origin.as_ref()) >= 0 {
                    return Ok(false);
                }
            }

            let cmp = version_cmp(st.version, st.origin.as_ref(), r.version, origin.as_ref());
            if cmp >= 0 {
                return Ok(false);
            }

            st.applying = Some((r.version, origin.clone()));
            true
        };

        if !should_apply {
            return Ok(false);
        }

        // Suppress re-broadcast of the resulting local generation.
        self.suppress_config_broadcast
            .store(r.version, Ordering::Relaxed);

        let raw_str = match String::from_utf8(r.raw_json.as_ref().clone()) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("gossip config apply failed: raw_json not utf-8");
                self.clear_config_applying(r.version).await;
                return Ok(true);
            }
        };

        let raw_for_compile = raw_str.clone();
        let compiled =
            tokio::task::spawn_blocking(move || ConfigManager::compile_raw_json(&raw_for_compile))
                .await;

        let compiled = match compiled {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                eprintln!("gossip config compile failed: {e}");
                self.clear_config_applying(r.version).await;
                return Ok(true);
            }
            Err(_) => {
                eprintln!("gossip config compile task panicked");
                self.clear_config_applying(r.version).await;
                return Ok(true);
            }
        };

        let gen = compiled.generation;
        if gen != r.version {
            eprintln!(
                "gossip config generation mismatch: expected {} compiled {}",
                r.version, gen
            );
        }

        let applied = self.mgr.apply_compiled(compiled);
        self.finish_config_apply(applied, origin).await;

        // Forward immediately (we accepted a newer state).
        Ok(true)
    }

    async fn clear_config_applying(&self, expect_ver: u64) {
        let mut st = self.config_state.lock().await;
        if let Some((v, _)) = st.applying.as_ref() {
            if *v == expect_ver {
                st.applying = None;
            }
        }
    }

    async fn finish_config_apply(&self, applied_gen: u64, origin: Arc<str>) {
        self.local_config_version
            .store(applied_gen, Ordering::Relaxed);

        let mut st = self.config_state.lock().await;
        st.version = applied_gen;
        st.origin = origin;
        st.applying = None;
    }

    async fn merge_circuit_rumor(&self, node_id: Arc<str>, r: &CircuitRumor, now: u64) -> bool {
        if node_id.as_ref() == self.node_id.as_ref() {
            return false;
        }

        // LWW per node.
        let mut store = self.circuit_store.lock().await;
        let update = match store.get(&node_id) {
            Some(cur) => {
                if r.ts_ms > cur.ts_ms {
                    true
                } else if r.ts_ms < cur.ts_ms {
                    false
                } else {
                    // tie-break by node_id lexicographic (deterministic)
                    node_id.as_ref() > node_id.as_ref()
                }
            }
            None => true,
        };

        if !update {
            return false;
        }

        store.insert(
            node_id.clone(),
            StoredCircuit {
                ts_ms: r.ts_ms,
                open_until_ms: r.open_until_ms.clone(),
            },
        );

        // Apply to cluster circuit view for dashboard/reference.
        let snap = NodeCircuitSnapshot {
            node_id: node_id.to_string(),
            ts_ms: r.ts_ms.max(now),
            open_until_ms: r.open_until_ms.clone(),
        };
        self.cluster_circuit.ingest_peer_snapshot(snap);
        true
    }

    async fn merge_gcounter_rumor(&self, origin: Arc<str>, r: &GCounterRumor, _now: u64) -> bool {
        let mut store = self.gcounter_store.lock().await;
        let per_key = store
            .entry(r.key.as_ref().to_string())
            .or_insert_with(HashMap::new);
        let cur = per_key.get(&origin).copied().unwrap_or(0);
        if r.value > cur {
            per_key.insert(origin, r.value);
            return true;
        }
        false
    }

    async fn merge_xdp_block_rumor(&self, r: &XdpBlockRumor, now_ms_val: u64) -> bool {
        let Some(xdp) = global_xdp_manager() else {
            return false;
        };
        let bl = xdp.blacklist().await;
        match r.action {
            XdpBlockAction::Add => {
                let ttl_ms = if r.ttl_ms == 0 {
                    0
                } else {
                    let elapsed = now_ms_val.saturating_sub(r.observed_at_ms);
                    if elapsed >= r.ttl_ms {
                        return false;
                    }
                    r.ttl_ms.saturating_sub(elapsed).max(1)
                };
                let ttl = Duration::from_millis(ttl_ms);
                match bl.add(r.ip, ttl, r.reason) {
                    Ok(_) => {
                        let mut sup = self.suppress_xdp_broadcast.lock().await;
                        sup.insert(ip_digest(r.ip), now_ms_val.saturating_add(5_000));
                        true
                    }
                    Err(e) => {
                        eprintln!("gossip xdp add apply failed: {e}");
                        false
                    }
                }
            }
            XdpBlockAction::Remove => match bl.remove(r.ip) {
                Ok(changed) => {
                    if changed {
                        let mut sup = self.suppress_xdp_broadcast.lock().await;
                        sup.insert(ip_digest(r.ip), now_ms_val.saturating_add(5_000));
                    }
                    changed
                }
                Err(e) => {
                    eprintln!("gossip xdp remove apply failed: {e}");
                    false
                }
            },
        }
    }

    async fn tcp_accept_loop(self: Arc<Self>) {
        let Some(listener) = self.tcp.get().cloned() else {
            return;
        };

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }

            let accept = tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    return;
                }
                v = listener.accept() => v,
            };

            let (stream, peer) = match accept {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("gossip tcp accept error: {e}");
                    continue;
                }
            };

            let h = self.clone();
            tokio::spawn(async move {
                if let Err(e) = h.handle_tcp_sync(stream, peer).await {
                    eprintln!("gossip tcp sync error ({peer}): {e}");
                }
            });
        }
    }

    async fn handle_tcp_sync(&self, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let req_bytes = read_frame(&mut stream, 32 * 1024 * 1024).await?;
        let req = SyncRequest::decode(&req_bytes)
            .map_err(|_| ArcError::proto("sync request decode failed"))?;

        // touch member from request meta
        let now = now_ms();
        self.touch_member(&req.meta, peer, now);

        let resp = self.build_sync_response(now).await;
        let bytes = resp.encode();

        write_frame(&mut stream, &bytes).await?;
        self.stats.sent_sync.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn tcp_full_sync(&self, peer: SocketAddr) -> Result<()> {
        let timeout = Duration::from_millis(1500);
        let mut stream = match time::timeout(timeout, TcpStream::connect(peer)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(ArcError::io("gossip tcp connect", e)),
            Err(_) => {
                return Err(ArcError::io(
                    "gossip tcp connect",
                    std::io::Error::other("timeout"),
                ))
            }
        };

        let req = SyncRequest {
            meta: self.local_meta(),
        };
        write_frame(&mut stream, &req.encode()).await?;
        self.stats.sent_sync.fetch_add(1, Ordering::Relaxed);

        let resp_bytes = read_frame(&mut stream, 64 * 1024 * 1024).await?;
        let resp = SyncResponse::decode(&resp_bytes)
            .map_err(|_| ArcError::proto("sync response decode failed"))?;

        self.apply_sync_response(resp).await?;
        Ok(())
    }

    async fn build_sync_response(&self, _now: u64) -> SyncResponse {
        // members
        let mems = self.members.snapshot();
        let mut members = Vec::with_capacity(mems.len());
        for m in mems {
            members.push(SyncMember {
                node_id: m.id.clone(),
                addr: m.addr,
                status: m.status,
                incarnation: m.incarnation,
                last_seen_ms: m.last_seen_ms,
                config_version: m.config_version,
            });
        }

        // config
        let raw = self.mgr.current().raw_json.clone();
        let raw_json = Arc::new(raw.as_bytes().to_vec());
        let (version, origin) = {
            let st = self.config_state.lock().await;
            (st.version, st.origin.clone())
        };

        let config = SyncConfig {
            version,
            origin,
            raw_json,
        };

        // circuits
        let mut circuits = Vec::new();
        {
            let store = self.circuit_store.lock().await;
            circuits.reserve(store.len());
            for (nid, c) in store.iter() {
                circuits.push(SyncCircuit {
                    node_id: nid.clone(),
                    ts_ms: c.ts_ms,
                    open_until_ms: c.open_until_ms.clone(),
                });
            }
        }

        // gcounters
        let mut gcounters = Vec::new();
        {
            let store = self.gcounter_store.lock().await;
            gcounters.reserve(store.len());
            for (k, per) in store.iter() {
                gcounters.push(SyncGCounter {
                    key: k.clone(),
                    per_node: per.clone(),
                });
            }
        }

        // xdp blocks (best-effort)
        let xdp_blocks = self.snapshot_local_xdp_blocks().await;

        SyncResponse {
            meta: self.local_meta(),
            members,
            config,
            circuits,
            gcounters,
            xdp_blocks,
        }
    }

    async fn apply_sync_response(&self, resp: SyncResponse) -> Result<()> {
        let now = now_ms();

        // members
        for m in resp.members.iter() {
            if m.node_id.as_ref() == self.node_id.as_ref() {
                continue;
            }
            self.members.merge_remote_status(
                m.node_id.clone(),
                normalize_advertise(m.addr),
                m.status,
                m.incarnation,
                m.last_seen_ms,
                now,
                m.config_version,
            );
        }

        // config: apply if newer (version, origin)
        let should_apply = {
            let st = self.config_state.lock().await;
            version_cmp(
                st.version,
                st.origin.as_ref(),
                resp.config.version,
                resp.config.origin.as_ref(),
            ) < 0
        };
        if should_apply {
            // suppress re-broadcast
            self.suppress_config_broadcast
                .store(resp.config.version, Ordering::Relaxed);

            let raw_str = String::from_utf8(resp.config.raw_json.as_ref().clone())
                .map_err(|_| ArcError::proto("sync config raw_json not utf-8"))?;
            let raw_for_compile = raw_str.clone();
            let compiled = tokio::task::spawn_blocking(move || {
                ConfigManager::compile_raw_json(&raw_for_compile)
            })
            .await
            .map_err(|_| ArcError::internal("sync compile task panicked"))??;

            let gen = compiled.generation;
            let applied = self.mgr.apply_compiled(compiled);
            let _ = gen;
            self.finish_config_apply(applied, resp.config.origin.clone())
                .await;
        }

        // circuits
        for c in resp.circuits.into_iter() {
            if c.node_id.as_ref() == self.node_id.as_ref() {
                continue;
            }
            let rumor = CircuitRumor {
                ts_ms: c.ts_ms,
                open_until_ms: c.open_until_ms,
            };
            let _ = self.merge_circuit_rumor(c.node_id, &rumor, now).await;
        }

        // gcounters
        {
            let mut store = self.gcounter_store.lock().await;
            for g in resp.gcounters.into_iter() {
                let entry = store.entry(g.key).or_insert_with(HashMap::new);
                for (nid, val) in g.per_node.into_iter() {
                    let cur = entry.get(&nid).copied().unwrap_or(0);
                    if val > cur {
                        entry.insert(nid, val);
                    }
                }
            }
        }

        // xdp blocks
        for b in resp.xdp_blocks.into_iter() {
            let ttl_ms = if b.ttl_ms == 0 {
                0
            } else {
                let elapsed = now.saturating_sub(b.observed_at_ms);
                if elapsed >= b.ttl_ms {
                    continue;
                }
                b.ttl_ms.saturating_sub(elapsed).max(1)
            };
            let Some(xdp) = global_xdp_manager() else {
                break;
            };
            let bl = xdp.blacklist().await;
            match bl.add(b.ip, Duration::from_millis(ttl_ms), b.reason) {
                Ok(_) => {
                    let mut sup = self.suppress_xdp_broadcast.lock().await;
                    sup.insert(ip_digest(b.ip), now.saturating_add(5_000));
                }
                Err(e) => {
                    eprintln!("gossip sync xdp apply failed: {e}");
                }
            }
        }

        Ok(())
    }

    async fn snapshot_local_xdp_blocks(&self) -> Vec<SyncXdpBlock> {
        let Some(xdp) = global_xdp_manager() else {
            return Vec::new();
        };
        let bl = xdp.blacklist().await;
        let entries = match bl.list(4096) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("gossip sync snapshot xdp list failed: {e}");
                return Vec::new();
            }
        };
        let mut out = Vec::with_capacity(entries.len());
        for (ip, ent) in entries.into_iter() {
            out.push(SyncXdpBlock {
                ip,
                reason: ent.reason,
                ttl_ms: ent.ttl_ns / 1_000_000,
                observed_at_ms: ent.blocked_at_ns / 1_000_000,
            });
        }
        out
    }

    async fn gossip_loop(self: Arc<Self>) {
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }

            let interval = self.runtime.load().gossip.interval;
            let started = Instant::now();

            self.gossip_round().await;

            let elapsed = started.elapsed();
            self.stats.last_round_ns.store(
                elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );

            if elapsed < interval {
                tokio::select! {
                    _ = self.shutdown_notify.notified() => { return; }
                    _ = time::sleep(interval - elapsed) => {}
                }
            } else {
                tokio::task::yield_now().await;
            }
        }
    }

    async fn gossip_round(&self) {
        let now = now_ms();

        // Refresh runtime config if the underlying Arc config generation changed.
        self.refresh_runtime_config_if_needed(now).await;

        // Config version propagation (local changes)
        self.detect_local_config_change(now).await;

        // Delta: circuit state (only when open_until map changed)
        self.broadcast_circuit_if_changed(now).await;

        // Delta: GCounter local changes (best-effort; not wired to dataplane in this patch)
        self.broadcast_gcounter_if_changed(now).await;

        // Delta: XDP blacklist changes (cross-node kernel blacklist sync).
        self.broadcast_xdp_blacklist_if_changed(now).await;

        // Member timers: suspect -> dead -> remove
        self.advance_member_timers(now);

        // Cleanup tables
        self.gc_tables(now).await;

        // Disseminate outgoing rumors
        self.disseminate(now).await;

        // Convergence check (approx)
        self.check_convergence(now).await;
    }

    async fn refresh_runtime_config_if_needed(&self, now: u64) {
        let cur_gen = self.mgr.current_generation();
        let prev = self.last_observed_generation.load(Ordering::Relaxed);
        if cur_gen == prev {
            return;
        }
        self.last_observed_generation
            .store(cur_gen, Ordering::Relaxed);
        self.local_config_version.store(cur_gen, Ordering::Relaxed);

        let raw = self.mgr.current().raw_json.clone();
        let new_rt = GossipRuntimeConfig::parse_from_raw_json(raw.as_ref());

        // bind address is immutable at runtime (requires socket rebind); we keep old bind if changed.
        let old = self.runtime.load();
        if new_rt.gossip.bind != old.gossip.bind {
            eprintln!(
                "gossip config change ignored (bind requires restart): old={} new={}",
                old.gossip.bind, new_rt.gossip.bind
            );
        }

        // Keep node-local socket identity stable across distributed config sync.
        // Remote configs may carry leader-specific advertise/bind values; applying them
        // on followers would poison membership addresses and break rumor routing.
        let adv = normalize_advertise(old.gossip.advertise);
        self.members
            .set_self_addr(adv, now, self.local_config_version.load(Ordering::Relaxed));

        // apply new runtime, but preserve node-local bind/advertise from boot/runtime
        let mut merged = new_rt;
        merged.gossip.bind = old.gossip.bind;
        merged.gossip.advertise = old.gossip.advertise;
        self.runtime.store(Arc::new(merged));
    }

    async fn detect_local_config_change(&self, now: u64) {
        let cur_gen = self.mgr.current_generation();
        let last_broadcast = self.last_broadcast_generation.load(Ordering::Relaxed);
        if cur_gen == last_broadcast {
            return;
        }

        // If this gen came from gossip apply, suppress re-broadcast.
        let suppress = self.suppress_config_broadcast.load(Ordering::Relaxed);
        if suppress == cur_gen && suppress != 0 {
            self.suppress_config_broadcast.store(0, Ordering::Relaxed);
            self.last_broadcast_generation
                .store(cur_gen, Ordering::Relaxed);
            return;
        }

        // Broadcast local config change.
        self.last_broadcast_generation
            .store(cur_gen, Ordering::Relaxed);

        let raw = self.mgr.current().raw_json.clone();
        let raw_bytes = Arc::new(raw.as_bytes().to_vec());

        {
            let mut st = self.config_state.lock().await;
            st.version = cur_gen;
            st.origin = self.node_id.clone();
            st.applying = None;
        }

        let rumor = RumorEnvelope {
            id: self.next_id(),
            hop: 0,
            kind: RumorKind::Config(ConfigRumor {
                version: cur_gen,
                raw_json: raw_bytes,
            }),
        };
        self.enqueue_rumor(rumor);

        let mut conv = self.convergence.lock().await;
        conv.start(cur_gen, now);
    }

    async fn broadcast_circuit_if_changed(&self, now: u64) {
        if !self.cluster_circuit.enabled() {
            return;
        }

        let snap = self.cluster_circuit.local_snapshot();
        let open = snap.open_until_ms;

        // Compare with last broadcasted map; only gossip when map changes.
        let mut last = self.last_circuit_open_until.lock().await;
        if *last == open {
            return;
        }
        *last = open.clone();

        // Store local snapshot (for TCP sync).
        {
            let mut store = self.circuit_store.lock().await;
            store.insert(
                self.node_id.clone(),
                StoredCircuit {
                    ts_ms: now,
                    open_until_ms: open.clone(),
                },
            );
        }

        let rumor = RumorEnvelope {
            id: self.next_id(),
            hop: 0,
            kind: RumorKind::Circuit(CircuitRumor {
                ts_ms: now,
                open_until_ms: open,
            }),
        };
        self.enqueue_rumor(rumor);
    }

    async fn broadcast_gcounter_if_changed(&self, now: u64) {
        // This patch provides the CRDT + dissemination path; dataplane wiring is a downstream task.
        let _ = now;
        let _ = self;
        // No-op: without dataplane integration there is nothing to broadcast.
    }

    async fn broadcast_xdp_blacklist_if_changed(&self, now: u64) {
        // Scan at 1Hz to avoid expensive full-map polling every gossip interval.
        let prev_scan = self.last_xdp_scan_ms.load(Ordering::Relaxed);
        if now.saturating_sub(prev_scan) < 1_000 {
            return;
        }
        self.last_xdp_scan_ms.store(now, Ordering::Relaxed);

        let Some(xdp) = global_xdp_manager() else {
            return;
        };
        let bl = xdp.blacklist().await;
        let entries = match bl.list(4096) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("gossip xdp scan failed: {e}");
                return;
            }
        };

        let mut cur: HashMap<IpDigest, XdpBlockSnapshot> = HashMap::with_capacity(entries.len());
        for (ip, ent) in entries.iter() {
            let key = ip_digest(*ip);
            let snap = XdpBlockSnapshot {
                reason: block_reason_code(ent.reason),
                ttl_ms: ent.ttl_ns / 1_000_000,
                observed_at_ms: ent.blocked_at_ns / 1_000_000,
            };
            cur.insert(key, snap);
        }

        let mut last = self.last_xdp_blacklist.lock().await;
        let mut suppress = self.suppress_xdp_broadcast.lock().await;
        suppress.retain(|_, until| *until > now);

        // New/changed entries -> ADD rumor.
        for (ip, ent) in entries.iter() {
            let key = ip_digest(*ip);
            let snap = XdpBlockSnapshot {
                reason: block_reason_code(ent.reason),
                ttl_ms: ent.ttl_ns / 1_000_000,
                observed_at_ms: ent.blocked_at_ns / 1_000_000,
            };
            let changed = match last.get(&key) {
                Some(prev) => prev != &snap,
                None => true,
            };
            if changed {
                if suppress.get(&key).copied().unwrap_or(0) > now {
                    continue;
                }
                self.enqueue_rumor(RumorEnvelope {
                    id: self.next_id(),
                    hop: 0,
                    kind: RumorKind::XdpBlock(XdpBlockRumor {
                        ip: *ip,
                        action: XdpBlockAction::Add,
                        reason: ent.reason,
                        ttl_ms: snap.ttl_ms,
                        observed_at_ms: snap.observed_at_ms,
                    }),
                });
            }
        }

        // Removed entries -> REMOVE rumor.
        for key in last.keys() {
            if !cur.contains_key(key) {
                if suppress.get(key).copied().unwrap_or(0) > now {
                    continue;
                }
                self.enqueue_rumor(RumorEnvelope {
                    id: self.next_id(),
                    hop: 0,
                    kind: RumorKind::XdpBlock(XdpBlockRumor {
                        ip: ip_from_digest(*key),
                        action: XdpBlockAction::Remove,
                        reason: arc_xdp_common::BlockReason::Manual,
                        ttl_ms: 0,
                        observed_at_ms: now,
                    }),
                });
            }
        }

        *last = cur;
    }

    fn advance_member_timers(&self, now: u64) {
        let cfg = self.runtime.load().gossip.clone();
        let suspicion_ms = cfg.suspicion_timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        let dead_ms = cfg.dead_timeout.as_millis().min(u128::from(u64::MAX)) as u64;

        let members = self.members.snapshot();
        for m in members {
            if m.id.as_ref() == self.node_id.as_ref() {
                continue;
            }

            match m.status {
                MemberStatus::Suspect => {
                    if now.saturating_sub(m.status_since_ms) > suspicion_ms {
                        self.members.mark_dead(
                            m.id.clone(),
                            m.addr,
                            m.incarnation,
                            now,
                            m.config_version,
                            "suspect_timeout",
                        );

                        let rumor = RumorEnvelope {
                            id: self.next_id(),
                            hop: 0,
                            kind: RumorKind::Member(MemberRumor {
                                node_id: m.id.clone(),
                                addr: m.addr,
                                status: MemberStatus::Dead,
                                incarnation: m.incarnation,
                                ts_ms: now,
                            }),
                        };
                        self.enqueue_rumor(rumor);
                    }
                }
                MemberStatus::Dead => {
                    if now.saturating_sub(m.status_since_ms) > dead_ms {
                        self.members.remove(&m.id);
                    }
                }
                MemberStatus::Alive => {}
            }
        }
    }

    async fn gc_tables(&self, now: u64) {
        // seen dedup GC
        {
            let mut seen = self.seen.lock().await;
            let ttl = self.seen_ttl.as_millis().min(u128::from(u64::MAX)) as u64;
            seen.retain(|_, ts| now.saturating_sub(*ts) <= ttl);
        }

        // reassembly GC
        {
            let mut table = self.reassembly.lock().await;
            table.retain(|_, e| now.saturating_sub(e.created_ms) <= 5_000);
        }

        // relay forwards GC
        {
            let mut fw = self.relay_forwards.lock().await;
            fw.retain(|_, e| now <= e.expires_ms);
        }
    }

    async fn disseminate(&self, now: u64) {
        let cfg = self.runtime.load().gossip.clone();
        let fanout = cfg.fanout.max(1);

        let peers = self
            .members
            .sample_alive_peers_except(self.node_id.as_ref(), fanout)
            .await;
        if peers.is_empty() {
            return;
        }

        let n = self.members.len();
        let retransmit_rounds = retransmit_rounds(cfg.retransmit_multiplier, n);
        let max_take = 128usize;

        // Take a snapshot of rumors to send in this round and decrement their rounds.
        let (to_send, queue_depth) = {
            let mut q = lock_unpoison(&self.outgoing);
            let mut items = Vec::new();
            let mut removed: Vec<Id> = Vec::new();

            for (id, item) in q.items.iter_mut() {
                if items.len() >= max_take {
                    break;
                }
                // ensure at least 1 round
                if item.remaining_rounds == 0 {
                    item.remaining_rounds = retransmit_rounds;
                }
                // clone rumor for sending
                items.push(item.rumor.clone());

                if item.remaining_rounds > 0 {
                    item.remaining_rounds -= 1;
                }
                if item.remaining_rounds == 0 {
                    removed.push(id.clone());
                }
            }

            for rid in removed {
                q.remove_by_id(&rid);
            }

            let depth = q.items.len();
            (items, depth)
        };

        self.stats
            .queue_depth
            .store(queue_depth as u64, Ordering::Relaxed);

        if to_send.is_empty() {
            return;
        }

        // Send each rumor to each peer (fanout).
        for peer in peers {
            for rumor in to_send.iter() {
                let meta = self.local_meta();
                let msg = WireMsg::Rumor {
                    meta,
                    rumor: rumor.clone(),
                };
                let _ = self.send_udp(peer, &msg).await;
            }
        }

        // Update stats for convergence check input.
        let _ = now;
    }

    async fn check_convergence(&self, now: u64) {
        let mut conv = self.convergence.lock().await;
        if let Some(active) = conv.active.as_ref() {
            let target = active.version;

            // We consider convergence when all alive nodes (excluding self) report config_version == target.
            let members = self.members.snapshot();
            for m in members {
                if m.id.as_ref() == self.node_id.as_ref() {
                    continue;
                }
                if m.status != MemberStatus::Alive {
                    continue;
                }
                if m.config_version != target {
                    return;
                }
            }

            // converged
            let dur = now.saturating_sub(active.started_ms);
            conv.record(dur);
            conv.active = None;
        }
    }

    async fn swim_loop(self: Arc<Self>) {
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }

            let interval = self.runtime.load().gossip.interval;
            let started = Instant::now();

            if let Err(e) = self.swim_probe_once().await {
                eprintln!("gossip swim probe error: {e}");
            }

            let elapsed = started.elapsed();
            if elapsed < interval {
                tokio::select! {
                    _ = self.shutdown_notify.notified() => { return; }
                    _ = time::sleep(interval - elapsed) => {}
                }
            } else {
                tokio::task::yield_now().await;
            }
        }
    }

    async fn swim_probe_once(&self) -> Result<()> {
        let now = now_ms();
        let target = self
            .members
            .random_alive_peer_except(self.node_id.as_ref())
            .await;
        let Some(target) = target else {
            return Ok(());
        };

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let probe = Id {
            node_id: self.node_id.clone(),
            seq,
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_pings.lock().await;
            pending.insert(seq, tx);
        }

        // 1) direct ping
        let ping = WireMsg::Ping {
            meta: self.local_meta(),
            probe: probe.clone(),
        };
        let _ = self.send_udp(target.addr, &ping).await;

        let ping_timeout = self.ping_timeout();
        let ok = match time::timeout(ping_timeout, rx).await {
            Ok(Ok(())) => true,
            _ => false,
        };

        if ok {
            return Ok(());
        }

        // 2) ping-req to k relays
        let k = 3usize;
        let relays = self
            .members
            .sample_alive_peers_excluding(&[self.node_id.as_ref(), target.id.as_ref()], k)
            .await;

        for r in relays {
            let req = WireMsg::PingReq {
                meta: self.local_meta(),
                probe: probe.clone(),
                target_id: target.id.clone(),
                target_addr: target.addr,
                origin_addr: normalize_advertise(self.runtime.load().gossip.advertise),
            };
            let _ = self.send_udp(r, &req).await;
        }

        // Wait for forwarded ack (reuse pending slot).
        let (tx2, rx2) = oneshot::channel();
        {
            let mut pending = self.pending_pings.lock().await;
            // if the previous slot is still there (not consumed), replace it.
            pending.insert(seq, tx2);
        }

        let ok2 = match time::timeout(ping_timeout, rx2).await {
            Ok(Ok(())) => true,
            _ => false,
        };

        if ok2 {
            return Ok(());
        }

        // 3) mark suspect
        self.members.mark_suspect(
            target.id.clone(),
            target.addr,
            target.incarnation,
            now,
            target.config_version,
            "ping_timeout",
        );

        let rumor = RumorEnvelope {
            id: self.next_id(),
            hop: 0,
            kind: RumorKind::Member(MemberRumor {
                node_id: target.id,
                addr: target.addr,
                status: MemberStatus::Suspect,
                incarnation: target.incarnation,
                ts_ms: now,
            }),
        };
        self.enqueue_rumor(rumor);

        Ok(())
    }

    fn ping_timeout(&self) -> Duration {
        let interval = self.runtime.load().gossip.interval;
        let half = interval / 2;
        // Clamp to keep probes responsive without busy looping.
        half.clamp(Duration::from_millis(50), Duration::from_millis(500))
    }

    fn local_meta(&self) -> NodeMeta {
        let adv = normalize_advertise(self.runtime.load().gossip.advertise);
        NodeMeta {
            node_id: self.node_id.clone(),
            addr: adv,
            incarnation: self.local_incarnation.load(Ordering::Relaxed),
            config_version: self.local_config_version.load(Ordering::Relaxed),
        }
    }

    fn next_id(&self) -> Id {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        Id {
            node_id: self.node_id.clone(),
            seq,
        }
    }

    fn enqueue_rumor(&self, rumor: RumorEnvelope) {
        if !self.is_running() {
            return;
        }
        let mut q = lock_unpoison(&self.outgoing);
        q.insert(rumor);
        self.stats
            .queue_depth
            .store(q.items.len() as u64, Ordering::Relaxed);
    }

    fn touch_member(&self, meta: &NodeMeta, src: SocketAddr, now: u64) {
        // If suspect about self, increase incarnation and broadcast alive (SWIM self-defense).
        if meta.node_id.as_ref() == self.node_id.as_ref() {
            return;
        }

        let addr = if meta.addr.ip().is_unspecified() {
            src
        } else {
            normalize_advertise(meta.addr)
        };

        self.members.touch(
            meta.node_id.clone(),
            addr,
            meta.incarnation,
            now,
            meta.config_version,
        );
    }

    async fn send_udp(&self, addr: SocketAddr, msg: &WireMsg) -> Result<()> {
        let Some(sock) = self.udp.get().cloned() else {
            return Err(ArcError::internal("gossip udp not started"));
        };

        let max = self.runtime.load().gossip.max_message_size.max(256);
        let bytes = msg.encode();
        if bytes.len() <= max {
            let _ = sock.send_to(&bytes, addr).await;
            self.stats.inc_sent(msg);
            return Ok(());
        }

        // Fragment only supports messages with stable id (Rumor).
        let frag_id = match msg {
            WireMsg::Rumor { rumor, .. } => rumor.id.clone(),
            _ => {
                self.stats.dropped_too_old.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };

        self.send_fragments(sock, addr, msg_meta(msg), frag_id, bytes, max)
            .await?;
        Ok(())
    }

    async fn send_fragments(
        &self,
        sock: Arc<UdpSocket>,
        addr: SocketAddr,
        meta: Option<NodeMeta>,
        id: Id,
        bytes: Vec<u8>,
        max: usize,
    ) -> Result<()> {
        let meta = meta.unwrap_or_else(|| self.local_meta());

        // Compute overhead by encoding empty fragment.
        let overhead = WireMsg::Fragment {
            meta: meta.clone(),
            id: id.clone(),
            idx: 0,
            total: 1,
            data: Vec::new(),
        }
        .encode()
        .len();

        let mut chunk = max.saturating_sub(overhead + 8).max(64);
        if chunk > 4096 {
            chunk = 4096;
        }

        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let take = chunk.min(bytes.len() - i);
            parts.push(bytes[i..i + take].to_vec());
            i += take;
        }

        if parts.len() > usize::from(u16::MAX) {
            return Err(ArcError::proto("gossip message too large to fragment"));
        }

        let total = parts.len() as u16;
        for (idx, data) in parts.into_iter().enumerate() {
            let frag = WireMsg::Fragment {
                meta: meta.clone(),
                id: id.clone(),
                idx: idx as u16,
                total,
                data,
            };
            let enc = frag.encode();

            // Ensure <= max; shrink if needed (rare; mostly due to bin header growth).
            if enc.len() > max {
                return Err(ArcError::proto(
                    "gossip fragment sizing failed; decrease max_message_size or config size",
                ));
            }

            let _ = sock.send_to(&enc, addr).await;
            self.stats.sent_user.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }
}

fn msg_meta(msg: &WireMsg) -> Option<NodeMeta> {
    match msg {
        WireMsg::Ping { meta, .. } => Some(meta.clone()),
        WireMsg::Ack { meta, .. } => Some(meta.clone()),
        WireMsg::PingReq { meta, .. } => Some(meta.clone()),
        WireMsg::Join { meta } => Some(meta.clone()),
        WireMsg::JoinAck { meta } => Some(meta.clone()),
        WireMsg::Rumor { meta, .. } => Some(meta.clone()),
        WireMsg::Fragment { meta, .. } => Some(meta.clone()),
    }
}

fn normalize_advertise(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

#[inline]
fn ip_digest(ip: IpKey) -> IpDigest {
    (ip.addr, ip.prefix_len)
}

#[inline]
fn ip_from_digest(d: IpDigest) -> IpKey {
    IpKey::new(d.0, d.1)
}

#[inline]
fn block_reason_code(r: arc_xdp_common::BlockReason) -> u32 {
    match r {
        arc_xdp_common::BlockReason::Unknown => 0,
        arc_xdp_common::BlockReason::SynFlood => 1,
        arc_xdp_common::BlockReason::AckFlood => 2,
        arc_xdp_common::BlockReason::RstInvalid => 3,
        arc_xdp_common::BlockReason::UdpRateLimit => 4,
        arc_xdp_common::BlockReason::Manual => 5,
    }
}

fn hop_limit(n: usize) -> u8 {
    let n = n.max(1);
    let base = ceil_log2(n);
    let v = base.saturating_add(2);
    u8::try_from(v.min(255)).unwrap_or(255)
}

fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

fn retransmit_rounds(mult: usize, n: usize) -> u32 {
    let base = ceil_log2(n.max(2));
    let rounds = mult.max(1).saturating_mul(base.max(1));
    u32::try_from(rounds.min(1_000)).unwrap_or(1_000)
}

#[inline]
fn lock_unpoison<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

fn version_cmp(a_ver: u64, a_node: &str, b_ver: u64, b_node: &str) -> i32 {
    if a_ver > b_ver {
        return 1;
    }
    if a_ver < b_ver {
        return -1;
    }
    // same version => lexicographic tie-break on node id
    if a_node > b_node {
        1
    } else if a_node < b_node {
        -1
    } else {
        0
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

async fn read_frame(stream: &mut TcpStream, max: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| ArcError::io("gossip tcp read len", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max {
        return Err(ArcError::proto("gossip tcp frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| ArcError::io("gossip tcp read frame", e))?;
    Ok(buf)
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let len =
        u32::try_from(payload.len()).map_err(|_| ArcError::proto("gossip tcp frame overflow"))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| ArcError::io("gossip tcp write len", e))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| ArcError::io("gossip tcp write frame", e))?;
    Ok(())
}

#[derive(Debug)]
struct RelayForward {
    origin_addr: SocketAddr,
    expires_ms: u64,
}

#[derive(Debug)]
struct ReassemblyEntry {
    created_ms: u64,
    total: u16,
    parts: Vec<Option<Vec<u8>>>,
    received: u16,
}

#[derive(Debug, Clone)]
struct StoredCircuit {
    ts_ms: u64,
    open_until_ms: HashMap<String, u64>,
}

type IpDigest = ([u8; 16], u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XdpBlockSnapshot {
    reason: u32,
    ttl_ms: u64,
    observed_at_ms: u64,
}

#[derive(Debug)]
struct ConfigState {
    version: u64,
    origin: Arc<str>,
    applying: Option<(u64, Arc<str>)>,
}

#[derive(Debug)]
struct ConvergenceTracker {
    active: Option<ActiveConvergence>,
    samples: VecDeque<u64>,
    cap: usize,
}

#[derive(Debug)]
struct ActiveConvergence {
    version: u64,
    started_ms: u64,
}

impl ConvergenceTracker {
    fn new() -> Self {
        Self {
            active: None,
            samples: VecDeque::with_capacity(256),
            cap: 256,
        }
    }

    fn start(&mut self, version: u64, started_ms: u64) {
        self.active = Some(ActiveConvergence {
            version,
            started_ms,
        });
    }

    fn record(&mut self, ms: u64) {
        if self.samples.len() >= self.cap {
            self.samples.pop_front();
        }
        self.samples.push_back(ms);
    }

    fn p99_ms(&self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut v: Vec<u64> = self.samples.iter().copied().collect();
        v.sort_unstable();
        let idx = ((v.len().saturating_sub(1)) * 99) / 100;
        v.get(idx).copied().unwrap_or(0)
    }
}

/// Outgoing rumor queue with simple coalescing.
#[derive(Debug)]
struct OutgoingQueue {
    items: HashMap<Id, OutgoingItem>,
    coalesce: HashMap<CoalesceKey, Id>,
}

#[derive(Debug)]
struct OutgoingItem {
    rumor: RumorEnvelope,
    remaining_rounds: u32,
    key: CoalesceKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CoalesceKey {
    Config,
    Member(Arc<str>),
    Circuit(Arc<str>),
    GCounter(Arc<str>),
    XdpBlock(IpDigest),
}

impl OutgoingQueue {
    fn new() -> Self {
        Self {
            items: HashMap::new(),
            coalesce: HashMap::new(),
        }
    }

    fn insert(&mut self, rumor: RumorEnvelope) {
        let key = match &rumor.kind {
            RumorKind::Config(_) => CoalesceKey::Config,
            RumorKind::Member(m) => CoalesceKey::Member(m.node_id.clone()),
            RumorKind::Circuit(_) => CoalesceKey::Circuit(rumor.id.node_id.clone()),
            RumorKind::GCounter(g) => CoalesceKey::GCounter(g.key.clone()),
            RumorKind::XdpBlock(x) => CoalesceKey::XdpBlock(ip_digest(x.ip)),
        };

        if let Some(old) = self.coalesce.get(&key).cloned() {
            self.items.remove(&old);
        }
        self.coalesce.insert(key.clone(), rumor.id.clone());

        self.items.insert(
            rumor.id.clone(),
            OutgoingItem {
                rumor,
                remaining_rounds: 0,
                key,
            },
        );
    }

    fn remove_by_id(&mut self, id: &Id) {
        if let Some(item) = self.items.remove(id) {
            if let Some(cur) = self.coalesce.get(&item.key) {
                if cur == id {
                    self.coalesce.remove(&item.key);
                }
            }
        }
    }
}

/// Member snapshot for internal iteration.
#[derive(Debug, Clone)]
struct MemberSnapshot {
    id: Arc<str>,
    addr: SocketAddr,
    status: MemberStatus,
    incarnation: u64,
    status_since_ms: u64,
    last_seen_ms: u64,
    config_version: u64,
}

/// Lock-free membership list:
/// - Map is stored behind ArcSwap for lock-free reads.
/// - Hot fields are atomics inside `MemberEntry`.
#[derive(Debug)]
struct MemberEntry {
    id: Arc<str>,
    addr: ArcSwap<SocketAddr>,

    status: AtomicU8, // MemberStatus as u8
    incarnation: AtomicU64,

    status_since_ms: AtomicU64,
    last_seen_ms: AtomicU64,

    config_version: AtomicU64,
}

impl MemberEntry {
    fn new(
        id: Arc<str>,
        addr: SocketAddr,
        status: MemberStatus,
        incarnation: u64,
        now: u64,
        config_version: u64,
    ) -> Self {
        Self {
            id,
            addr: ArcSwap::from_pointee(addr),
            status: AtomicU8::new(status as u8),
            incarnation: AtomicU64::new(incarnation),
            status_since_ms: AtomicU64::new(now),
            last_seen_ms: AtomicU64::new(now),
            config_version: AtomicU64::new(config_version),
        }
    }

    fn status(&self) -> MemberStatus {
        match self.status.load(Ordering::Relaxed) {
            0 => MemberStatus::Alive,
            1 => MemberStatus::Suspect,
            _ => MemberStatus::Dead,
        }
    }

    fn snapshot(&self) -> MemberSnapshot {
        MemberSnapshot {
            id: self.id.clone(),
            addr: *self.addr.load().as_ref(),
            status: self.status(),
            incarnation: self.incarnation.load(Ordering::Relaxed),
            status_since_ms: self.status_since_ms.load(Ordering::Relaxed),
            last_seen_ms: self.last_seen_ms.load(Ordering::Relaxed),
            config_version: self.config_version.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct MemberList {
    self_id: Arc<str>,
    map: ArcSwap<HashMap<Arc<str>, Arc<MemberEntry>>>,
}

impl MemberList {
    fn new(self_id: Arc<str>, self_addr: SocketAddr, now: u64, config_version: u64) -> Self {
        let mut m: HashMap<Arc<str>, Arc<MemberEntry>> = HashMap::new();
        m.insert(
            self_id.clone(),
            Arc::new(MemberEntry::new(
                self_id.clone(),
                self_addr,
                MemberStatus::Alive,
                now.max(1),
                now,
                config_version,
            )),
        );
        Self {
            self_id,
            map: ArcSwap::from_pointee(m),
        }
    }

    fn len(&self) -> usize {
        self.map.load().len()
    }

    fn snapshot(&self) -> Vec<MemberSnapshot> {
        let cur = self.map.load();
        cur.values().map(|e| e.snapshot()).collect()
    }

    fn counts(&self) -> (usize, usize, usize) {
        let cur = self.map.load();
        let mut a = 0usize;
        let mut s = 0usize;
        let mut d = 0usize;
        for e in cur.values() {
            match e.status() {
                MemberStatus::Alive => a += 1,
                MemberStatus::Suspect => s += 1,
                MemberStatus::Dead => d += 1,
            }
        }
        (a, s, d)
    }

    fn remove(&self, id: &Arc<str>) {
        if id.as_ref() == self.self_id.as_ref() {
            return;
        }
        loop {
            let cur = self.map.load();
            if !cur.contains_key(id.as_ref()) {
                return;
            }
            let mut next = (**cur).clone();
            next.remove(id.as_ref());
            let prev = self.map.compare_and_swap(&cur, Arc::new(next));
            if Arc::ptr_eq(&prev, &cur) {
                return;
            }
        }
    }

    fn set_self_addr(&self, addr: SocketAddr, now: u64, config_version: u64) {
        self.touch(self.self_id.clone(), addr, now.max(1), now, config_version);
    }

    fn touch(
        &self,
        id: Arc<str>,
        addr: SocketAddr,
        incarnation: u64,
        now: u64,
        config_version: u64,
    ) {
        // Fast path: existing entry.
        let cur = self.map.load();
        if let Some(e) = cur.get(id.as_ref()) {
            e.addr.store(Arc::new(addr));
            e.last_seen_ms.store(now, Ordering::Relaxed);
            e.config_version.store(config_version, Ordering::Relaxed);

            let old_inc = e.incarnation.load(Ordering::Relaxed);
            if incarnation > old_inc {
                e.incarnation.store(incarnation, Ordering::Relaxed);
            }

            // If we got any message, treat as Alive unless we have a higher-incarnation dead.
            let st = e.status();
            if st == MemberStatus::Suspect {
                e.status.store(MemberStatus::Alive as u8, Ordering::Relaxed);
                e.status_since_ms.store(now, Ordering::Relaxed);
            }
            return;
        }

        // Slow path: insert.
        loop {
            let cur = self.map.load();
            if let Some(e) = cur.get(id.as_ref()) {
                e.addr.store(Arc::new(addr));
                e.last_seen_ms.store(now, Ordering::Relaxed);
                e.config_version.store(config_version, Ordering::Relaxed);
                return;
            }
            let mut next = (**cur).clone();
            next.insert(
                id.clone(),
                Arc::new(MemberEntry::new(
                    id.clone(),
                    addr,
                    MemberStatus::Alive,
                    incarnation.max(1),
                    now,
                    config_version,
                )),
            );
            let prev = self.map.compare_and_swap(&cur, Arc::new(next));
            if Arc::ptr_eq(&prev, &cur) {
                return;
            }
        }
    }

    fn merge_remote_status(
        &self,
        id: Arc<str>,
        addr: SocketAddr,
        status: MemberStatus,
        incarnation: u64,
        ts_ms: u64,
        now: u64,
        config_version: u64,
    ) -> bool {
        let cur = self.map.load();
        if let Some(e) = cur.get(id.as_ref()) {
            // incarnation dominates
            let old_inc = e.incarnation.load(Ordering::Relaxed);
            if incarnation < old_inc {
                return false;
            }

            if incarnation > old_inc {
                e.incarnation.store(incarnation, Ordering::Relaxed);
                e.addr.store(Arc::new(addr));
                e.config_version.store(
                    config_version.max(e.config_version.load(Ordering::Relaxed)),
                    Ordering::Relaxed,
                );

                e.status.store(status as u8, Ordering::Relaxed);
                e.status_since_ms.store(ts_ms.max(now), Ordering::Relaxed);

                if status != MemberStatus::Dead {
                    e.last_seen_ms.store(now, Ordering::Relaxed);
                }
                return true;
            }

            // same incarnation: status rules
            let old_status = e.status();

            // Dead is final unless higher incarnation
            if old_status == MemberStatus::Dead {
                return false;
            }

            // Dead wins
            if status == MemberStatus::Dead && old_status != MemberStatus::Dead {
                e.status.store(MemberStatus::Dead as u8, Ordering::Relaxed);
                e.status_since_ms.store(ts_ms.max(now), Ordering::Relaxed);
                e.addr.store(Arc::new(addr));
                return true;
            }

            // Alive beats Suspect
            if status == MemberStatus::Alive && old_status == MemberStatus::Suspect {
                e.status.store(MemberStatus::Alive as u8, Ordering::Relaxed);
                e.status_since_ms.store(ts_ms.max(now), Ordering::Relaxed);
                e.addr.store(Arc::new(addr));
                e.last_seen_ms.store(now, Ordering::Relaxed);
                return true;
            }

            // Suspect only if currently alive
            if status == MemberStatus::Suspect && old_status == MemberStatus::Alive {
                e.status
                    .store(MemberStatus::Suspect as u8, Ordering::Relaxed);
                e.status_since_ms.store(ts_ms.max(now), Ordering::Relaxed);
                e.addr.store(Arc::new(addr));
                return true;
            }

            false
        } else {
            // Insert as per remote status.
            loop {
                let cur = self.map.load();
                if cur.contains_key(id.as_ref()) {
                    return true;
                }
                let mut next = (**cur).clone();
                next.insert(
                    id.clone(),
                    Arc::new(MemberEntry::new(
                        id.clone(),
                        addr,
                        status,
                        incarnation.max(1),
                        ts_ms.max(now),
                        config_version,
                    )),
                );
                let prev = self.map.compare_and_swap(&cur, Arc::new(next));
                if Arc::ptr_eq(&prev, &cur) {
                    return true;
                }
            }
        }
    }

    fn mark_suspect(
        &self,
        id: Arc<str>,
        addr: SocketAddr,
        incarnation: u64,
        now: u64,
        config_version: u64,
        reason: &str,
    ) {
        if id.as_ref() == self.self_id.as_ref() {
            return;
        }
        let changed = self.merge_remote_status(
            id.clone(),
            addr,
            MemberStatus::Suspect,
            incarnation,
            now,
            now,
            config_version,
        );
        if changed {
            eprintln!(
                "gossip member status change: node_id={} address={} from=alive to=suspect reason={} duration_ms={}",
                id.as_ref(),
                addr,
                reason,
                0
            );
        }
    }

    fn mark_dead(
        &self,
        id: Arc<str>,
        addr: SocketAddr,
        incarnation: u64,
        now: u64,
        config_version: u64,
        reason: &str,
    ) {
        if id.as_ref() == self.self_id.as_ref() && reason != "leave" {
            return;
        }
        let changed = self.merge_remote_status(
            id.clone(),
            addr,
            MemberStatus::Dead,
            incarnation,
            now,
            now,
            config_version,
        );
        if changed {
            eprintln!(
                "gossip member status change: node_id={} address={} from=suspect to=dead reason={} duration_ms={}",
                id.as_ref(),
                addr,
                reason,
                0
            );
        }
    }

    fn alive_peers_except(&self, exclude: &str) -> Vec<SocketAddr> {
        let cur = self.map.load();
        let mut out = Vec::new();
        for e in cur.values() {
            if e.id.as_ref() == exclude {
                continue;
            }
            if e.status() == MemberStatus::Alive {
                out.push(*e.addr.load().as_ref());
            }
        }
        out
    }

    async fn sample_alive_peers_except(&self, exclude: &str, k: usize) -> Vec<SocketAddr> {
        // Reservoir sampling without replacement in one pass.
        let cur = self.map.load();
        let mut res: Vec<SocketAddr> = Vec::with_capacity(k);
        let mut seen = 0u64;

        // Use deterministic seed from pointer address is not needed; we do stable selection by walking.
        // Randomness is provided by upper layer; here we just take the first k if no rng.
        for e in cur.values() {
            if e.id.as_ref() == exclude {
                continue;
            }
            if e.status() != MemberStatus::Alive {
                continue;
            }
            seen += 1;
            if res.len() < k {
                res.push(*e.addr.load().as_ref());
            } else {
                // basic hash mixing for replacement index
                let j = (seen.wrapping_mul(0x9e37_79b9_7f4a_7c15) % (seen)) as usize;
                if j < k {
                    res[j] = *e.addr.load().as_ref();
                }
            }
        }

        res
    }

    async fn sample_alive_peers_excluding(&self, exclude: &[&str], k: usize) -> Vec<SocketAddr> {
        let cur = self.map.load();
        let mut out = Vec::new();
        for e in cur.values() {
            if out.len() >= k {
                break;
            }
            if exclude.iter().any(|x| *x == e.id.as_ref()) {
                continue;
            }
            if e.status() != MemberStatus::Alive {
                continue;
            }
            out.push(*e.addr.load().as_ref());
        }
        out
    }

    async fn random_alive_peer_except(&self, exclude: &str) -> Option<MemberSnapshot> {
        let cur = self.map.load();
        // Reservoir sample 1
        let mut chosen: Option<MemberSnapshot> = None;
        let mut seen = 0u64;
        for e in cur.values() {
            if e.id.as_ref() == exclude {
                continue;
            }
            if e.status() != MemberStatus::Alive {
                continue;
            }
            seen += 1;
            let candidate = MemberSnapshot {
                id: e.id.clone(),
                addr: *e.addr.load().as_ref(),
                status: e.status(),
                incarnation: e.incarnation.load(Ordering::Relaxed),
                status_since_ms: e.status_since_ms.load(Ordering::Relaxed),
                last_seen_ms: e.last_seen_ms.load(Ordering::Relaxed),
                config_version: e.config_version.load(Ordering::Relaxed),
            };
            if seen == 1 {
                chosen = Some(candidate);
            } else {
                // deterministic mixing; not perfect randomness but enough for SWIM peer choice
                let pick =
                    (seen.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x2545_f491_4f6c_dd1d) % seen;
                if pick == 0 {
                    chosen = Some(candidate);
                }
            }
        }
        chosen
    }
}

#[derive(Debug, Default)]
struct GossipStats {
    sent_ping: AtomicU64,
    sent_ping_req: AtomicU64,
    sent_ack: AtomicU64,
    sent_sync: AtomicU64,
    sent_user: AtomicU64,

    recv_ping: AtomicU64,
    recv_ping_req: AtomicU64,
    recv_ack: AtomicU64,
    recv_sync: AtomicU64,
    recv_user: AtomicU64,

    dropped_duplicate: AtomicU64,
    dropped_too_old: AtomicU64,
    dropped_decode_error: AtomicU64,

    queue_depth: AtomicU64,
    last_round_ns: AtomicU64,
}

impl GossipStats {
    fn inc_sent(&self, msg: &WireMsg) {
        match msg {
            WireMsg::Ping { .. } => {
                self.sent_ping.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::PingReq { .. } => {
                self.sent_ping_req.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::Ack { .. } => {
                self.sent_ack.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::Join { .. } | WireMsg::JoinAck { .. } => {
                self.sent_user.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::Rumor { .. } | WireMsg::Fragment { .. } => {
                self.sent_user.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn inc_received(&self, msg: &WireMsg) {
        match msg {
            WireMsg::Ping { .. } => {
                self.recv_ping.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::PingReq { .. } => {
                self.recv_ping_req.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::Ack { .. } => {
                self.recv_ack.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::Join { .. } | WireMsg::JoinAck { .. } => {
                self.recv_user.fetch_add(1, Ordering::Relaxed);
            }
            WireMsg::Rumor { .. } | WireMsg::Fragment { .. } => {
                self.recv_user.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn messages_sent_total(&self) -> u64 {
        self.sent_ping.load(Ordering::Relaxed)
            + self.sent_ping_req.load(Ordering::Relaxed)
            + self.sent_ack.load(Ordering::Relaxed)
            + self.sent_sync.load(Ordering::Relaxed)
            + self.sent_user.load(Ordering::Relaxed)
    }

    fn messages_received_total(&self) -> u64 {
        self.recv_ping.load(Ordering::Relaxed)
            + self.recv_ping_req.load(Ordering::Relaxed)
            + self.recv_ack.load(Ordering::Relaxed)
            + self.recv_sync.load(Ordering::Relaxed)
            + self.recv_user.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_circuit::{ClusterCircuit, ClusterCircuitConfig};
    use tokio::time::{timeout, Duration as TokioDuration};

    fn node_id(v: &str) -> Arc<str> {
        Arc::<str>::from(v)
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn status_of(list: &MemberList, id: &str) -> Option<MemberStatus> {
        let cur = list.map.load();
        cur.get(id).map(|e| e.status())
    }

    fn meta(id: &str, address: SocketAddr, incarnation: u64, config_version: u64) -> NodeMeta {
        NodeMeta {
            node_id: node_id(id),
            addr: address,
            incarnation,
            config_version,
        }
    }

    fn member_rumor(origin: &str, seq: u64, target: &str, port: u16) -> RumorEnvelope {
        RumorEnvelope {
            id: Id {
                node_id: node_id(origin),
                seq,
            },
            hop: 0,
            kind: RumorKind::Member(MemberRumor {
                node_id: node_id(target),
                addr: addr(port),
                status: MemberStatus::Alive,
                incarnation: 1,
                ts_ms: 1,
            }),
        }
    }

    fn config_rumor(origin: &str, seq: u64, version: u64) -> RumorEnvelope {
        RumorEnvelope {
            id: Id {
                node_id: node_id(origin),
                seq,
            },
            hop: 0,
            kind: RumorKind::Config(ConfigRumor {
                version,
                raw_json: Arc::new(br#"{"k":"v"}"#.to_vec()),
            }),
        }
    }

    fn test_config_json(local_node: &str, upstream_port: u16, route_path: &str) -> String {
        format!(
            r#"{{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {{
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  }},
  "buffers": {{ "buf_size": 8192, "buf_count": 64 }},
  "timeouts_ms": {{
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  }},
  "upstreams": [
    {{ "name": "u", "addr": "127.0.0.1:{upstream_port}", "keepalive": 8, "idle_ttl_ms": 1000 }}
  ],
  "plugins": [],
  "routes": [
    {{ "path": "{route_path}", "upstream": "u" }}
  ],
  "control_plane": {{
    "enabled": true,
    "bind": "127.0.0.1:21000",
    "node_id": "{local_node}",
    "role": "leader"
  }},
  "cluster": {{
    "gossip": {{
      "enabled": true,
      "bind": "127.0.0.1:22101",
      "advertise": "127.0.0.1:22101",
      "interval": "200ms",
      "fanout": 3,
      "suspicion_timeout": "5s",
      "dead_timeout": "30s",
      "max_message_size": 1400,
      "retransmit_multiplier": 2
    }}
  }}
}}"#
        )
    }

    fn test_bus(local_node: &str, upstream_port: u16, route_path: &str) -> Arc<GossipBus> {
        let raw = test_config_json(local_node, upstream_port, route_path);
        let cfg = ConfigManager::compile_raw_json(raw.as_str()).expect("compile test config");
        let cp = cfg.control_plane.clone();
        let mgr = ConfigManager::new(cfg);
        let circuit = Arc::new(ClusterCircuit::new(
            cp.node_id.clone(),
            ClusterCircuitConfig::default(),
        ));
        GossipBus::from_bootstrap(mgr, &cp, circuit).expect("gossip bus should be enabled")
    }

    async fn test_bus_async(
        local_node: &str,
        upstream_port: u16,
        route_path: &str,
    ) -> Arc<GossipBus> {
        let local_node = local_node.to_string();
        let route_path = route_path.to_string();
        tokio::task::spawn_blocking(move || {
            test_bus(local_node.as_str(), upstream_port, route_path.as_str())
        })
        .await
        .expect("spawn_blocking test_bus")
    }

    async fn set_bus_running(bus: &Arc<GossipBus>) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind test udp");
        let tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test tcp");
        let _ = bus.udp.set(Arc::new(udp));
        let _ = bus.tcp.set(Arc::new(tcp));
        bus.running.store(true, Ordering::SeqCst);
    }

    #[test]
    fn normalize_advertise_unspecified_becomes_loopback() {
        let input = SocketAddr::from(([0, 0, 0, 0], 22101));
        let got = normalize_advertise(input);
        assert_eq!(got.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(got.port(), 22101);
    }

    #[test]
    fn version_cmp_tie_breaks_by_node_id() {
        assert_eq!(version_cmp(10, "node-b", 10, "node-a"), 1);
        assert_eq!(version_cmp(10, "node-a", 10, "node-b"), -1);
        assert_eq!(version_cmp(10, "node-a", 10, "node-a"), 0);
        assert_eq!(version_cmp(11, "node-a", 10, "node-z"), 1);
        assert_eq!(version_cmp(9, "node-z", 10, "node-a"), -1);
    }

    #[test]
    fn hop_and_retransmit_rounds_are_monotonic() {
        assert_eq!(hop_limit(1), 2);
        assert!(hop_limit(32) >= hop_limit(4));
        assert_eq!(retransmit_rounds(0, 1), 1);
        assert!(retransmit_rounds(3, 64) > retransmit_rounds(1, 64));
    }

    #[test]
    fn outgoing_queue_coalesces_member_rumors_by_node() {
        let mut q = OutgoingQueue::new();
        let r1 = member_rumor("node-a", 1, "node-x", 18081);
        let id1 = r1.id.clone();
        q.insert(r1);
        assert_eq!(q.items.len(), 1);

        let r2 = member_rumor("node-a", 2, "node-x", 18082);
        let id2 = r2.id.clone();
        q.insert(r2);

        assert_eq!(q.items.len(), 1);
        assert_eq!(q.coalesce.len(), 1);
        assert!(!q.items.contains_key(&id1));
        assert!(q.items.contains_key(&id2));
    }

    #[test]
    fn outgoing_queue_coalesces_config_to_single_latest() {
        let mut q = OutgoingQueue::new();
        let r1 = config_rumor("node-a", 10, 1);
        let id1 = r1.id.clone();
        q.insert(r1);

        let r2 = config_rumor("node-a", 11, 2);
        let id2 = r2.id.clone();
        q.insert(r2);

        assert_eq!(q.items.len(), 1);
        assert!(!q.items.contains_key(&id1));
        assert!(q.items.contains_key(&id2));

        q.remove_by_id(&id1);
        assert!(q.items.contains_key(&id2));
        assert_eq!(q.coalesce.len(), 1);

        q.remove_by_id(&id2);
        assert!(q.items.is_empty());
        assert!(q.coalesce.is_empty());
    }

    #[test]
    fn member_list_same_incarnation_status_rules_hold() {
        let list = MemberList::new(node_id("node-a"), addr(22101), 100, 1);
        list.touch(node_id("node-b"), addr(22102), 7, 100, 1);
        assert_eq!(status_of(&list, "node-b"), Some(MemberStatus::Alive));

        let changed = list.merge_remote_status(
            node_id("node-b"),
            addr(22102),
            MemberStatus::Suspect,
            7,
            120,
            120,
            1,
        );
        assert!(changed);
        assert_eq!(status_of(&list, "node-b"), Some(MemberStatus::Suspect));

        let changed = list.merge_remote_status(
            node_id("node-b"),
            addr(22102),
            MemberStatus::Alive,
            7,
            130,
            130,
            1,
        );
        assert!(changed);
        assert_eq!(status_of(&list, "node-b"), Some(MemberStatus::Alive));

        let changed = list.merge_remote_status(
            node_id("node-b"),
            addr(22102),
            MemberStatus::Dead,
            7,
            140,
            140,
            1,
        );
        assert!(changed);
        assert_eq!(status_of(&list, "node-b"), Some(MemberStatus::Dead));

        let changed = list.merge_remote_status(
            node_id("node-b"),
            addr(22102),
            MemberStatus::Alive,
            7,
            150,
            150,
            1,
        );
        assert!(!changed);
        assert_eq!(status_of(&list, "node-b"), Some(MemberStatus::Dead));
    }

    #[test]
    fn member_list_lower_incarnation_cannot_override_higher() {
        let list = MemberList::new(node_id("node-a"), addr(22101), 100, 1);
        list.touch(node_id("node-b"), addr(22102), 10, 100, 1);

        let changed = list.merge_remote_status(
            node_id("node-b"),
            addr(22102),
            MemberStatus::Suspect,
            9,
            120,
            120,
            1,
        );
        assert!(!changed);
        assert_eq!(status_of(&list, "node-b"), Some(MemberStatus::Alive));
    }

    #[test]
    fn member_list_mark_dead_does_not_kill_self_without_leave_reason() {
        let list = MemberList::new(node_id("node-a"), addr(22101), 100, 1);
        list.mark_dead(node_id("node-a"), addr(22101), 100, 200, 1, "ping_timeout");
        assert_eq!(status_of(&list, "node-a"), Some(MemberStatus::Alive));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn random_alive_peer_except_returns_matching_id_and_addr() {
        let list = MemberList::new(node_id("node-a"), addr(22101), 100, 1);
        list.touch(node_id("node-b"), addr(22102), 1, 110, 1);
        list.mark_dead(node_id("node-c"), addr(22103), 1, 120, 1, "test");

        let picked = list
            .random_alive_peer_except("node-a")
            .await
            .expect("expected one alive peer");
        assert_eq!(picked.id.as_ref(), "node-b");
        assert_eq!(picked.addr, addr(22102));
        assert_eq!(picked.status, MemberStatus::Alive);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sample_alive_peers_excluding_respects_node_ids() {
        let list = MemberList::new(node_id("node-a"), addr(22101), 100, 1);
        list.touch(node_id("node-b"), addr(22102), 1, 110, 1);
        list.touch(node_id("node-c"), addr(22103), 1, 120, 1);
        list.mark_suspect(node_id("node-d"), addr(22104), 1, 130, 1, "test");

        let peers = list
            .sample_alive_peers_excluding(&["node-a", "node-b"], 8)
            .await;
        assert_eq!(peers, vec![addr(22103)]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn merge_config_rumor_rejects_lower_version_without_state_change() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let old_gen = bus.mgr.current_generation();
        let old_origin = {
            let st = bus.config_state.lock().await;
            st.origin.clone()
        };

        let next_raw = test_config_json("node-a", 19081, "/");
        let applied = bus
            .merge_config_rumor(
                node_id("node-b"),
                ConfigRumor {
                    version: 0,
                    raw_json: Arc::new(next_raw.into_bytes()),
                },
                100,
            )
            .await
            .expect("merge_config_rumor should not fail");

        assert!(!applied);
        assert_eq!(bus.mgr.current_generation(), old_gen);

        let st = bus.config_state.lock().await;
        assert_eq!(st.version, old_gen);
        assert_eq!(st.origin.as_ref(), old_origin.as_ref());
        assert!(st.applying.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_rumor_new_config_applies_and_enqueues_forward() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        set_bus_running(&bus).await;

        let next_raw = test_config_json("node-a", 19081, "/v2");
        let expected_gen = ConfigManager::compile_raw_json(next_raw.as_str())
            .expect("compile next config")
            .generation;

        let incoming = RumorEnvelope {
            id: Id {
                node_id: node_id("node-b"),
                seq: 42,
            },
            hop: 0,
            kind: RumorKind::Config(ConfigRumor {
                version: u64::MAX - 1,
                raw_json: Arc::new(next_raw.into_bytes()),
            }),
        };

        bus.handle_rumor(incoming.clone(), 200)
            .await
            .expect("handle rumor");

        assert_eq!(bus.mgr.current_generation(), expected_gen);

        let st = bus.config_state.lock().await;
        assert_eq!(st.origin.as_ref(), "node-b");
        drop(st);

        let q = lock_unpoison(&bus.outgoing);
        let item = q
            .items
            .get(&incoming.id)
            .expect("forwarded rumor should be queued");
        assert_eq!(item.rumor.hop, 1);
        match &item.rumor.kind {
            RumorKind::Config(c) => assert_eq!(c.version, u64::MAX - 1),
            other => panic!("unexpected forwarded rumor kind: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn merge_config_rumor_compile_failure_does_not_pollute_current_config() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let old_gen = bus.mgr.current_generation();
        let old_origin = {
            let st = bus.config_state.lock().await;
            st.origin.clone()
        };

        let applied = bus
            .merge_config_rumor(
                node_id("node-b"),
                ConfigRumor {
                    version: u64::MAX,
                    raw_json: Arc::new(br#"{"listen":bad-json}"#.to_vec()),
                },
                300,
            )
            .await
            .expect("merge_config_rumor should not fail");

        assert!(applied);
        assert_eq!(bus.mgr.current_generation(), old_gen);

        let st = bus.config_state.lock().await;
        assert_eq!(st.version, old_gen);
        assert_eq!(st.origin.as_ref(), old_origin.as_ref());
        assert!(st.applying.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn apply_sync_response_higher_version_applies_compiled_config() {
        let bus = test_bus_async("node-a", 19080, "/").await;

        let next_raw = test_config_json("node-a", 19081, "/sync");
        let expected_gen = ConfigManager::compile_raw_json(next_raw.as_str())
            .expect("compile next config")
            .generation;

        let resp = SyncResponse {
            meta: NodeMeta {
                node_id: node_id("node-b"),
                addr: addr(22102),
                incarnation: 1,
                config_version: u64::MAX - 2,
            },
            members: Vec::new(),
            config: SyncConfig {
                version: u64::MAX - 2,
                origin: node_id("node-b"),
                raw_json: Arc::new(next_raw.into_bytes()),
            },
            circuits: Vec::new(),
            gcounters: Vec::new(),
            xdp_blocks: Vec::new(),
        };

        bus.apply_sync_response(resp)
            .await
            .expect("apply sync response");

        assert_eq!(bus.mgr.current_generation(), expected_gen);
        let st = bus.config_state.lock().await;
        assert_eq!(st.origin.as_ref(), "node-b");
        assert!(st.applying.is_none());
    }

    #[test]
    fn self_member_rumor_suspect_or_dead_is_ignored() {
        let bus = test_bus("node-a", 19080, "/");
        let me = bus.node_id.clone();
        let now = 500;

        let suspect = MemberRumor {
            node_id: me.clone(),
            addr: addr(22101),
            status: MemberStatus::Suspect,
            incarnation: u64::MAX,
            ts_ms: now,
        };
        let dead = MemberRumor {
            node_id: me.clone(),
            addr: addr(22101),
            status: MemberStatus::Dead,
            incarnation: u64::MAX,
            ts_ms: now + 1,
        };

        assert!(!bus.merge_member_rumor(&suspect, now));
        assert!(!bus.merge_member_rumor(&dead, now + 1));
        assert_eq!(
            status_of(&bus.members, me.as_ref()),
            Some(MemberStatus::Alive)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dead_nodes_do_not_participate_in_peer_sampling() {
        let list = MemberList::new(node_id("node-a"), addr(22101), 100, 1);
        list.touch(node_id("node-b"), addr(22102), 1, 110, 1);
        list.touch(node_id("node-c"), addr(22103), 1, 120, 1);
        list.mark_dead(node_id("node-c"), addr(22103), 1, 130, 1, "test");

        let peers = list.sample_alive_peers_except("node-a", 8).await;
        assert_eq!(peers, vec![addr(22102)]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn advance_member_timers_promotes_suspect_to_dead_and_enqueues_rumor() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        set_bus_running(&bus).await;

        let mut rt = bus.runtime.load().as_ref().clone();
        rt.gossip.suspicion_timeout = Duration::from_millis(1);
        rt.gossip.dead_timeout = Duration::from_secs(60);
        bus.runtime.store(Arc::new(rt));

        bus.members.touch(node_id("node-b"), addr(22102), 3, 100, 1);
        bus.members
            .mark_suspect(node_id("node-b"), addr(22102), 3, 101, 1, "test");
        bus.advance_member_timers(300);

        assert_eq!(status_of(&bus.members, "node-b"), Some(MemberStatus::Dead));

        let q = lock_unpoison(&bus.outgoing);
        let has_dead_rumor = q.items.values().any(|item| {
            matches!(
                &item.rumor.kind,
                RumorKind::Member(m)
                    if m.node_id.as_ref() == "node-b" && m.status == MemberStatus::Dead
            )
        });
        assert!(has_dead_rumor);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_fragment_reassembles_out_of_order_parts() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let id = Id {
            node_id: node_id("node-frag"),
            seq: 1,
        };

        let r1 = bus
            .handle_fragment(id.clone(), 2, 3, b"cc".to_vec(), 100)
            .await
            .expect("fragment 2");
        let r2 = bus
            .handle_fragment(id.clone(), 0, 3, b"aa".to_vec(), 101)
            .await
            .expect("fragment 0");
        let r3 = bus
            .handle_fragment(id.clone(), 1, 3, b"bb".to_vec(), 102)
            .await
            .expect("fragment 1");

        assert!(r1.is_none());
        assert!(r2.is_none());
        assert_eq!(r3, Some(b"aabbcc".to_vec()));

        let table = bus.reassembly.lock().await;
        assert!(!table.contains_key(&id));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_fragment_incomplete_does_not_emit_payload() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let id = Id {
            node_id: node_id("node-frag"),
            seq: 2,
        };

        let out = bus
            .handle_fragment(id.clone(), 0, 2, b"aa".to_vec(), 200)
            .await
            .expect("fragment");
        assert!(out.is_none());

        let table = bus.reassembly.lock().await;
        let ent = table.get(&id).expect("entry should exist");
        assert_eq!(ent.received, 1);
        assert_eq!(ent.total, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_fragment_duplicate_does_not_double_count_or_duplicate_process() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let id = Id {
            node_id: node_id("node-frag"),
            seq: 3,
        };

        let first = bus
            .handle_fragment(id.clone(), 0, 2, b"aa".to_vec(), 300)
            .await
            .expect("first");
        let dup = bus
            .handle_fragment(id.clone(), 0, 2, b"AA".to_vec(), 301)
            .await
            .expect("dup");
        let done = bus
            .handle_fragment(id.clone(), 1, 2, b"bb".to_vec(), 302)
            .await
            .expect("second");

        assert!(first.is_none());
        assert!(dup.is_none());
        assert_eq!(done, Some(b"aabb".to_vec()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn advance_member_timers_removes_dead_after_retention_window() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let mut rt = bus.runtime.load().as_ref().clone();
        rt.gossip.dead_timeout = Duration::from_millis(1);
        rt.gossip.suspicion_timeout = Duration::from_secs(60);
        bus.runtime.store(Arc::new(rt));

        bus.members.touch(node_id("node-b"), addr(22102), 1, 10, 1);
        bus.members
            .mark_dead(node_id("node-b"), addr(22102), 1, 11, 1, "test");
        assert_eq!(status_of(&bus.members, "node-b"), Some(MemberStatus::Dead));

        bus.advance_member_timers(10_000);
        assert_eq!(status_of(&bus.members, "node-b"), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn advance_member_timers_keeps_alive_members() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let mut rt = bus.runtime.load().as_ref().clone();
        rt.gossip.dead_timeout = Duration::from_millis(1);
        rt.gossip.suspicion_timeout = Duration::from_millis(1);
        bus.runtime.store(Arc::new(rt));

        bus.members.touch(node_id("node-b"), addr(22102), 1, 10, 1);
        bus.advance_member_timers(10_000);
        assert_eq!(status_of(&bus.members, "node-b"), Some(MemberStatus::Alive));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gc_tables_cleans_expired_entries_but_keeps_outgoing_rumor_flow() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        let now = 500_000u64;

        {
            let mut seen = bus.seen.lock().await;
            seen.insert(
                Id {
                    node_id: node_id("old"),
                    seq: 1,
                },
                0,
            );
            seen.insert(
                Id {
                    node_id: node_id("new"),
                    seq: 2,
                },
                now.saturating_sub(100),
            );
        }
        {
            let mut reas = bus.reassembly.lock().await;
            reas.insert(
                Id {
                    node_id: node_id("old"),
                    seq: 11,
                },
                ReassemblyEntry {
                    created_ms: now.saturating_sub(10_000),
                    total: 2,
                    parts: vec![None, None],
                    received: 0,
                },
            );
            reas.insert(
                Id {
                    node_id: node_id("new"),
                    seq: 12,
                },
                ReassemblyEntry {
                    created_ms: now.saturating_sub(100),
                    total: 2,
                    parts: vec![None, None],
                    received: 0,
                },
            );
        }
        {
            let mut fw = bus.relay_forwards.lock().await;
            fw.insert(
                Id {
                    node_id: node_id("old"),
                    seq: 21,
                },
                RelayForward {
                    origin_addr: addr(23001),
                    expires_ms: now.saturating_sub(1),
                },
            );
            fw.insert(
                Id {
                    node_id: node_id("new"),
                    seq: 22,
                },
                RelayForward {
                    origin_addr: addr(23002),
                    expires_ms: now.saturating_add(10_000),
                },
            );
        }

        let flow_id = Id {
            node_id: node_id("flow"),
            seq: 99,
        };
        {
            let mut q = lock_unpoison(&bus.outgoing);
            q.insert(RumorEnvelope {
                id: flow_id.clone(),
                hop: 0,
                kind: RumorKind::Member(MemberRumor {
                    node_id: node_id("node-b"),
                    addr: addr(22102),
                    status: MemberStatus::Alive,
                    incarnation: 1,
                    ts_ms: now,
                }),
            });
        }

        bus.gc_tables(now).await;

        {
            let seen = bus.seen.lock().await;
            assert!(!seen.keys().any(|id| id.node_id.as_ref() == "old"));
            assert!(seen.keys().any(|id| id.node_id.as_ref() == "new"));
        }
        {
            let reas = bus.reassembly.lock().await;
            assert!(!reas.keys().any(|id| id.node_id.as_ref() == "old"));
            assert!(reas.keys().any(|id| id.node_id.as_ref() == "new"));
        }
        {
            let fw = bus.relay_forwards.lock().await;
            assert!(!fw.keys().any(|id| id.node_id.as_ref() == "old"));
            assert!(fw.keys().any(|id| id.node_id.as_ref() == "new"));
        }
        {
            let q = lock_unpoison(&bus.outgoing);
            assert!(q.items.contains_key(&flow_id));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_rumor_hop_limit_exhausted_does_not_forward() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        set_bus_running(&bus).await;

        let before = bus.stats.dropped_too_old.load(Ordering::Relaxed);
        let rumor = RumorEnvelope {
            id: Id {
                node_id: node_id("node-b"),
                seq: 500,
            },
            hop: hop_limit(bus.members.len()).saturating_add(1),
            kind: RumorKind::Member(MemberRumor {
                node_id: node_id("node-c"),
                addr: addr(22103),
                status: MemberStatus::Alive,
                incarnation: 1,
                ts_ms: 1,
            }),
        };

        bus.handle_rumor(rumor.clone(), 1)
            .await
            .expect("handle rumor");

        let after = bus.stats.dropped_too_old.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
        let q = lock_unpoison(&bus.outgoing);
        assert!(!q.items.contains_key(&rumor.id));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_forward_ack_goes_to_origin_not_message_source() {
        let bus = test_bus_async("node-a", 19080, "/").await;
        set_bus_running(&bus).await;

        let src_rx = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind source rx");
        let origin_rx = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind origin rx");
        let target_rx = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind target rx");
        let src_addr = src_rx.local_addr().expect("source addr");
        let origin_addr = origin_rx.local_addr().expect("origin addr");
        let target_addr = target_rx.local_addr().expect("target addr");

        let probe = Id {
            node_id: node_id("probe-owner"),
            seq: 77,
        };
        let ping_req = WireMsg::PingReq {
            meta: meta("src-node", src_addr, 1, 1),
            probe: probe.clone(),
            target_id: node_id("target-node"),
            target_addr,
            origin_addr,
        };
        bus.handle_msg(ping_req, src_addr, 100)
            .await
            .expect("handle ping-req");

        // Drain the direct ping sent to target.
        let mut tmp = [0u8; 2048];
        let _ = timeout(
            TokioDuration::from_millis(200),
            target_rx.recv_from(&mut tmp),
        )
        .await
        .expect("target should receive direct ping")
        .expect("recv ping");

        let ack = WireMsg::Ack {
            meta: meta("target-node", target_addr, 1, 1),
            probe: probe.clone(),
            target: None,
        };
        bus.handle_msg(ack, target_addr, 101)
            .await
            .expect("handle ack");

        let mut buf_origin = [0u8; 2048];
        let (n, _) = timeout(
            TokioDuration::from_millis(300),
            origin_rx.recv_from(&mut buf_origin),
        )
        .await
        .expect("origin should get forwarded ack")
        .expect("recv forwarded ack");
        let decoded = WireMsg::decode(&buf_origin[..n]).expect("decode forwarded ack");
        match decoded {
            WireMsg::Ack { probe: p, .. } => assert_eq!(p.seq, probe.seq),
            other => panic!("unexpected forwarded message: {other:?}"),
        }

        let mut buf_src = [0u8; 2048];
        let src_got_any = timeout(
            TokioDuration::from_millis(150),
            src_rx.recv_from(&mut buf_src),
        )
        .await
        .is_ok();
        assert!(!src_got_any);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_forward_send_failure_does_not_break_local_processing() {
        let bus = test_bus_async("node-a", 19080, "/").await;

        let probe = Id {
            node_id: node_id("probe-owner"),
            seq: 88,
        };
        {
            let mut fw = bus.relay_forwards.lock().await;
            fw.insert(
                probe.clone(),
                RelayForward {
                    origin_addr: addr(23090),
                    expires_ms: 10_000,
                },
            );
        }

        let ack = WireMsg::Ack {
            meta: meta("target-node", addr(23091), 1, 1),
            probe: probe.clone(),
            target: None,
        };
        // No UDP socket is started for this bus; send_udp fails internally.
        // The handler must still succeed and complete local state transition.
        bus.handle_msg(ack, addr(23091), 1234)
            .await
            .expect("handle ack should succeed even when forward send fails");

        let fw = bus.relay_forwards.lock().await;
        assert!(!fw.contains_key(&probe));
    }
}
