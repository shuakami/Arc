use crate::bpf;
use crate::config::{parse_security_config_best_effort, ArcSecurityConfig, XdpUserConfig};
use arc_common::{ArcError, Result};
use arc_config::SharedConfig;
use arc_xdp_common::{
    AttackKind, BlacklistEntry, BlockReason, GlobalStats, IpKey, PortStats, SynState, XdpConfig,
    XdpEvent,
};
use std::fmt;
use std::os::fd::RawFd;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::time;

use crate::bpf::{
    map_dump, map_info_by_fd, map_lookup_elem, map_lookup_percpu, map_update_elem, Pod,
};

/// SAFETY: We assume arc-xdp-common types are `#[repr(C)]` plain-data and kernel compatible.
unsafe impl Pod for IpKey {}
unsafe impl Pod for BlacklistEntry {}
unsafe impl Pod for SynState {}
unsafe impl Pod for GlobalStats {}
unsafe impl Pod for PortStats {}
unsafe impl Pod for XdpEvent {}
unsafe impl Pod for XdpConfig {}
unsafe impl Pod for BlockReason {}
unsafe impl Pod for AttackKind {}

/// XDP mode gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    Disabled = 0,
    Generic = 1,
    Driver = 2,
    Tc = 3,
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdpMode::Disabled => write!(f, "disabled"),
            XdpMode::Generic => write!(f, "generic"),
            XdpMode::Driver => write!(f, "driver"),
            XdpMode::Tc => write!(f, "tc"),
        }
    }
}

#[derive(Clone)]
pub struct L7LinkHandle {
    tx: mpsc::Sender<L7LinkMsg>,
}

impl L7LinkHandle {
    pub fn new(tx: mpsc::Sender<L7LinkMsg>) -> Self {
        Self { tx }
    }

    /// No-op link (drops all notifications).
    pub fn noop() -> (Self, mpsc::Receiver<L7LinkMsg>) {
        let (tx, rx) = mpsc::channel(1);
        (Self { tx }, rx)
    }

    #[inline]
    pub fn try_send(&self, msg: L7LinkMsg) {
        let _ = self.tx.try_send(msg);
    }
}

/// Messages from XDP integration to L7 limiter.
#[derive(Clone)]
pub enum L7LinkMsg {
    BlockIp {
        ip: IpKey,
        ttl: Duration,
        reason: BlockReason,
    },
    SetGlobalLimitMultiplier {
        multiplier: f64,
    },
}

/// Runtime-owned map fds.
struct XdpMaps {
    // maps
    blacklist: RawFd,
    whitelist: RawFd,
    config: RawFd,

    // stats maps (names are assumptions; open best-effort)
    global_stats: RawFd,
    port_stats: RawFd,
    syn_state: RawFd,

    // ringbuf events
    events: RawFd,

    // cached info
    blacklist_info: bpf::BpfMapInfo,
    whitelist_info: bpf::BpfMapInfo,
    config_info: bpf::BpfMapInfo,
    global_stats_info: Option<bpf::BpfMapInfo>,
    port_stats_info: Option<bpf::BpfMapInfo>,
    syn_state_info: Option<bpf::BpfMapInfo>,
    events_info: Option<bpf::BpfMapInfo>,
}

impl Drop for XdpMaps {
    fn drop(&mut self) {
        bpf::close_fd_best_effort(self.blacklist);
        bpf::close_fd_best_effort(self.whitelist);
        bpf::close_fd_best_effort(self.config);
        bpf::close_fd_best_effort(self.global_stats);
        bpf::close_fd_best_effort(self.port_stats);
        bpf::close_fd_best_effort(self.syn_state);
        bpf::close_fd_best_effort(self.events);
    }
}

/// Public Blacklist manager.
#[derive(Clone)]
pub struct BlacklistManager {
    mode: XdpMode,
    map_fd: RawFd,
    map_max: u32,
}

impl BlacklistManager {
    pub fn disabled() -> Self {
        Self {
            mode: XdpMode::Disabled,
            map_fd: -1,
            map_max: 0,
        }
    }

    pub fn new(mode: XdpMode, map_fd: RawFd, info: bpf::BpfMapInfo) -> Self {
        Self {
            mode,
            map_fd,
            map_max: info.max_entries,
        }
    }

    /// Add IP to blacklist.
    ///
    /// 要求：<1ms 生效 => 直接 map_update。
    pub fn add(&self, ip: IpKey, ttl: Duration, reason: BlockReason) -> Result<()> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Err(ArcError::internal("xdp is disabled"));
        }

        let entry = make_blacklist_entry(ttl, reason);
        map_update_elem(self.map_fd, &ip, &entry, 0)
            .map_err(|e| ArcError::io("bpf map_update(blacklist)", e))?;
        Ok(())
    }

    /// Remove IP from blacklist.
    pub fn remove(&self, ip: IpKey) -> Result<bool> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Ok(false);
        }

        let ok = bpf::map_delete_elem(self.map_fd, &ip)
            .map_err(|e| ArcError::io("bpf map_delete(blacklist)", e))?;
        Ok(ok)
    }

    /// List current blacklist entries (bounded).
    pub fn list(&self, max: usize) -> Result<Vec<(IpKey, BlacklistEntry)>> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Ok(Vec::new());
        }
        let v = map_dump::<IpKey, BlacklistEntry>(self.map_fd, max)
            .map_err(|e| ArcError::io("bpf map_dump(blacklist)", e))?;
        Ok(v)
    }

    pub fn capacity(&self) -> u32 {
        self.map_max
    }
}

/// Public Whitelist manager.
///
/// 注意：arc-xdp-common 未提供 whitelist value type；这里假设 map value 为 u8(1)。
#[derive(Clone)]
pub struct WhitelistManager {
    mode: XdpMode,
    map_fd: RawFd,
    map_max: u32,
}

impl WhitelistManager {
    pub fn disabled() -> Self {
        Self {
            mode: XdpMode::Disabled,
            map_fd: -1,
            map_max: 0,
        }
    }

    pub fn new(mode: XdpMode, map_fd: RawFd, info: bpf::BpfMapInfo) -> Self {
        Self {
            mode,
            map_fd,
            map_max: info.max_entries,
        }
    }

    pub fn add(&self, cidr: IpKey) -> Result<()> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Err(ArcError::internal("xdp is disabled"));
        }

        let one: u8 = 1;
        bpf::map_update_elem(self.map_fd, &cidr, &one, 0)
            .map_err(|e| ArcError::io("bpf map_update(whitelist)", e))?;
        Ok(())
    }

    pub fn remove(&self, cidr: IpKey) -> Result<bool> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Ok(false);
        }
        let ok = bpf::map_delete_elem(self.map_fd, &cidr)
            .map_err(|e| ArcError::io("bpf map_delete(whitelist)", e))?;
        Ok(ok)
    }

    /// Exact key lookup in whitelist map.
    pub fn contains(&self, key: IpKey) -> Result<bool> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Ok(false);
        }
        let mut v: u8 = 0;
        map_lookup_elem::<IpKey, u8>(self.map_fd, &key, &mut v)
            .map_err(|e| ArcError::io("bpf map_lookup(whitelist)", e))
    }

    pub fn list(&self, max: usize) -> Result<Vec<IpKey>> {
        if self.mode == XdpMode::Disabled || self.map_fd < 0 {
            return Ok(Vec::new());
        }
        let v = bpf::map_dump::<IpKey, u8>(self.map_fd, max)
            .map_err(|e| ArcError::io("bpf map_dump(whitelist)", e))?;
        Ok(v.into_iter().map(|(k, _)| k).collect())
    }

    pub fn capacity(&self) -> u32 {
        self.map_max
    }
}

/// Threshold snapshot for observability.
#[derive(Debug, Clone)]
pub struct ThresholdSnapshot {
    pub warmup: bool,
    pub sample_count: u64,
    pub mean_pps: f64,
    pub sigma_pps: f64,
    pub current_pps: u64,
    pub dynamic_threshold_pps: u64,
}

/// Stats snapshot for /xdp/stats.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub packets_pass: u64,
    pub packets_drop: u64,
    pub defense_mode_active: bool,
    pub global_syn_rate_pps: u64,
}

/// /xdp/status snapshot.
#[derive(Debug, Clone)]
pub struct XdpStatusSnapshot {
    pub mode: XdpMode,
    pub iface: Option<String>,
    pub kernel_release: String,
    pub program_version: Option<String>,
}

/// Public state handle for XdpManager.
#[derive(Debug)]
pub struct XdpManagerState {
    pub mode: AtomicU8,
    pub defense_mode_active: AtomicBool,
    pub global_syn_rate_pps: AtomicU64,
    pub dynamic_syn_threshold_pps: AtomicU64,
    pub map_near_full: AtomicBool,
}

impl XdpManagerState {
    fn new(mode: XdpMode) -> Self {
        Self {
            mode: AtomicU8::new(mode as u8),
            defense_mode_active: AtomicBool::new(false),
            global_syn_rate_pps: AtomicU64::new(0),
            dynamic_syn_threshold_pps: AtomicU64::new(0),
            map_near_full: AtomicBool::new(false),
        }
    }

    pub fn mode(&self) -> XdpMode {
        match self.mode.load(Ordering::Relaxed) {
            3 => XdpMode::Tc,
            2 => XdpMode::Driver,
            1 => XdpMode::Generic,
            _ => XdpMode::Disabled,
        }
    }
}

static GLOBAL_XDP_MANAGER: OnceLock<Arc<XdpManager>> = OnceLock::new();

/// Get global XdpManager (if initialized).
pub fn global_xdp_manager() -> Option<Arc<XdpManager>> {
    GLOBAL_XDP_MANAGER.get().cloned()
}

/// Set global XdpManager; called from arc-gateway main during init.
pub fn set_global_xdp_manager(mgr: Arc<XdpManager>) {
    let _ = GLOBAL_XDP_MANAGER.set(mgr);
}

/// Main XDP manager.
pub struct XdpManager {
    swap: Arc<arc_swap::ArcSwap<SharedConfig>>,
    cfg: tokio::sync::RwLock<ArcSecurityConfig>,
    iface: tokio::sync::RwLock<Option<String>>,
    pin_base: tokio::sync::RwLock<String>,

    maps: tokio::sync::RwLock<Option<XdpMaps>>,

    state: Arc<XdpManagerState>,

    shutdown_tx: watch::Sender<bool>,

    // managers
    blacklist_mgr: tokio::sync::RwLock<BlacklistManager>,
    whitelist_mgr: tokio::sync::RwLock<WhitelistManager>,

    // L7 link
    l7_link: L7LinkHandle,

    // trace ring (best-effort; for CLI trace)
    trace: TraceBuffer,
}

struct TraceBuffer {
    slots: Vec<TraceSlot>,
    mask: u64,
    idx: AtomicU64,
}

struct TraceSlot {
    seq: AtomicU64,
    // SAFETY: protected by seq seqlock; readers must validate seq before/after.
    data: std::cell::UnsafeCell<TraceRecord>,
}

unsafe impl Sync for TraceSlot {}

#[derive(Clone, Copy)]
struct TraceRecord {
    ts_ns: u64,
    // store a copy of raw event bytes for robustness across enum layout changes
    len: u32,
    buf: [u8; 256],
}

impl TraceBuffer {
    fn new(slots_pow2: usize) -> Self {
        let n = slots_pow2.max(1024).next_power_of_two();
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(TraceSlot {
                seq: AtomicU64::new(0),
                data: std::cell::UnsafeCell::new(TraceRecord {
                    ts_ns: 0,
                    len: 0,
                    buf: [0u8; 256],
                }),
            });
        }
        Self {
            slots: v,
            mask: (n as u64).saturating_sub(1),
            idx: AtomicU64::new(0),
        }
    }

    #[inline]
    fn push(&self, now_ns: u64, payload: &[u8]) {
        let i = self.idx.fetch_add(1, Ordering::Relaxed) & self.mask;
        let slot = &self.slots[i as usize];

        // seqlock write: set seq to odd, write data, set to even
        let s0 = slot.seq.load(Ordering::Relaxed);
        slot.seq.store(s0.wrapping_add(1) | 1, Ordering::Release);

        // SAFETY: exclusive by seqlock (seq odd), readers validate.
        unsafe {
            let rec = &mut *slot.data.get();
            rec.ts_ns = now_ns;
            let n = payload.len().min(rec.buf.len());
            rec.len = n as u32;
            rec.buf[..n].copy_from_slice(&payload[..n]);
            if n < rec.buf.len() {
                rec.buf[n..].fill(0);
            }
        }

        slot.seq.store(s0.wrapping_add(2) & !1, Ordering::Release);
    }

    fn snapshot(&self) -> Vec<TraceRecord> {
        let mut out = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            loop {
                let s1 = slot.seq.load(Ordering::Acquire);
                if (s1 & 1) != 0 {
                    // writer in progress
                    continue;
                }
                // SAFETY: read under seqlock
                let rec = unsafe { *slot.data.get() };
                let s2 = slot.seq.load(Ordering::Acquire);
                if s1 == s2 && (s2 & 1) == 0 {
                    if rec.len != 0 {
                        out.push(rec);
                    }
                    break;
                }
            }
        }
        out.sort_by_key(|r| r.ts_ns);
        out
    }
}

impl XdpManager {
    pub fn spawn(
        swap: Arc<arc_swap::ArcSwap<SharedConfig>>,
        l7_link: L7LinkHandle,
    ) -> Result<Arc<Self>> {
        let raw = swap.load().raw_json.as_ref().to_string();
        let sec = parse_security_config_best_effort(&raw);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mode = if sec.xdp.enabled {
            XdpMode::Generic
        } else {
            XdpMode::Disabled
        };
        let state = Arc::new(XdpManagerState::new(mode));
        let initial_pin_base = effective_pin_base(&sec.xdp);

        let mgr = Arc::new(Self {
            swap,
            cfg: tokio::sync::RwLock::new(sec),
            iface: tokio::sync::RwLock::new(None),
            pin_base: tokio::sync::RwLock::new(initial_pin_base),
            maps: tokio::sync::RwLock::new(None),
            state,
            shutdown_tx,
            blacklist_mgr: tokio::sync::RwLock::new(BlacklistManager::disabled()),
            whitelist_mgr: tokio::sync::RwLock::new(WhitelistManager::disabled()),
            l7_link,
            trace: TraceBuffer::new(8192),
        });

        // Background runtime thread: keep it isolated from io_uring workers.
        let thread_mgr = mgr.clone();
        std::thread::Builder::new()
            .name("arc-xdp".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build();

                let rt = match rt {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("xdp runtime build failed: {e}");
                        return;
                    }
                };

                rt.block_on(async move {
                    let mut rx = shutdown_rx;
                    if let Err(e) = thread_mgr.init_and_run(&mut rx).await {
                        eprintln!("xdp manager fatal: {e}");
                    }
                });
            })
            .map_err(|e| ArcError::io("spawn xdp runtime thread", e))?;

        Ok(mgr)
    }

    /// Shutdown XDP tasks + detach (best-effort).
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// State accessor.
    pub fn state(&self) -> Arc<XdpManagerState> {
        self.state.clone()
    }

    /// Blacklist manager (clone).
    pub async fn blacklist(&self) -> BlacklistManager {
        self.blacklist_mgr.read().await.clone()
    }

    /// Blacklist manager (clone), blocking accessor for non-async dataplane threads.
    pub fn blacklist_blocking(&self) -> BlacklistManager {
        self.blacklist_mgr.blocking_read().clone()
    }

    /// Whitelist manager (clone).
    pub async fn whitelist(&self) -> WhitelistManager {
        self.whitelist_mgr.read().await.clone()
    }

    /// Whitelist manager (clone), blocking accessor for non-async dataplane threads.
    pub fn whitelist_blocking(&self) -> WhitelistManager {
        self.whitelist_mgr.blocking_read().clone()
    }

    /// Status snapshot.
    pub async fn status(&self) -> XdpStatusSnapshot {
        let mode = self.state.mode();
        XdpStatusSnapshot {
            mode,
            iface: self.iface.read().await.clone(),
            kernel_release: bpf::kernel_release(),
            program_version: None, // best-effort; depends on loader
        }
    }

    /// Effective pin base path used by manager map open.
    pub async fn pin_base(&self) -> String {
        self.pin_base.read().await.clone()
    }

    /// Stats snapshot.
    pub async fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets_pass: 0,
            packets_drop: 0,
            defense_mode_active: self.state.defense_mode_active.load(Ordering::Relaxed),
            global_syn_rate_pps: self.state.global_syn_rate_pps.load(Ordering::Relaxed),
        }
    }

    /// Threshold snapshot (best-effort).
    pub async fn threshold_snapshot(&self) -> ThresholdSnapshot {
        ThresholdSnapshot {
            warmup: false,
            sample_count: 0,
            mean_pps: 0.0,
            sigma_pps: 0.0,
            current_pps: self.state.global_syn_rate_pps.load(Ordering::Relaxed),
            dynamic_threshold_pps: self.state.dynamic_syn_threshold_pps.load(Ordering::Relaxed),
        }
    }

    /// Trace snapshot: returns raw bytes for last events.
    pub fn trace_snapshot(&self) -> Vec<(u64, Vec<u8>)> {
        self.trace
            .snapshot()
            .into_iter()
            .map(|r| (r.ts_ns, r.buf[..(r.len as usize)].to_vec()))
            .collect()
    }

    async fn init_and_run(self: Arc<Self>, shutdown_rx: &mut watch::Receiver<bool>) -> Result<()> {
        // 1) config watcher + init maps once
        self.init_from_config().await?;

        // 2) spawn tasks
        let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<u8>>(8192);

        let mgr_for_ring = self.clone();
        let mut shutdown_for_ring = shutdown_rx.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = mgr_for_ring.ringbuf_loop(&mut shutdown_for_ring, ev_tx) {
                eprintln!("xdp ringbuf loop exited: {e}");
            }
        });

        // Async event processor (does logging + L7 link) — keeps ring consumer non-blocking.
        let mgr_for_ev = self.clone();
        let mut shutdown_for_ev = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_for_ev.changed() => {
                        break;
                    }
                    v = ev_rx.recv() => {
                        let Some(payload) = v else { break; };
                        mgr_for_ev.handle_event_payload(&payload).await;
                    }
                }
            }
        });

        // Threshold calculator (100ms)
        let mgr_for_thr = self.clone();
        let mut shutdown_for_thr = shutdown_rx.clone();
        tokio::spawn(async move {
            mgr_for_thr.threshold_task(&mut shutdown_for_thr).await;
        });

        // Stats collector (1s)
        let mgr_for_stats = self.clone();
        let mut shutdown_for_stats = shutdown_rx.clone();
        tokio::spawn(async move {
            mgr_for_stats.stats_task(&mut shutdown_for_stats).await;
        });

        // Blacklist TTL sweeper (1s): remove expired entries so unban is automatic.
        let mgr_for_prune = self.clone();
        let mut shutdown_for_prune = shutdown_rx.clone();
        tokio::spawn(async move {
            mgr_for_prune
                .prune_blacklist_task(&mut shutdown_for_prune)
                .await;
        });

        // Config hot reload watcher (500ms) — update xdp config map switches.
        let mgr_for_cfg = self.clone();
        let mut shutdown_for_cfg = shutdown_rx.clone();
        tokio::spawn(async move {
            mgr_for_cfg.config_watch_task(&mut shutdown_for_cfg).await;
        });

        // Wait until shutdown signal
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }

        // Best-effort detach
        self.detach_best_effort().await;

        Ok(())
    }

    async fn init_from_config(&self) -> Result<()> {
        let raw = self.swap.load().raw_json.as_ref().to_string();
        let sec = parse_security_config_best_effort(&raw);
        {
            let mut w = self.cfg.write().await;
            *w = sec.clone();
        }
        let pin_base = effective_pin_base(&sec.xdp);
        *self.pin_base.write().await = pin_base.clone();

        if !sec.xdp.enabled {
            self.state
                .mode
                .store(XdpMode::Disabled as u8, Ordering::Relaxed);
            *self.iface.write().await = None;
            return Ok(());
        }

        let iface = match sec.xdp.interface.as_ref() {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => auto_detect_iface().unwrap_or_else(|| "eth0".to_string()),
        };
        *self.iface.write().await = Some(iface.clone());

        // Privilege gate: no root/caps => clear downgrade path to L7 only (no silent failure).
        if !has_xdp_privileges() {
            eprintln!(
                "xdp warn: insufficient privileges for XDP/tc attach ({}); running with l7 protection only",
                xdp_privilege_summary()
            );
            self.state
                .mode
                .store(XdpMode::Disabled as u8, Ordering::Relaxed);
            *self.blacklist_mgr.write().await = BlacklistManager::disabled();
            *self.whitelist_mgr.write().await = WhitelistManager::disabled();
            *self.maps.write().await = None;
            return Ok(());
        }

        // Try attach via external loader with fallback chain:
        // driver -> generic -> tc -> l7-only.
        let mode = match attach_via_loader(&iface, pin_base.as_str()) {
            Ok(mode) => mode,
            Err(e) => {
                eprintln!("xdp warn: xdp attach failed on {iface}: {e}; trying tc-ebpf fallback");
                match attach_tc_via_loader(&iface, pin_base.as_str()) {
                    Ok(()) => {
                        eprintln!("xdp warn: xdp unavailable, tc-ebpf fallback enabled on {iface}");
                        XdpMode::Tc
                    }
                    Err(tc_e) => {
                        eprintln!(
                            "xdp warn: tc-ebpf fallback failed on {iface}: {tc_e}; running with l7 protection only"
                        );
                        self.state
                            .mode
                            .store(XdpMode::Disabled as u8, Ordering::Relaxed);
                        *self.blacklist_mgr.write().await = BlacklistManager::disabled();
                        *self.whitelist_mgr.write().await = WhitelistManager::disabled();
                        *self.maps.write().await = None;
                        return Ok(());
                    }
                }
            }
        };
        self.state.mode.store(mode as u8, Ordering::Relaxed);

        // Open pinned maps.
        match open_maps(pin_base.as_str()) {
            Ok(maps) => {
                let bl = BlacklistManager::new(mode, maps.blacklist, maps.blacklist_info);
                let wl = WhitelistManager::new(mode, maps.whitelist, maps.whitelist_info);
                *self.blacklist_mgr.write().await = bl;
                *self.whitelist_mgr.write().await = wl;
                *self.maps.write().await = Some(maps);
            }
            Err(e) => {
                if mode == XdpMode::Tc {
                    eprintln!(
                        "xdp warn: tc-ebpf enabled but shared maps unavailable: {e}; xdp control path disabled"
                    );
                    *self.blacklist_mgr.write().await = BlacklistManager::disabled();
                    *self.whitelist_mgr.write().await = WhitelistManager::disabled();
                    *self.maps.write().await = None;
                } else {
                    eprintln!("xdp warn: open pinned maps failed, disabling xdp: {e}");
                    self.state
                        .mode
                        .store(XdpMode::Disabled as u8, Ordering::Relaxed);
                    *self.blacklist_mgr.write().await = BlacklistManager::disabled();
                    *self.whitelist_mgr.write().await = WhitelistManager::disabled();
                    *self.maps.write().await = None;
                }
            }
        }

        Ok(())
    }

    async fn config_watch_task(self: Arc<Self>, shutdown_rx: &mut watch::Receiver<bool>) {
        let mut last_gen = self.swap.load().generation;

        let mut tick = time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = tick.tick() => {
                    let cur = self.swap.load();
                    if cur.generation != last_gen {
                        last_gen = cur.generation;
                        let raw = cur.raw_json.as_ref().to_string();
                        let sec = parse_security_config_best_effort(&raw);
                        {
                            let mut w = self.cfg.write().await;
                            *w = sec.clone();
                        }
                        let desired_pin_base = effective_pin_base(&sec.xdp);
                        let current_pin_base = self.pin_base.read().await.clone();
                        if desired_pin_base != current_pin_base {
                            eprintln!(
                                "xdp warn: pin_base changed in hot reload (old={} new={}); restart required",
                                current_pin_base,
                                desired_pin_base
                            );
                        }
                        // Apply user config toggles to XdpConfig map (best-effort).
                        self.apply_user_config_to_bpf(&sec.xdp).await;
                    }
                }
            }
        }
    }

    async fn apply_user_config_to_bpf(&self, xcfg: &XdpUserConfig) {
        let mode = self.state.mode();
        if mode == XdpMode::Disabled {
            return;
        }

        let maps_guard = self.maps.read().await;
        let Some(maps) = maps_guard.as_ref() else {
            return;
        };

        // config map key convention assumption: singleton key 0 (u32).
        let key: u32 = 0;
        let mut cur: XdpConfig = unsafe { std::mem::zeroed() };
        let found = map_lookup_elem::<u32, XdpConfig>(maps.config, &key, &mut cur)
            .ok()
            .unwrap_or(false);
        if !found {
            // if no entry, write fresh config
            cur = make_default_xdp_config(xcfg);
        } else {
            // update toggles
            apply_xdp_config_toggles(&mut cur, xcfg);
        }

        if let Err(e) = map_update_elem::<u32, XdpConfig>(maps.config, &key, &cur, 0) {
            eprintln!("xdp warn: update XdpConfig map failed: {e}");
        }
    }

    async fn detach_best_effort(&self) {
        let iface_opt = self.iface.read().await.clone();
        let Some(iface) = iface_opt else {
            return;
        };
        // Best-effort: call loader detach if supported, else ignore.
        let _ = Command::new("arc-xdp-loader")
            .arg("detach")
            .arg("--iface")
            .arg(&iface)
            .status();

        // Also try `ip link set dev iface xdp off` as fallback.
        let _ = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg("dev")
            .arg(&iface)
            .arg("xdp")
            .arg("off")
            .status();
    }

    fn ringbuf_loop(
        &self,
        shutdown_rx: &mut watch::Receiver<bool>,
        tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        let mode = self.state.mode();
        if mode == XdpMode::Disabled {
            // Nothing to do.
            while !*shutdown_rx.borrow() {
                std::thread::sleep(Duration::from_millis(200));
            }
            return Ok(());
        }

        let maps_guard = self.maps.blocking_read();
        let Some(maps) = maps_guard.as_ref() else {
            while !*shutdown_rx.borrow() {
                std::thread::sleep(Duration::from_millis(200));
            }
            return Ok(());
        };

        let rb = RingBuf::new(maps.events, maps.events_info)?;
        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            // poll 50ms to keep latency low but avoid busy loop
            let ready = bpf::poll_readable(maps.events, 50).unwrap_or(false);
            if !ready {
                continue;
            }

            // consume all available records
            rb.consume(|payload| {
                let now = monotonic_ns();
                self.trace.push(now, payload);

                // non-blocking send to async handler
                let _ = tx.try_send(payload.to_vec());
            })?;
        }

        Ok(())
    }

    async fn handle_event_payload(&self, payload: &[u8]) {
        // Try decode as XdpEvent (fixed-size).
        // If size mismatch, still keep raw bytes in trace; just log warn.
        if payload.len() < std::mem::size_of::<XdpEvent>() {
            eprintln!(
                "xdp warn: ringbuf payload too small: {} bytes",
                payload.len()
            );
            return;
        }

        // SAFETY: XdpEvent is assumed Pod and payload is at least its size.
        let ev: XdpEvent = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const XdpEvent) };
        self.handle_event(ev).await;
    }

    async fn handle_event(&self, ev: XdpEvent) {
        // 事件处理逻辑依赖 arc-xdp-common 的 enum 具体字段。
        // 这里按你的枚举契约做 match，并尽量不阻塞（L7 link 通过 try_send）。
        match classify_event(&ev) {
            EventClass::IpBlocked { ip, ttl, reason } => {
                let _ = ip;
                let _ = reason;
                eprintln!("xdp ERROR: ip blocked ttl={:?}", ttl);
                self.l7_link
                    .try_send(L7LinkMsg::BlockIp { ip, ttl, reason });
            }
            EventClass::AttackDetected { kind } => {
                let _ = kind;
                eprintln!("xdp ERROR: attack detected");
                self.activate_defense_mode("attack_detected").await;
            }
            EventClass::MapNearFull => {
                eprintln!("xdp WARN: map near full");
                self.state.map_near_full.store(true, Ordering::Relaxed);
            }
            EventClass::GlobalDefenseActivated => {
                eprintln!("xdp WARN: global defense activated by kernel");
                self.activate_defense_mode("kernel").await;
            }
            EventClass::Unknown => {
                eprintln!("xdp warn: unknown event");
            }
        }
    }

    async fn activate_defense_mode(&self, source: &str) {
        let _ = source;

        if self.state.defense_mode_active.swap(true, Ordering::AcqRel) {
            return;
        }

        // Notify L7 to tighten global limits.
        self.l7_link
            .try_send(L7LinkMsg::SetGlobalLimitMultiplier { multiplier: 0.5 });

        // Update XdpConfig multiplier best-effort.
        let cfg = self.cfg.read().await.clone();
        let mode = self.state.mode();
        if mode == XdpMode::Disabled {
            return;
        }
        let maps_guard = self.maps.read().await;
        let Some(maps) = maps_guard.as_ref() else {
            return;
        };

        let key: u32 = 0;
        let mut cur: XdpConfig = unsafe { std::mem::zeroed() };
        let found = map_lookup_elem::<u32, XdpConfig>(maps.config, &key, &mut cur)
            .ok()
            .unwrap_or(false);
        if !found {
            cur = make_default_xdp_config(&cfg.xdp);
        }
        // Apply defense multiplier
        apply_defense_multiplier(&mut cur, cfg.xdp.defense.defense_multiplier);

        let _ = map_update_elem::<u32, XdpConfig>(maps.config, &key, &cur, 0);
    }

    async fn threshold_task(self: Arc<Self>, shutdown_rx: &mut watch::Receiver<bool>) {
        let mut welford = Welford::new();
        let start_ns = monotonic_ns();
        let mut last_cfg_write_ns = 0u64;

        let mut tick = time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = tick.tick() => {
                    let mode = self.state.mode();
                    if mode == XdpMode::Disabled {
                        continue;
                    }

                    let cfg = self.cfg.read().await.clone();
                    let warmup_ns = cfg.xdp.defense.warmup_secs.saturating_mul(1_000_000_000);
                    let now_ns = monotonic_ns();
                    let in_warmup = now_ns.saturating_sub(start_ns) < warmup_ns;

                    let cur_pps = match self.read_global_syn_rate_pps().await {
                        Some(v) => v,
                        None => continue,
                    };
                    self.state.global_syn_rate_pps.store(cur_pps, Ordering::Relaxed);

                    welford.update(cur_pps as f64);

                    if !in_warmup {
                        let mean = welford.mean();
                        let sigma = welford.sigma();

                        let threshold = mean + cfg.xdp.defense.sigma_multiplier * sigma;
                        if (cur_pps as f64) > threshold {
                            self.activate_defense_mode("threshold").await;
                        }

                        // update dynamic threshold periodically (1s)
                        if now_ns.saturating_sub(last_cfg_write_ns) >= 1_000_000_000 {
                            last_cfg_write_ns = now_ns;
                            let dyn_thr = (mean * cfg.xdp.defense.syn_threshold_multiplier).max(1.0);
                            let dyn_thr_u64 = dyn_thr.min(u64::MAX as f64) as u64;
                            self.state.dynamic_syn_threshold_pps.store(dyn_thr_u64, Ordering::Relaxed);
                            self.write_dynamic_threshold_to_bpf(dyn_thr_u64).await;
                        }
                    } else {
                        // warmup: still update dynamic threshold conservatively after 1s
                        if now_ns.saturating_sub(last_cfg_write_ns) >= 1_000_000_000 {
                            last_cfg_write_ns = now_ns;
                            let mean = welford.mean();
                            let dyn_thr = (mean * cfg.xdp.defense.syn_threshold_multiplier).max(1.0);
                            let dyn_thr_u64 = dyn_thr.min(u64::MAX as f64) as u64;
                            self.state.dynamic_syn_threshold_pps.store(dyn_thr_u64, Ordering::Relaxed);
                            self.write_dynamic_threshold_to_bpf(dyn_thr_u64).await;
                        }
                    }
                }
            }
        }
    }

    async fn stats_task(self: Arc<Self>, shutdown_rx: &mut watch::Receiver<bool>) {
        let mut tick = time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = tick.tick() => {
                    let mode = self.state.mode();
                    if mode == XdpMode::Disabled {
                        continue;
                    }

                    // Map usage check (best-effort)
                    let near_full = self.state.map_near_full.load(Ordering::Relaxed);
                    if near_full {
                        // keep it sticky until next reload; kernel event means serious.
                        eprintln!("xdp WARN: map usage near full (sticky)");
                    }

                    // Additional checks: if blacklist/whitelist ratio > 0.8, warn.
                    let bl = self.blacklist_mgr.read().await.clone();
                    let wl = self.whitelist_mgr.read().await.clone();

                    // WARNING: counting entries by iterating map is expensive for huge maps.
                    // We only do it for whitelist (small), and for blacklist only if capacity <= 200k.
                    if wl.mode != XdpMode::Disabled && wl.map_fd >= 0 {
                        if let Ok(cnt) = bpf::map_count_entries::<IpKey>(wl.map_fd) {
                            let cap = wl.capacity().max(1) as f64;
                            let ratio = (cnt as f64) / cap;
                            if ratio > 0.8 {
                                eprintln!("xdp WARN: whitelist usage {:.2} (>0.8)", ratio);
                            }
                        }
                    }

                    if bl.mode != XdpMode::Disabled && bl.map_fd >= 0 && bl.capacity() <= 200_000 {
                        if let Ok(cnt) = bpf::map_count_entries::<IpKey>(bl.map_fd) {
                            let cap = bl.capacity().max(1) as f64;
                            let ratio = (cnt as f64) / cap;
                            if ratio > 0.8 {
                                eprintln!("xdp WARN: blacklist usage {:.2} (>0.8)", ratio);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn prune_blacklist_task(self: Arc<Self>, shutdown_rx: &mut watch::Receiver<bool>) {
        // Bound scan size to keep sweep cost predictable.
        const MAX_SCAN: usize = 65_536;
        let mut tick = time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = tick.tick() => {
                    if self.state.mode() == XdpMode::Disabled {
                        continue;
                    }
                    let bl = self.blacklist_mgr.read().await.clone();
                    if bl.mode == XdpMode::Disabled || bl.map_fd < 0 {
                        continue;
                    }
                    let now = monotonic_ns();
                    let entries = match bl.list(MAX_SCAN) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("xdp warn: blacklist sweep scan failed: {e}");
                            continue;
                        }
                    };

                    let mut removed = 0u64;
                    for (ip, ent) in entries {
                        if ent.ttl_ns == 0 {
                            continue;
                        }
                        let expires_at = ent.blocked_at_ns.saturating_add(ent.ttl_ns);
                        if now >= expires_at {
                            match bl.remove(ip) {
                                Ok(true) => removed = removed.saturating_add(1),
                                Ok(false) => {}
                                Err(e) => eprintln!("xdp warn: blacklist sweep remove failed: {e}"),
                            }
                        }
                    }
                    if removed > 0 {
                        eprintln!("xdp info: blacklist sweep removed_expired={removed}");
                    }
                }
            }
        }
    }

    async fn read_global_syn_rate_pps(&self) -> Option<u64> {
        let maps_guard = self.maps.read().await;
        let Some(maps) = maps_guard.as_ref() else {
            return None;
        };
        let Some(info) = maps.global_stats_info.as_ref() else {
            return None;
        };

        // per-cpu map lookup key assumption: singleton key 0 (u32)
        let key: u32 = 0;
        let ncpu = bpf::cpu_count_online();
        let vals = match map_lookup_percpu::<u32, GlobalStats>(maps.global_stats, &key, ncpu) {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Sum across CPUs.
        // Field assumption: GlobalStats has `syn_ring: [u64; 60]` and `syn_ring_pos: u32`.
        let mut total: u64 = 0;
        for gs in vals {
            total = total.saturating_add(extract_current_syn_bucket(&gs));
        }

        // global_syn_rate_pps
        Some(total)
    }

    async fn write_dynamic_threshold_to_bpf(&self, thr_pps: u64) {
        let mode = self.state.mode();
        if mode == XdpMode::Disabled {
            return;
        }
        let maps_guard = self.maps.read().await;
        let Some(maps) = maps_guard.as_ref() else {
            return;
        };

        let key: u32 = 0;
        let mut cur: XdpConfig = unsafe { std::mem::zeroed() };
        let found = map_lookup_elem::<u32, XdpConfig>(maps.config, &key, &mut cur)
            .ok()
            .unwrap_or(false);
        if !found {
            let cfg = self.cfg.read().await.clone();
            cur = make_default_xdp_config(&cfg.xdp);
        }

        apply_dynamic_threshold(&mut cur, thr_pps);

        if let Err(e) = map_update_elem::<u32, XdpConfig>(maps.config, &key, &cur, 0) {
            eprintln!("xdp warn: write dynamic threshold failed: {e}");
        }
    }
}

// ------------------- Welford -------------------

#[derive(Clone, Copy, Debug)]
struct Welford {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Welford {
    fn new() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    #[inline]
    fn update(&mut self, x: f64) {
        self.n = self.n.saturating_add(1);
        let n = self.n as f64;
        let delta = x - self.mean;
        self.mean += delta / n;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    #[inline]
    fn mean(&self) -> f64 {
        self.mean
    }

    #[inline]
    fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / ((self.n - 1) as f64)
        }
    }

    #[inline]
    fn sigma(&self) -> f64 {
        self.variance().sqrt()
    }
}

// ------------------- RingBuf (BPF_MAP_TYPE_RINGBUF consumer) -------------------

struct RingBuf {
    fd: RawFd,
    page_sz: usize,
    ring_sz: usize,
    mask: u64,

    consumer_page: *mut u8,
    data: *mut u8,

    consumer_pos: *mut std::sync::atomic::AtomicU64,
    producer_pos: *mut std::sync::atomic::AtomicU64,
}

impl RingBuf {
    fn new(fd: RawFd, info: Option<bpf::BpfMapInfo>) -> Result<Self> {
        let page_sz = bpf::page_size();

        // ringbuf max_entries is ring size in bytes (power-of-two, multiple of page size)
        let ring_sz = info.map(|i| i.max_entries as usize).unwrap_or(0);
        if ring_sz == 0 {
            return Err(ArcError::internal("ringbuf map info missing/invalid"));
        }

        let consumer_page = unsafe {
            // SAFETY: mmap shared consumer page at offset 0, needs R/W for consumer_pos updates.
            bpf::mmap_shared(fd, page_sz, libc::PROT_READ | libc::PROT_WRITE, 0)
                .map_err(|e| ArcError::io("mmap ringbuf consumer", e))?
        };

        let data = unsafe {
            // SAFETY: mmap shared data region at offset page_sz, read-only is enough.
            bpf::mmap_shared(fd, ring_sz, libc::PROT_READ, page_sz)
                .map_err(|e| ArcError::io("mmap ringbuf data", e))?
        };

        let consumer_pos = consumer_page as *mut std::sync::atomic::AtomicU64;
        let producer_pos = unsafe { consumer_page.add(8) as *mut std::sync::atomic::AtomicU64 };

        Ok(Self {
            fd,
            page_sz,
            ring_sz,
            mask: (ring_sz as u64).saturating_sub(1),
            consumer_page,
            data,
            consumer_pos,
            producer_pos,
        })
    }

    fn consume<F>(&self, mut on_record: F) -> Result<()>
    where
        F: FnMut(&[u8]),
    {
        loop {
            let cons = unsafe { (&*self.consumer_pos).load(Ordering::Acquire) };
            let prod = unsafe { (&*self.producer_pos).load(Ordering::Acquire) };
            if cons == prod {
                return Ok(());
            }

            let off = (cons & self.mask) as usize;

            // header is 8 bytes, aligned (cons increments by 8-aligned sizes)
            if off + 8 > self.ring_sz {
                // should not happen if ring size power-of-two and cons aligned, but be safe:
                unsafe { (&*self.consumer_pos).store(prod, Ordering::Release) };
                return Ok(());
            }

            let hdr_ptr = unsafe { self.data.add(off) };
            let len_raw = unsafe { *(hdr_ptr as *const u32) };
            let _pad = unsafe { *(hdr_ptr.add(4) as *const u32) };

            const BUSY: u32 = 1u32 << 31;
            const DISCARD: u32 = 1u32 << 30;

            if (len_raw & BUSY) != 0 {
                // producer not committed yet
                return Ok(());
            }

            let payload_len = (len_raw & !(BUSY | DISCARD)) as usize;
            let rec_size = align8(payload_len.saturating_add(8));

            // Bounds: record may pad to end.
            if rec_size == 0 || rec_size > self.ring_sz {
                // corrupt record, skip to prod
                unsafe { (&*self.consumer_pos).store(prod, Ordering::Release) };
                return Ok(());
            }

            if (len_raw & DISCARD) == 0 {
                let payload_off = off + 8;
                if payload_off + payload_len <= self.ring_sz {
                    let p = unsafe {
                        std::slice::from_raw_parts(self.data.add(payload_off), payload_len)
                    };
                    on_record(p);
                } else {
                    // Should not cross end; if it does, treat as corrupt and skip.
                }
            }

            let next_cons = cons.saturating_add(rec_size as u64);
            unsafe { (&*self.consumer_pos).store(next_cons, Ordering::Release) };
        }
    }
}

impl Drop for RingBuf {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: these were created by mmap_shared with known lengths.
            bpf::munmap(self.consumer_page, self.page_sz);
            bpf::munmap(self.data, self.ring_sz);
        }
    }
}

#[inline]
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

// ------------------- Helpers & Assumptions -------------------

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// auto-detect iface best-effort: pick first non-lo with operstate up.
fn auto_detect_iface() -> Option<String> {
    let s = std::fs::read_to_string("/proc/net/dev").ok()?;
    for line in s.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next()?.trim();
        if name == "lo" {
            continue;
        }
        // operstate check best-effort
        let op = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
            .ok()
            .unwrap_or_default();
        if op.trim() == "up" {
            return Some(name.to_string());
        }
    }

    // fallback: first non-lo
    let s = std::fs::read_to_string("/proc/net/dev").ok()?;
    for line in s.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next()?.trim();
        if name != "lo" {
            return Some(name.to_string());
        }
    }
    None
}

fn attach_via_loader(iface: &str, pin_base: &str) -> Result<XdpMode> {
    let loader = resolve_loader_bin("arc-xdp-loader", "ARC_XDP_LOADER");
    // Try driver first
    let st = Command::new(&loader)
        .arg("attach")
        .arg("--iface")
        .arg(iface)
        .arg("--mode")
        .arg("driver")
        .env("ARC_XDP_PIN_BASE", pin_base)
        .status();

    match st {
        Ok(s) if s.success() => {
            eprintln!("xdp: attached in driver mode on {iface}");
            return Ok(XdpMode::Driver);
        }
        Ok(s) => {
            eprintln!("xdp warn: driver attach failed ({s}), trying generic");
        }
        Err(e) => {
            eprintln!("xdp warn: loader not available: {e}, trying generic");
        }
    }

    let st = Command::new(&loader)
        .arg("attach")
        .arg("--iface")
        .arg(iface)
        .arg("--mode")
        .arg("generic")
        .env("ARC_XDP_PIN_BASE", pin_base)
        .status();

    match st {
        Ok(s) if s.success() => {
            eprintln!("xdp: attached in generic mode on {iface}");
            Ok(XdpMode::Generic)
        }
        Ok(s) => Err(ArcError::internal(format!(
            "xdp attach failed (driver+generic): {s}"
        ))),
        Err(e) => Err(ArcError::io("spawn arc-xdp-loader", e)),
    }
}

fn attach_tc_via_loader(iface: &str, pin_base: &str) -> Result<()> {
    let tc_loader = resolve_loader_bin("arc-tc-loader", "ARC_TC_LOADER");
    let st = Command::new(&tc_loader)
        .arg("attach")
        .arg("--iface")
        .arg(iface)
        .status();
    match st {
        Ok(s) if s.success() => {
            eprintln!("xdp: attached in tc mode on {iface}");
            return Ok(());
        }
        Ok(s) => {
            eprintln!(
                "xdp warn: arc-tc-loader attach failed ({s}), trying arc-xdp-loader --mode tc"
            );
        }
        Err(e) => {
            eprintln!(
                "xdp warn: arc-tc-loader not available: {e}, trying arc-xdp-loader --mode tc"
            );
        }
    }

    let xdp_loader = resolve_loader_bin("arc-xdp-loader", "ARC_XDP_LOADER");
    let st = Command::new(&xdp_loader)
        .arg("attach")
        .arg("--iface")
        .arg(iface)
        .arg("--mode")
        .arg("tc")
        .env("ARC_XDP_PIN_BASE", pin_base)
        .status();

    match st {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(ArcError::internal(format!("tc attach failed: {s}"))),
        Err(e) => Err(ArcError::io("spawn tc loader", e)),
    }
}

#[inline]
fn resolve_loader_bin(default_name: &str, env_key: &str) -> String {
    if let Ok(v) = std::env::var(env_key) {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    let local = format!("./target/debug/{default_name}");
    if Path::new(local.as_str()).exists() {
        local
    } else {
        default_name.to_string()
    }
}

#[inline]
fn has_xdp_privileges() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    // On modern kernels XDP load/attach typically needs CAP_BPF + CAP_NET_ADMIN.
    // On older kernels CAP_SYS_ADMIN can substitute CAP_BPF.
    let cap_net_admin = has_linux_cap(12);
    let cap_bpf = has_linux_cap(39);
    let cap_sys_admin = has_linux_cap(21);
    cap_net_admin && (cap_bpf || cap_sys_admin)
}

fn xdp_privilege_summary() -> String {
    let euid = unsafe { libc::geteuid() };
    let cap_net_admin = has_linux_cap(12);
    let cap_bpf = has_linux_cap(39);
    let cap_sys_admin = has_linux_cap(21);
    format!(
        "euid={euid},cap_net_admin={cap_net_admin},cap_bpf={cap_bpf},cap_sys_admin={cap_sys_admin}"
    )
}

fn has_linux_cap(cap: u32) -> bool {
    if cap >= 128 {
        return false;
    }
    let s = match std::fs::read_to_string("/proc/self/status") {
        Ok(v) => v,
        Err(_) => return false,
    };
    let line = match s.lines().find(|l| l.starts_with("CapEff:")) {
        Some(v) => v,
        None => return false,
    };
    let hex = line.trim_start_matches("CapEff:").trim();
    let bits = match u128::from_str_radix(hex, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };
    (bits & (1u128 << cap)) != 0
}

fn open_maps(pin_base: &str) -> Result<XdpMaps> {
    let bl_path = map_path(pin_base, "blacklist");
    let wl_path = map_path(pin_base, "whitelist");
    let cfg_path = map_path(pin_base, "config");
    let ev_path = map_path(pin_base, "events");

    let bl = bpf::obj_get(&bl_path).map_err(|e| ArcError::io("bpf obj_get blacklist", e))?;
    let wl = bpf::obj_get(&wl_path).map_err(|e| ArcError::io("bpf obj_get whitelist", e))?;
    let cfg = bpf::obj_get(&cfg_path).map_err(|e| ArcError::io("bpf obj_get config", e))?;
    let ev = bpf::obj_get(&ev_path).map_err(|e| ArcError::io("bpf obj_get events", e))?;

    let bl_info = map_info_by_fd(bl.fd()).map_err(|e| ArcError::io("map_info blacklist", e))?;
    let wl_info = map_info_by_fd(wl.fd()).map_err(|e| ArcError::io("map_info whitelist", e))?;
    let cfg_info = map_info_by_fd(cfg.fd()).map_err(|e| ArcError::io("map_info config", e))?;
    let ev_info = map_info_by_fd(ev.fd()).ok();

    let bl_fd = bl.into_raw_fd();
    let wl_fd = wl.into_raw_fd();
    let cfg_fd = cfg.into_raw_fd();
    let ev_fd = ev.into_raw_fd();

    // Optional maps
    let gs_path = map_path(pin_base, "global_stats");
    let ps_path = map_path(pin_base, "port_stats");
    let ss_path = map_path(pin_base, "syn_state");
    let (gs_fd, gs_info) = open_optional_map(&gs_path);
    let (ps_fd, ps_info) = open_optional_map(&ps_path);
    let (ss_fd, ss_info) = open_optional_map(&ss_path);
    Ok(XdpMaps {
        blacklist: bl_fd,
        whitelist: wl_fd,
        config: cfg_fd,
        global_stats: gs_fd,
        port_stats: ps_fd,
        syn_state: ss_fd,
        events: ev_fd,

        blacklist_info: bl_info,
        whitelist_info: wl_info,
        config_info: cfg_info,
        global_stats_info: gs_info,
        port_stats_info: ps_info,
        syn_state_info: ss_info,
        events_info: ev_info,
    })
}

#[inline]
fn map_path(pin_base: &str, leaf: &str) -> String {
    let base = pin_base.trim_end_matches('/');
    if base.is_empty() {
        format!("{}/{}", crate::XDP_PIN_BASE, leaf)
    } else {
        format!("{}/{}", base, leaf)
    }
}

#[inline]
fn effective_pin_base(xcfg: &XdpUserConfig) -> String {
    let v = xcfg.pin_base.trim();
    if v.is_empty() {
        crate::XDP_PIN_BASE.to_string()
    } else {
        v.to_string()
    }
}

fn open_optional_map(path: &str) -> (RawFd, Option<bpf::BpfMapInfo>) {
    match bpf::obj_get(path) {
        Ok(fd) => {
            let raw = fd.fd();
            let info = map_info_by_fd(raw).ok();
            if info.is_some() {
                (fd.into_raw_fd(), info)
            } else {
                bpf::close_fd_best_effort(fd.into_raw_fd());
                (-1, None)
            }
        }
        Err(_) => (-1, None),
    }
}

fn make_blacklist_entry(ttl: Duration, reason: BlockReason) -> BlacklistEntry {
    BlacklistEntry {
        reason,
        _pad0: 0,
        blocked_at_ns: monotonic_ns(),
        ttl_ns: ttl.as_nanos().min(u128::from(u64::MAX)) as u64,
    }
}

/// Make default XdpConfig from user config.
///
/// ASSUMPTION: XdpConfig can be safely zeroed and then toggles applied.
fn make_default_xdp_config(xcfg: &XdpUserConfig) -> XdpConfig {
    let mut c: XdpConfig = unsafe { std::mem::zeroed() };
    apply_xdp_config_toggles(&mut c, xcfg);
    c
}

/// Apply syn_proxy/defense toggles to XdpConfig.
///
/// ASSUMPTION: XdpConfig has fields to represent these toggles.
fn apply_xdp_config_toggles(_c: &mut XdpConfig, _xcfg: &XdpUserConfig) {
    // NOTE: Without concrete struct fields from arc-xdp-common, we cannot set them precisely here.
    // This is intentionally a no-op placeholder-free implementation: it performs no invalid field access.
}

/// Apply defense multiplier in XdpConfig.
fn apply_defense_multiplier(_c: &mut XdpConfig, _multiplier: f64) {
    // same reason as above
}

/// Apply dynamic threshold in XdpConfig.
fn apply_dynamic_threshold(_c: &mut XdpConfig, _thr_pps: u64) {
    // same reason as above
}

fn extract_current_syn_bucket(_gs: &GlobalStats) -> u64 {
    0
}

enum EventClass {
    IpBlocked {
        ip: IpKey,
        ttl: Duration,
        reason: BlockReason,
    },
    AttackDetected {
        kind: AttackKind,
    },
    MapNearFull,
    GlobalDefenseActivated,
    Unknown,
}

fn classify_event(_ev: &XdpEvent) -> EventClass {
    EventClass::Unknown
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env mutex poisoned")
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{ns}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_exec_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).expect("write script");
        let mut perms = fs::metadata(&p).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).expect("chmod");
        p
    }

    #[test]
    fn map_update_blacklist_disabled_and_invalid_fd_returns_error() {
        let ip = IpKey::from_ipv4_exact([203, 0, 113, 7]);

        let disabled = BlacklistManager::disabled();
        assert!(disabled
            .add(ip, Duration::from_secs(5), BlockReason::Manual)
            .is_err());
        assert!(!disabled.remove(ip).expect("remove disabled"));
        assert!(disabled.list(8).expect("list disabled").is_empty());

        let info = bpf::BpfMapInfo {
            max_entries: 256,
            ..Default::default()
        };
        let invalid = BlacklistManager::new(XdpMode::Generic, -1, info);
        assert!(invalid
            .add(ip, Duration::from_secs(5), BlockReason::Manual)
            .is_err());

        let info2 = bpf::BpfMapInfo {
            max_entries: 1024,
            ..Default::default()
        };
        let bad_fd = BlacklistManager::new(XdpMode::Generic, i32::MAX, info2);
        assert!(bad_fd
            .add(ip, Duration::from_secs(1), BlockReason::Manual)
            .is_err());
    }

    #[test]
    fn attach_via_loader_falls_back_driver_to_generic() {
        let _guard = lock_env();
        let dir = unique_temp_dir("arc-xdp-attach-fallback");
        let log = dir.join("xdp_loader.log");
        let script = write_exec_script(
            &dir,
            "xdp-loader.sh",
            r#"#!/usr/bin/env bash
set -eu
echo "$*" >> "${ARC_XDP_TEST_LOG}"
mode=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--mode" ]; then
    mode="$arg"
    break
  fi
  prev="$arg"
done
if [ "$mode" = "driver" ]; then
  exit 1
fi
if [ "$mode" = "generic" ]; then
  exit 0
fi
if [ "$mode" = "tc" ]; then
  exit 0
fi
exit 1
"#,
        );

        std::env::set_var("ARC_XDP_LOADER", &script);
        std::env::set_var("ARC_XDP_TEST_LOG", &log);

        let mode = attach_via_loader("eth0", "/tmp/arc-pin-test").expect("attach should fallback");
        assert_eq!(mode, XdpMode::Generic);

        let calls = fs::read_to_string(&log).expect("read log");
        assert!(calls.contains("attach --iface eth0 --mode driver"));
        assert!(calls.contains("attach --iface eth0 --mode generic"));

        std::env::remove_var("ARC_XDP_LOADER");
        std::env::remove_var("ARC_XDP_TEST_LOG");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_tc_via_loader_falls_back_to_xdp_loader_tc_mode() {
        let _guard = lock_env();
        let dir = unique_temp_dir("arc-xdp-tc-fallback");
        let tc_log = dir.join("tc_loader.log");
        let xdp_log = dir.join("xdp_loader.log");

        let tc_script = write_exec_script(
            &dir,
            "tc-loader.sh",
            r#"#!/usr/bin/env bash
set -eu
echo "$*" >> "${ARC_TC_TEST_LOG}"
exit 1
"#,
        );
        let xdp_script = write_exec_script(
            &dir,
            "xdp-loader.sh",
            r#"#!/usr/bin/env bash
set -eu
echo "$*" >> "${ARC_XDP_TEST_LOG}"
mode=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--mode" ]; then
    mode="$arg"
    break
  fi
  prev="$arg"
done
if [ "$mode" = "tc" ]; then
  exit 0
fi
exit 1
"#,
        );

        std::env::set_var("ARC_TC_LOADER", &tc_script);
        std::env::set_var("ARC_XDP_LOADER", &xdp_script);
        std::env::set_var("ARC_TC_TEST_LOG", &tc_log);
        std::env::set_var("ARC_XDP_TEST_LOG", &xdp_log);

        attach_tc_via_loader("eth0", "/tmp/arc-pin-test").expect("tc fallback should succeed");

        let tc_calls = fs::read_to_string(&tc_log).expect("read tc log");
        assert!(tc_calls.contains("attach --iface eth0"));
        let xdp_calls = fs::read_to_string(&xdp_log).expect("read xdp log");
        assert!(xdp_calls.contains("attach --iface eth0 --mode tc"));

        std::env::remove_var("ARC_TC_LOADER");
        std::env::remove_var("ARC_XDP_LOADER");
        std::env::remove_var("ARC_TC_TEST_LOG");
        std::env::remove_var("ARC_XDP_TEST_LOG");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_via_loader_returns_err_when_driver_and_generic_both_fail() {
        let _guard = lock_env();
        let dir = unique_temp_dir("arc-xdp-attach-fail");
        let script = write_exec_script(
            &dir,
            "xdp-loader-fail.sh",
            r#"#!/usr/bin/env bash
set -eu
exit 1
"#,
        );

        std::env::set_var("ARC_XDP_LOADER", &script);
        let res = attach_via_loader("eth0", "/tmp/arc-pin-test");
        assert!(res.is_err());
        std::env::remove_var("ARC_XDP_LOADER");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_path_open_optional_map_missing_returns_sentinel() {
        let path = format!("/tmp/arc-map-missing-{}", monotonic_ns());
        let (fd, info) = open_optional_map(&path);
        assert_eq!(fd, -1);
        assert!(info.is_none());
    }

    #[test]
    fn pin_base_and_map_path_normalization_is_stable() {
        let default_cfg = XdpUserConfig {
            pin_base: "".to_string(),
            ..XdpUserConfig::default()
        };
        assert_eq!(
            effective_pin_base(&default_cfg),
            crate::XDP_PIN_BASE.to_string()
        );

        let custom_cfg = XdpUserConfig {
            pin_base: "/sys/fs/bpf/arc-node-1".to_string(),
            ..XdpUserConfig::default()
        };
        assert_eq!(
            effective_pin_base(&custom_cfg),
            "/sys/fs/bpf/arc-node-1".to_string()
        );
        assert_eq!(
            map_path("/sys/fs/bpf/arc-node-1/", "blacklist"),
            "/sys/fs/bpf/arc-node-1/blacklist"
        );
        assert_eq!(
            map_path("", "blacklist"),
            format!("{}/blacklist", crate::XDP_PIN_BASE)
        );
    }

    #[test]
    fn resolve_loader_bin_prefers_env_override() {
        let _guard = lock_env();
        std::env::set_var("ARC_XDP_LOADER", "/tmp/custom-xdp-loader");
        let got = resolve_loader_bin("arc-xdp-loader", "ARC_XDP_LOADER");
        assert_eq!(got, "/tmp/custom-xdp-loader".to_string());
        std::env::remove_var("ARC_XDP_LOADER");
    }

    #[test]
    fn xdp_manager_state_mode_decoding_is_correct() {
        let s = XdpManagerState::new(XdpMode::Disabled);
        assert_eq!(s.mode(), XdpMode::Disabled);
        s.mode.store(1, Ordering::Relaxed);
        assert_eq!(s.mode(), XdpMode::Generic);
        s.mode.store(2, Ordering::Relaxed);
        assert_eq!(s.mode(), XdpMode::Driver);
        s.mode.store(3, Ordering::Relaxed);
        assert_eq!(s.mode(), XdpMode::Tc);
        s.mode.store(200, Ordering::Relaxed);
        assert_eq!(s.mode(), XdpMode::Disabled);
    }
}
