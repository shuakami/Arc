#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::{BuildHasherDefault, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{self, Instant};

pub const DEFAULT_REDIS_BUDGET_MS: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub rps: u64,
    pub burst: u64,
}

impl Policy {
    #[inline]
    pub const fn new(rps: u64, burst: u64) -> Self {
        Self { rps, burst }
    }
}

#[derive(Clone, Debug)]
pub struct GlobalRateLimiterConfig {
    pub namespace: Arc<str>,

    /// Low-watermark under which the worker schedules a refill.
    pub low_watermark: u32,

    /// Refill request size (token lease batch).
    pub prefetch: u32,

    /// Redis/L2 strict budget (circuit breaker trips when exceeded).
    pub redis_budget: Duration,

    /// Circuit open duration after an error/timeout.
    pub circuit_open: Duration,

    /// Refill retry backoff when backend grants 0 tokens (or errors).
    pub refill_backoff: Duration,

    /// Max in-flight refill requests in the global channel.
    pub channel_capacity: usize,

    /// L1 cache limits (per worker).
    pub l1_max_entries: usize,
    pub l1_idle_ttl: Duration,
}

impl Default for GlobalRateLimiterConfig {
    fn default() -> Self {
        Self {
            namespace: Arc::from("arc:rl"),
            low_watermark: 16,
            prefetch: 128,
            redis_budget: Duration::from_millis(DEFAULT_REDIS_BUDGET_MS),
            circuit_open: Duration::from_millis(500),
            refill_backoff: Duration::from_millis(1),
            channel_capacity: 65_536,
            l1_max_entries: 200_000,
            l1_idle_ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Default)]
pub struct RateLimitMetrics {
    pub rate_limit_redis_latency_us_sum: AtomicU64,
    pub rate_limit_redis_latency_us_count: AtomicU64,
    pub rate_limit_fallback_triggered: AtomicU64,
    pub rate_limit_backend_timeouts: AtomicU64,
    pub rate_limit_backend_errors: AtomicU64,
    pub rate_limit_circuit_opened: AtomicU64,
}

impl RateLimitMetrics {
    #[inline]
    fn record_redis_latency(&self, us: u64) {
        self.rate_limit_redis_latency_us_sum
            .fetch_add(us, Ordering::Relaxed);
        self.rate_limit_redis_latency_us_count
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct CircuitBreaker {
    open_until_ns: AtomicU64,
    ever_healthy: AtomicBool,
}

impl CircuitBreaker {
    #[inline]
    fn is_open(&self, now_ns: u64) -> bool {
        let until = self.open_until_ns.load(Ordering::Relaxed);
        now_ns < until
    }

    #[inline]
    fn on_success(&self, now_ns: u64) {
        let _ = now_ns;
        self.ever_healthy.store(true, Ordering::Relaxed);
        self.open_until_ns.store(0, Ordering::Relaxed);
    }

    #[inline]
    fn on_failure(&self, now_ns: u64, open_for: Duration) {
        let until = now_ns.saturating_add(open_for.as_nanos() as u64);
        self.ever_healthy.store(false, Ordering::Relaxed);
        self.open_until_ns.store(until, Ordering::Relaxed);
    }

    #[inline]
    fn ever_healthy(&self) -> bool {
        self.ever_healthy.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub enum BackendError {
    Timeout,
    Disconnected,
    Protocol(&'static str),
    Other(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Timeout => write!(f, "timeout"),
            BackendError::Disconnected => write!(f, "disconnected"),
            BackendError::Protocol(s) => write!(f, "protocol error: {s}"),
            BackendError::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for BackendError {}

pub struct ReserveRequest {
    pub namespace: Arc<str>,
    pub key: u64,
    pub policy: Policy,
    pub want: u32,
    pub now_ms: u64,
    pub ttl_ms: u64,
}

pub trait RateLimiterBackend: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn reserve<'a>(
        &'a self,
        req: ReserveRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u32, BackendError>> + Send + 'a>>;

    fn ping<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), BackendError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone)]
pub struct GlobalRateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: GlobalRateLimiterConfig,
    metrics: RateLimitMetrics,
    circuit: CircuitBreaker,

    refill_tx: mpsc::Sender<RefillRequest>,
    worker_txs: Vec<mpsc::Sender<RefillResponse>>,
}

#[derive(Debug, Clone)]
struct RefillRequest {
    wid: usize,
    key: u64,
    policy: Policy,
    want: u32,
    ttl_ms: u64,
}

#[derive(Debug, Clone)]
struct RefillResponse {
    key: u64,
    granted: u32,
}

pub struct WorkerLimiter {
    wid: usize,
    inner: Arc<Inner>,
    rx: mpsc::Receiver<RefillResponse>,

    // Per-worker L1 state (sharded by worker => no locks).
    l1: HashMap<u64, Entry, BuildHasherDefault<IdentityU64Hasher>>,
    ops: u64,
    last_eviction_ns: u64,
}

#[derive(Clone, Copy)]
struct IdentityU64Hasher(u64);

impl Default for IdentityU64Hasher {
    #[inline]
    fn default() -> Self {
        Self(0)
    }
}

impl Hasher for IdentityU64Hasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Fallback for unexpected types; not used in our u64-key map.
        // Very small FNV-like folding.
        let mut h = 14695981039346656037u64;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211u64);
        }
        self.0 = h;
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone)]
struct Entry {
    policy: Policy,

    // L1 local token bucket state
    local_tokens: u64,
    local_last_ns: u64,

    // Global lease tokens (granted by backend)
    global_tokens: u32,
    has_global_lease: bool,
    refill_in_flight: bool,
    refill_cooldown_until_ns: u64,

    // eviction bookkeeping
    last_seen_ns: u64,
}

impl Entry {
    #[inline]
    fn new(policy: Policy, now_ns: u64) -> Self {
        Self {
            policy,
            local_tokens: policy.burst,
            local_last_ns: now_ns,
            global_tokens: 0,
            has_global_lease: false,
            refill_in_flight: false,
            refill_cooldown_until_ns: 0,
            last_seen_ns: now_ns,
        }
    }

    #[inline]
    fn reset_policy(&mut self, policy: Policy, now_ns: u64) {
        self.policy = policy;
        self.local_tokens = policy.burst;
        self.local_last_ns = now_ns;
        self.global_tokens = 0;
        self.has_global_lease = false;
        self.refill_in_flight = false;
        self.refill_cooldown_until_ns = 0;
        self.last_seen_ns = now_ns;
    }

    #[inline]
    fn local_refill(&mut self, now_ns: u64) {
        if now_ns <= self.local_last_ns {
            return;
        }
        let elapsed_ns = now_ns - self.local_last_ns;
        self.local_last_ns = now_ns;

        // add = elapsed * rps / 1e9
        // Use u128 to avoid overflow; hot path but arithmetic is tiny and predictable.
        let add = ((elapsed_ns as u128) * (self.policy.rps as u128) / 1_000_000_000u128) as u64;
        if add == 0 {
            return;
        }
        let new_tokens = self.local_tokens.saturating_add(add);
        self.local_tokens = new_tokens.min(self.policy.burst);
    }

    #[inline]
    fn local_try_take(&mut self, now_ns: u64, cost: u64) -> bool {
        self.local_refill(now_ns);
        if self.local_tokens >= cost {
            self.local_tokens -= cost;
            true
        } else {
            false
        }
    }
}

impl GlobalRateLimiter {
    /// Spawns the backend runtime on a dedicated thread, returns:
    /// - `GlobalRateLimiter` (for metrics & cloning)
    /// - `Vec<WorkerLimiter>` (one per worker thread)
    pub fn spawn(
        backend: Arc<dyn RateLimiterBackend>,
        workers: usize,
        cfg: GlobalRateLimiterConfig,
    ) -> (Self, Vec<WorkerLimiter>) {
        let (refill_tx, refill_rx) = mpsc::channel::<RefillRequest>(cfg.channel_capacity);

        let mut worker_txs = Vec::with_capacity(workers);
        let mut worker_rxs = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::channel::<RefillResponse>(cfg.channel_capacity / 4 + 64);
            worker_txs.push(tx);
            worker_rxs.push(rx);
        }

        let inner = Arc::new(Inner {
            cfg,
            metrics: RateLimitMetrics::default(),
            circuit: CircuitBreaker::default(),
            refill_tx,
            worker_txs,
        });

        let inner_for_thread = inner.clone();
        std::thread::Builder::new()
            .name("arc-rl-backend".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .max_blocking_threads(1)
                    .enable_io()
                    .enable_time()
                    .thread_name("arc-rl-rt")
                    .build();

                let rt = match rt {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("rate limiter backend runtime build failed: {e}");
                        return;
                    }
                };

                rt.block_on(async move {
                    backend_loop(inner_for_thread, backend, refill_rx).await;
                });
            })
            .expect("spawn arc-rl-backend thread");

        let mut handles = Vec::with_capacity(workers);
        for wid in 0..workers {
            let rx = worker_rxs.remove(0);
            handles.push(WorkerLimiter {
                wid,
                inner: inner.clone(),
                rx,
                l1: HashMap::with_capacity_and_hasher(
                    1024,
                    BuildHasherDefault::<IdentityU64Hasher>::default(),
                ),
                ops: 0,
                last_eviction_ns: 0,
            });
        }

        (Self { inner }, handles)
    }

    pub fn metrics(&self) -> &RateLimitMetrics {
        &self.inner.metrics
    }
}

async fn backend_loop(
    inner: Arc<Inner>,
    backend: Arc<dyn RateLimiterBackend>,
    mut rx: mpsc::Receiver<RefillRequest>,
) {
    let mut batch: Vec<RefillRequest> = Vec::with_capacity(256);

    loop {
        let first = match rx.recv().await {
            Some(v) => v,
            None => break,
        };
        batch.clear();
        batch.push(first);

        while batch.len() < 256 {
            match rx.try_recv() {
                Ok(v) => batch.push(v),
                Err(_) => break,
            }
        }

        // If circuit is open, don't even attempt backend I/O; workers are falling back.
        let now_ns = monotonic_ns();
        if inner.circuit.is_open(now_ns) {
            inner
                .metrics
                .rate_limit_fallback_triggered
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            // Drain requests and notify workers to clear refill_in_flight.
            for req in batch.iter() {
                if let Some(tx) = inner.worker_txs.get(req.wid) {
                    let _ = tx.try_send(RefillResponse {
                        key: req.key,
                        granted: 0,
                    });
                }
            }
            continue;
        }

        for req in batch.iter() {
            let reserve = ReserveRequest {
                namespace: inner.cfg.namespace.clone(),
                key: req.key,
                policy: req.policy,
                want: req.want,
                now_ms: epoch_ms(),
                ttl_ms: req.ttl_ms,
            };

            let started = Instant::now();
            let fut = backend.reserve(reserve);
            let result = time::timeout(inner.cfg.redis_budget, fut).await;

            match result {
                Ok(Ok(granted)) => {
                    let us = started.elapsed().as_micros() as u64;
                    inner.metrics.record_redis_latency(us);
                    inner.circuit.on_success(now_ns);

                    if let Some(tx) = inner.worker_txs.get(req.wid) {
                        let _ = tx.try_send(RefillResponse {
                            key: req.key,
                            granted,
                        });
                    }
                }
                Ok(Err(_e)) => {
                    inner
                        .metrics
                        .rate_limit_backend_errors
                        .fetch_add(1, Ordering::Relaxed);
                    inner
                        .metrics
                        .rate_limit_circuit_opened
                        .fetch_add(1, Ordering::Relaxed);
                    inner.circuit.on_failure(now_ns, inner.cfg.circuit_open);
                    inner
                        .metrics
                        .rate_limit_fallback_triggered
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(tx) = inner.worker_txs.get(req.wid) {
                        let _ = tx.try_send(RefillResponse {
                            key: req.key,
                            granted: 0,
                        });
                    }
                }
                Err(_) => {
                    inner
                        .metrics
                        .rate_limit_backend_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                    inner
                        .metrics
                        .rate_limit_circuit_opened
                        .fetch_add(1, Ordering::Relaxed);
                    inner.circuit.on_failure(now_ns, inner.cfg.circuit_open);
                    inner
                        .metrics
                        .rate_limit_fallback_triggered
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(tx) = inner.worker_txs.get(req.wid) {
                        let _ = tx.try_send(RefillResponse {
                            key: req.key,
                            granted: 0,
                        });
                    }
                }
            }
        }
    }
}

impl WorkerLimiter {
    #[inline]
    pub fn try_acquire(&mut self, key: u64, policy: Policy, now_ns: u64) -> bool {
        self.drain_responses(8);

        let mut schedule_refill = false;
        let mut do_evict = false;

        let decision = {
            let entry = self
                .l1
                .entry(key)
                .or_insert_with(|| Entry::new(policy, now_ns));
            if entry.policy != policy {
                entry.reset_policy(policy, now_ns);
            }
            entry.last_seen_ns = now_ns;

            // If backend never healthy OR circuit open => local-only fallback.
            // Still schedule refill attempts so backend can bootstrap/recover.
            if !self.inner.circuit.ever_healthy() || self.inner.circuit.is_open(now_ns) {
                self.inner
                    .metrics
                    .rate_limit_fallback_triggered
                    .fetch_add(1, Ordering::Relaxed);
                schedule_refill = true;
                do_evict = true;
                entry.local_try_take(now_ns, 1)
            } else {
                // Healthy path: enforce ONLY global lease.
                // Local bucket is fallback-only; double-enforcing both global+local
                // causes significant under-admission at high request rates.
                if entry.global_tokens == 0 {
                    schedule_refill = true;
                    // Cold-start safeguard: before the key gets its first global lease,
                    // allow key-local bucket to avoid false 429 under refill latency/jitter.
                    if !entry.has_global_lease {
                        do_evict = true;
                        entry.local_try_take(now_ns, 1)
                    } else {
                        false
                    }
                } else {
                    entry.global_tokens -= 1;
                    if entry.global_tokens <= self.inner.cfg.low_watermark {
                        schedule_refill = true;
                    }
                    do_evict = true;
                    true
                }
            }
        };

        if schedule_refill {
            self.maybe_schedule_refill_by_key(key, now_ns);
        }
        if do_evict {
            self.maybe_evict(now_ns);
        }
        decision
    }

    #[inline]
    fn drain_responses(&mut self, max: usize) {
        for _ in 0..max {
            match self.rx.try_recv() {
                Ok(r) => {
                    if let Some(e) = self.l1.get_mut(&r.key) {
                        if r.granted > 0 {
                            e.has_global_lease = true;
                        }
                        e.global_tokens = e.global_tokens.saturating_add(r.granted);
                        e.refill_in_flight = false;
                        // If granted=0, set a tiny cooldown to avoid hot-looping refills.
                        if r.granted == 0 {
                            let backoff_ns = self
                                .inner
                                .cfg
                                .refill_backoff
                                .as_nanos()
                                .min(u128::from(u64::MAX))
                                as u64;
                            e.refill_cooldown_until_ns = e
                                .refill_cooldown_until_ns
                                .max(e.last_seen_ns.saturating_add(backoff_ns));
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }

    #[inline]
    fn maybe_schedule_refill_by_key(&mut self, key: u64, now_ns: u64) {
        let Some(entry) = self.l1.get_mut(&key) else {
            return;
        };

        if entry.refill_in_flight {
            return;
        }
        if now_ns < entry.refill_cooldown_until_ns {
            return;
        }

        entry.refill_in_flight = true;

        let req = RefillRequest {
            wid: self.wid,
            key,
            policy: entry.policy,
            want: self.inner.cfg.prefetch.max(1),
            ttl_ms: self
                .inner
                .cfg
                .l1_idle_ttl
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        };

        if self.inner.refill_tx.try_send(req).is_err() {
            // Channel saturated: fail open to local-only for now (no blocking).
            entry.refill_in_flight = false;
            self.inner
                .metrics
                .rate_limit_fallback_triggered
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    fn maybe_evict(&mut self, now_ns: u64) {
        self.ops = self.ops.wrapping_add(1);

        // Cheap periodic eviction: every 4096 ops, scan and remove idle entries.
        if (self.ops & 0xFFF) != 0 {
            return;
        }

        let max = self.inner.cfg.l1_max_entries.max(1024);
        if self.l1.len() <= max {
            return;
        }

        let ttl_ns = self.inner.cfg.l1_idle_ttl.as_nanos() as u64;
        if self.last_eviction_ns != 0 && now_ns - self.last_eviction_ns < 200_000_000 {
            // at most 5Hz
            return;
        }
        self.last_eviction_ns = now_ns;

        // Remove idle entries; bounded work by limiting removals.
        let mut removed = 0usize;
        let target = (self.l1.len().saturating_sub(max)).min(4096);

        let keys: Vec<u64> = self
            .l1
            .iter()
            .filter_map(|(k, v)| {
                if now_ns.saturating_sub(v.last_seen_ns) > ttl_ns {
                    Some(*k)
                } else {
                    None
                }
            })
            .take(target)
            .collect();

        for k in keys {
            if self.l1.remove(&k).is_some() {
                removed += 1;
                if removed >= target {
                    break;
                }
            }
        }
    }
}

/// Utility: epoch ms for Redis/Lua scripts (best-effort).
#[inline]
fn epoch_ms() -> u64 {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    now.as_millis().min(u128::from(u64::MAX)) as u64
}

/// Monotonic nanoseconds from process bootstrapping point.
#[inline]
fn monotonic_ns() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    base.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(feature = "redis")]
pub mod redis_backend {
    use super::*;

    const LUA_TOKEN_BUCKET: &str = r#"
-- KEYS[1] = key
-- ARGV[1] = now_ms
-- ARGV[2] = rps
-- ARGV[3] = burst
-- ARGV[4] = want
-- ARGV[5] = ttl_ms

local now = tonumber(ARGV[1])
local rps = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local want = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local data = redis.call('HMGET', KEYS[1], 't', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = burst
end
if ts == nil then
  ts = now
end

local delta = now - ts
if delta < 0 then delta = 0 end

-- refill = delta_ms * rps / 1000
local add = (delta * rps) / 1000
tokens = tokens + add
if tokens > burst then
  tokens = burst
end
ts = now

local grant = 0
if tokens >= want then
  grant = want
  tokens = tokens - want
else
  grant = tokens
  tokens = 0
end

redis.call('HMSET', KEYS[1], 't', tokens, 'ts', ts)
redis.call('PEXPIRE', KEYS[1], ttl)

return grant
"#;

    pub struct RedisLuaBackend {
        conn: redis::aio::ConnectionManager,
        script: redis::Script,
    }

    impl RedisLuaBackend {
        pub async fn connect(redis_url: &str) -> Result<Self, BackendError> {
            let client =
                redis::Client::open(redis_url).map_err(|e| BackendError::Other(e.to_string()))?;
            let conn = redis::aio::ConnectionManager::new(client)
                .await
                .map_err(|e| BackendError::Other(e.to_string()))?;
            Ok(Self {
                conn,
                script: redis::Script::new(LUA_TOKEN_BUCKET),
            })
        }

        #[inline]
        fn redis_key(namespace: &str, key: u64) -> String {
            // Backend path: allocation acceptable; can be replaced by stack buffer later.
            format!("{namespace}:{key}")
        }
    }

    impl RateLimiterBackend for RedisLuaBackend {
        fn name(&self) -> &'static str {
            "redis_lua"
        }

        fn reserve<'a>(
            &'a self,
            req: ReserveRequest,
        ) -> Pin<Box<dyn Future<Output = Result<u32, BackendError>> + Send + 'a>> {
            Box::pin(async move {
                let mut conn = self.conn.clone();
                let k = Self::redis_key(req.namespace.as_ref(), req.key);

                let granted: i64 = self
                    .script
                    .key(k)
                    .arg(req.now_ms as i64)
                    .arg(req.policy.rps as i64)
                    .arg(req.policy.burst as i64)
                    .arg(req.want as i64)
                    .arg(req.ttl_ms as i64)
                    .invoke_async(&mut conn)
                    .await
                    .map_err(|e| BackendError::Other(e.to_string()))?;

                if granted < 0 {
                    return Err(BackendError::Protocol("negative grant"));
                }
                Ok(granted as u32)
            })
        }

        fn ping<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<(), BackendError>> + Send + 'a>> {
            Box::pin(async move {
                let mut conn = self.conn.clone();
                let pong: String = redis::cmd("PING")
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| BackendError::Other(e.to_string()))?;
                if pong.to_ascii_uppercase() == "PONG" {
                    Ok(())
                } else {
                    Err(BackendError::Protocol("bad PING response"))
                }
            })
        }
    }
}

pub struct InMemoryBackend {
    shards:
        Vec<std::sync::Mutex<HashMap<u64, GlobalBucket, BuildHasherDefault<IdentityU64Hasher>>>>,
}

#[derive(Debug, Clone)]
struct GlobalBucket {
    tokens: u64,
    last_ms: u64,
}

impl InMemoryBackend {
    pub fn new(shards: usize) -> Self {
        let n = shards.max(1).min(1024);
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(std::sync::Mutex::new(HashMap::with_capacity_and_hasher(
                1024,
                BuildHasherDefault::<IdentityU64Hasher>::default(),
            )));
        }
        Self { shards: v }
    }

    #[inline]
    fn shard(&self, key: u64) -> usize {
        (key as usize) % self.shards.len()
    }
}

impl RateLimiterBackend for InMemoryBackend {
    fn name(&self) -> &'static str {
        "in_memory"
    }

    fn reserve<'a>(
        &'a self,
        req: ReserveRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u32, BackendError>> + Send + 'a>> {
        Box::pin(async move {
            let shard = self.shard(req.key);
            let mut map = self.shards[shard]
                .lock()
                .map_err(|_| BackendError::Other("in_memory lock poisoned".to_string()))?;

            let b = map.entry(req.key).or_insert(GlobalBucket {
                tokens: req.policy.burst,
                last_ms: req.now_ms,
            });

            // refill
            let elapsed = req.now_ms.saturating_sub(b.last_ms);
            b.last_ms = req.now_ms;
            let add = (elapsed as u128) * (req.policy.rps as u128) / 1000u128;
            let new_tokens = (b.tokens as u128 + add).min(req.policy.burst as u128) as u64;
            b.tokens = new_tokens;

            let want = req.want as u64;
            let grant = if b.tokens >= want { want } else { b.tokens };
            b.tokens -= grant;

            Ok(grant as u32)
        })
    }
}
