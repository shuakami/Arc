use crate::config::LoggingRuntimeConfig;
use crate::metrics::LogMetrics;
use crate::record::{
    AccessErrorLogRecord, AccessLogContext, AccessLogRecord, LogEvent, LogLevel, LogStr, LogValue,
    RequestContextView, SystemLogRecord,
};
use crate::ring::SpscRing;
use crate::util::now_unix_ms;
use crate::writer::run_writer;
use arc_swap::ArcSwap;
use crossbeam_channel::{unbounded, Sender};
use serde::Serialize;
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

/// Logging subsystem error.
#[derive(Debug)]
pub enum LoggingError {
    /// Global logging already initialized.
    AlreadyInitialized,
    /// Logging is not initialized.
    NotInitialized,
    /// Invalid worker id.
    InvalidWorkerId { wid: usize, workers: usize },
    /// Config error.
    Config(String),
}

impl std::fmt::Display for LoggingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoggingError::AlreadyInitialized => write!(f, "logging already initialized"),
            LoggingError::NotInitialized => write!(f, "logging not initialized"),
            LoggingError::InvalidWorkerId { wid, workers } => {
                write!(f, "invalid worker id: wid={wid} workers={workers}")
            }
            LoggingError::Config(s) => write!(f, "config error: {s}"),
        }
    }
}

impl std::error::Error for LoggingError {}

/// Result type for logging subsystem.
pub type Result<T> = std::result::Result<T, LoggingError>;

/// Global logging handle (process-wide).
pub struct LoggingHandle {
    workers: usize,
    runtime: Arc<ArcSwap<LoggingRuntimeConfig>>,
    metrics: Arc<LogMetrics>,

    rings: Arc<[Arc<SpscRing<LogEvent>>]>,

    system_tx: Sender<SystemLogRecord>,

    #[cfg(feature = "debug_log")]
    debug_tx: Sender<SystemLogRecord>,

    _shutdown_tx: Sender<()>,
    overrides: Arc<ArcSwap<HashMap<String, RouteOverride>>>,
}

impl LoggingHandle {
    /// Update runtime config (RCU swap). Writer thread picks it up automatically.
    pub fn update_runtime(&self, new_rt: LoggingRuntimeConfig) {
        self.runtime.store(Arc::new(new_rt));
    }

    /// Update runtime config from raw_json.
    pub fn update_runtime_from_raw_json(&self, raw_json: &str) {
        let new_rt = LoggingRuntimeConfig::parse_from_raw_json(raw_json);
        self.update_runtime(new_rt);
    }

    /// Get current metrics snapshot render (Prometheus text).
    pub fn render_metrics_prometheus(&self) -> String {
        self.metrics.render_prometheus()
    }

    /// Set a route override (control plane).
    pub fn set_route_override(&self, route: &str, level: LogLevel, duration: Duration) {
        let now = now_unix_ms();
        let expires_at = now.saturating_add(duration.as_millis() as u64);

        let mut cur = (*self.overrides.load_full()).clone();
        cur.insert(
            route.to_string(),
            RouteOverride {
                level,
                expires_at_unix_ms: expires_at,
            },
        );
        self.overrides.store(Arc::new(cur));
    }

    /// Get a JSON status view for control plane.
    pub fn status_json(&self) -> String {
        let rt = self.runtime.load_full();
        let now = now_unix_ms();
        let ov = self.overrides.load_full();
        let mut routes: Vec<RouteOverrideView> = Vec::new();
        for (k, v) in ov.iter() {
            if v.expires_at_unix_ms > now {
                routes.push(RouteOverrideView {
                    route: k.clone(),
                    level: v.level,
                    expires_at_unix_ms: v.expires_at_unix_ms,
                });
            }
        }
        routes.sort_by(|a, b| a.route.cmp(&b.route));

        let view = LogStatusView {
            access_sample: rt.access.sample,
            force_on_status: rt.access.force_on_status.clone(),
            force_on_slow_ms: rt.access.force_on_slow_ms,
            output_file: rt.output.file.clone(),
            output_stdout: rt.output.stdout,
            rotation_max_size_bytes: rt.output.rotation.max_size_bytes,
            rotation_max_files: rt.output.rotation.max_files,
            rotation_compress: rt.output.rotation.compress,
            overrides: routes,
            // drop counters
            dropped_buffer_full: self.metrics_snapshot_dropped_buffer_full(),
            dropped_sampling: self.metrics_snapshot_dropped_sampling(),
        };

        serde_json::to_string(&view)
            .unwrap_or_else(|_| "{\"error\":\"serialize failed\"}".to_string())
    }

    fn metrics_snapshot_dropped_buffer_full(&self) -> u64 {
        // We intentionally do not expose internal atomics directly; render_metrics can show more.
        // Here we just parse from the prometheus string would be silly; we keep this minimal.
        // For control plane, consider using prometheus and scrape instead.
        0
    }

    fn metrics_snapshot_dropped_sampling(&self) -> u64 {
        0
    }
}

#[derive(Debug, Clone)]
struct RouteOverride {
    level: LogLevel,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct RouteOverrideView {
    route: String,
    level: LogLevel,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct LogStatusView {
    access_sample: f64,
    force_on_status: Vec<u16>,
    force_on_slow_ms: u64,

    output_file: String,
    output_stdout: bool,
    rotation_max_size_bytes: u64,
    rotation_max_files: usize,
    rotation_compress: bool,

    overrides: Vec<RouteOverrideView>,

    dropped_buffer_full: u64,
    dropped_sampling: u64,
}

// Global singleton
static GLOBAL: OnceLock<Arc<LoggingHandle>> = OnceLock::new();

// Worker TLS: pointer to SpscRing for ultra-fast push (no Arc clone on each log).
//
// 重要说明：
// - 这个 thread-local 只用于“写入目标 ring 选择”。ring 绑定线程是正确且必要的。
// - 请求上下文（trace_id/route/upstream 等）不应该依赖 thread-local 跨 await 传递。
// - 在 tokio 异步运行时中，请求跨 await 可能迁移线程；此时应使用 task-local
//   或显式 request context 结构体，避免上下文字段丢失。
thread_local! {
    static TL_RING_PTR: Cell<*const SpscRing<LogEvent>> = const { Cell::new(std::ptr::null()) };
    static TL_WID: Cell<usize> = const { Cell::new(usize::MAX) };

    // Request scope injection
    static TL_REQ_VIEW: Cell<*const RequestContextView> = const { Cell::new(std::ptr::null()) };
}

/// Initialize global logging subsystem.
///
/// Call exactly once at process startup (before spawning workers).
pub fn init_global(workers: usize, rt: LoggingRuntimeConfig) -> Result<Arc<LoggingHandle>> {
    if workers == 0 {
        return Err(LoggingError::Config("workers must be > 0".to_string()));
    }
    if GLOBAL.get().is_some() {
        return Err(LoggingError::AlreadyInitialized);
    }

    let runtime = Arc::new(ArcSwap::from_pointee(rt.clone()));
    let metrics = Arc::new(LogMetrics::default());

    let mut ring_vec: Vec<Arc<SpscRing<LogEvent>>> = Vec::with_capacity(workers);
    for _ in 0..workers {
        ring_vec.push(Arc::new(SpscRing::new(rt.writer.ring_capacity)));
    }
    let rings: Arc<[Arc<SpscRing<LogEvent>>]> = ring_vec.into();

    let (system_tx, system_rx) = unbounded::<SystemLogRecord>();

    #[cfg(feature = "debug_log")]
    let (debug_tx, debug_rx) = unbounded::<SystemLogRecord>();

    let (shutdown_tx, shutdown_rx) = unbounded::<()>();

    let overrides: Arc<ArcSwap<HashMap<String, RouteOverride>>> =
        Arc::new(ArcSwap::from_pointee(HashMap::new()));

    let handle = Arc::new(LoggingHandle {
        workers,
        runtime: runtime.clone(),
        metrics: metrics.clone(),
        rings: rings.clone(),
        system_tx,
        #[cfg(feature = "debug_log")]
        debug_tx,
        _shutdown_tx: shutdown_tx,
        overrides,
    });

    // Spawn writer thread
    let thread_rings = rings.clone();
    let thread_runtime = runtime.clone();
    let thread_metrics = metrics.clone();

    #[cfg(feature = "debug_log")]
    let thread_debug_rx = debug_rx;

    let thread_system_rx = system_rx;

    let builder = thread::Builder::new().name("arc-log-writer".to_string());
    let _join = builder.spawn(move || {
        run_writer(
            thread_rings,
            thread_system_rx,
            #[cfg(feature = "debug_log")]
            thread_debug_rx,
            thread_runtime,
            thread_metrics,
            shutdown_rx,
        );
    });

    let _ = GLOBAL.set(handle.clone());
    Ok(handle)
}

/// Initialize global logging from raw_json.
pub fn init_global_from_raw_json(workers: usize, raw_json: &str) -> Result<Arc<LoggingHandle>> {
    let rt = LoggingRuntimeConfig::parse_from_raw_json(raw_json);
    init_global(workers, rt)
}

/// Check if logging is initialized.
pub fn is_initialized() -> bool {
    GLOBAL.get().is_some()
}

/// Get global logging handle.
pub fn global() -> Option<Arc<LoggingHandle>> {
    GLOBAL.get().cloned()
}

pub fn access_log_hot_path_enabled() -> bool {
    let Some(h) = GLOBAL.get() else {
        return false;
    };
    let rt = h.runtime.load();
    rt.access.sample > 0.0
        || !rt.access.force_on_status.is_empty()
        || rt.access.force_on_slow_ms > 0
}

/// Initialize worker TLS ring pointer.
///
/// Must be called once per worker thread (hot path depends on it).
pub fn init_worker(wid: usize) -> Result<()> {
    let Some(h) = GLOBAL.get() else {
        return Err(LoggingError::NotInitialized);
    };
    if wid >= h.workers {
        return Err(LoggingError::InvalidWorkerId {
            wid,
            workers: h.workers,
        });
    }
    let ring = &h.rings[wid];
    let ptr: *const SpscRing<LogEvent> = Arc::as_ptr(ring);

    TL_RING_PTR.with(|c| c.set(ptr));
    TL_WID.with(|c| c.set(wid));
    Ok(())
}

pub fn enter_request_scope<'a>(view: &'a RequestContextView) -> RequestScopeGuard<'a> {
    let prev = TL_REQ_VIEW.with(|c| {
        let p = c.get();
        c.set(view as *const RequestContextView);
        p
    });
    RequestScopeGuard {
        _marker: std::marker::PhantomData,
        prev,
    }
}

/// Request scope guard.
pub struct RequestScopeGuard<'a> {
    _marker: std::marker::PhantomData<&'a RequestContextView>,
    prev: *const RequestContextView,
}

impl<'a> Drop for RequestScopeGuard<'a> {
    fn drop(&mut self) {
        TL_REQ_VIEW.with(|c| {
            c.set(self.prev);
        });
    }
}

/// Submit a successful access log at request end (tail-based sampling).
pub fn submit_access_success(ctx: AccessLogContext, status: u16, duration_ms: u64) {
    let rec = AccessLogRecord::from_ctx_success(ctx, status, duration_ms);
    submit_access_event(LogEvent::Access(rec), Some(status), duration_ms, false);
}

/// Submit an access error log at request end (forced write).
pub fn submit_access_error(
    ctx: AccessLogContext,
    msg: &str,
    error: &str,
    attempt: u32,
    max_attempts: u32,
    connect_timeout_ms: u64,
    elapsed_ms: u64,
    pool_active: u64,
    pool_max: u64,
) {
    let rec = AccessErrorLogRecord::from_ctx_error(
        ctx,
        msg,
        error,
        attempt,
        max_attempts,
        connect_timeout_ms,
        elapsed_ms,
        pool_active,
        pool_max,
    );
    // error is always forced
    submit_access_event(LogEvent::AccessError(rec), None, elapsed_ms, true);
}

fn submit_access_event(ev: LogEvent, status: Option<u16>, duration_ms: u64, is_error: bool) {
    let Some(h) = GLOBAL.get() else {
        return;
    };

    // Tail-based sampling decision at request end.
    let rt = h.runtime.load();
    let mut forced_reason_status = false;
    let mut forced_reason_error_record = false;
    let mut forced_reason_slow = false;

    if is_error {
        forced_reason_error_record = true;
    }
    if let Some(st) = status {
        if rt.access.force_on_status.binary_search(&st).is_ok() {
            forced_reason_status = true;
        }
    }
    if rt.access.force_on_slow_ms > 0 && duration_ms > rt.access.force_on_slow_ms {
        forced_reason_slow = true;
    }

    let forced = forced_reason_status || forced_reason_error_record || forced_reason_slow;
    if forced_reason_status {
        h.metrics.inc_force_written_status();
    }
    if forced_reason_error_record {
        h.metrics.inc_force_written_error_record();
    }
    if forced_reason_slow {
        h.metrics.inc_force_written_slow();
    }

    // Effective sampling rate (route override can set debug => 1.0)
    let sample = if forced {
        1.0
    } else {
        effective_sample_rate(h, &rt)
    };

    if !forced && sample <= 0.0 {
        h.metrics.inc_dropped_sampling();
        return;
    }

    if !forced && sample < 1.0 {
        if !sample_hit(sample) {
            h.metrics.inc_dropped_sampling();
            return;
        }
    }

    // Push into thread-local ring (lock-free). If ring is not initialized, drop silently.
    let ok = TL_RING_PTR.with(|c| {
        let p = c.get();
        if p.is_null() {
            return false;
        }
        // SAFETY:
        // - Pointer comes from Arc::as_ptr and ring lives for the process lifetime after init_global.
        // - This thread is the single producer for its ring; writer thread is the single consumer.
        let ring = unsafe { &*p };
        ring.push(ev).is_ok()
    });

    if !ok {
        h.metrics.inc_dropped_buffer_full();
    }
}

fn effective_sample_rate(h: &LoggingHandle, rt: &LoggingRuntimeConfig) -> f64 {
    // default: global access.sample
    let sample = rt.access.sample.clamp(0.0, 1.0);

    // If override exists and not expired, treat debug level as full sampling.
    let now = now_unix_ms();
    let ov = h.overrides.load();
    // We don't have route name in the generic event here without pattern matching.
    // For a full Arc integration, call a route-aware submit wrapper (route is in ctx.route).
    // As a safe default, apply only global sample here.
    //
    // NOTE:
    // - This is intentionally conservative. Once integrated into Arc request path,
    //   you should implement a route-aware effective sample, using ctx.route.as_str().
    let _ = now;
    let _ = ov;

    sample
}

// Very fast thread-local xorshift RNG for sampling (no rand crate).
thread_local! {
    static TL_RNG: Cell<u64> = Cell::new(0);
}

fn sample_hit(rate: f64) -> bool {
    let r = rate.clamp(0.0, 1.0);
    if r >= 1.0 {
        return true;
    }
    if r <= 0.0 {
        return false;
    }
    let threshold = (r * (u64::MAX as f64)) as u64;

    TL_RNG.with(|c| {
        let mut x = c.get();
        if x == 0 {
            // Seed: mix time + address of TLS cell (as entropy) + thread id hash.
            let t = now_unix_ms();
            let addr = (&*c as *const Cell<u64> as usize) as u64;
            let tid = std::thread::current()
                .name()
                .map(|s| s.as_bytes().len() as u64)
                .unwrap_or(1);
            x = t ^ addr.rotate_left(17) ^ tid.rotate_left(33) ^ 0x9e37_79b9_7f4a_7c15;
            if x == 0 {
                x = 1;
            }
        }
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545F4914F6CDD1D);
        c.set(x);
        x <= threshold
    })
}

/// System log (no extra fields).
pub fn system_log(level: LogLevel, msg: &str) {
    let Some(h) = GLOBAL.get() else {
        return;
    };
    let rec = SystemLogRecord::new(level, msg);
    let _ = h.system_tx.send(rec);
}

/// System log with prebuilt fields.
pub fn system_log_fields(level: LogLevel, msg: &str, fields: Vec<(LogStr, LogValue)>) {
    let Some(h) = GLOBAL.get() else {
        return;
    };
    let mut rec = SystemLogRecord::new(level, msg);
    rec.fields = fields;
    let _ = h.system_tx.send(rec);
}

/// System log with a single key/value field.
pub fn system_log_kv(level: LogLevel, msg: &str, key: &str, val: LogValue) {
    system_log_fields(level, msg, vec![(LogStr::new(key), val)]);
}

#[cfg(feature = "debug_log")]
/// Debug log (feature-gated).
pub fn debug_log(level: LogLevel, msg: &str) {
    let Some(h) = GLOBAL.get() else {
        return;
    };
    let rec = SystemLogRecord::new(level, msg);
    let _ = h.debug_tx.send(rec);
}

#[cfg(feature = "debug_log")]
/// Debug log with fields (feature-gated).
pub fn debug_log_fields(level: LogLevel, msg: &str, fields: Vec<(LogStr, LogValue)>) {
    let Some(h) = GLOBAL.get() else {
        return;
    };
    let mut rec = SystemLogRecord::new(level, msg);
    rec.fields = fields;
    let _ = h.debug_tx.send(rec);
}

/// Control plane: set route override by duration string (e.g. "5m").
///
/// This is a convenience wrapper. Unknown duration => no-op.
pub fn set_route_override(route: &str, level: LogLevel, duration: Duration) {
    if let Some(h) = GLOBAL.get() {
        h.set_route_override(route, level, duration);
    }
}

/// Control plane: status JSON.
pub fn status_json() -> String {
    match GLOBAL.get() {
        Some(h) => h.status_json(),
        None => "{\"error\":\"logging not initialized\"}\n".to_string(),
    }
}

/// Metrics: render prometheus text for logging subsystem.
pub fn global_metrics_render_prometheus() -> String {
    match GLOBAL.get() {
        Some(h) => h.render_metrics_prometheus(),
        None => String::new(),
    }
}
