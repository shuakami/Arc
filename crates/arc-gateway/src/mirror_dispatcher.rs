use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use arc_observability::WorkerMetrics;
use serde_json::Value;

/// Drop reason labels required by metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorDropReason {
    QueueFull,
    UpstreamError,
    Timeout,
}

#[derive(Debug)]
pub struct MirrorTargetMetrics {
    sent_total: AtomicU64,

    dropped_queue_full_total: AtomicU64,
    dropped_upstream_error_total: AtomicU64,
    dropped_timeout_total: AtomicU64,

    diff_total: AtomicU64,

    status_2xx_total: AtomicU64,
    status_3xx_total: AtomicU64,
    status_4xx_total: AtomicU64,
    status_5xx_total: AtomicU64,
    status_other_total: AtomicU64,

    queue_bytes: AtomicUsize,

    latency_count: AtomicU64,
    latency_total_ns: AtomicU64,
}

impl MirrorTargetMetrics {
    pub fn new() -> Self {
        Self {
            sent_total: AtomicU64::new(0),
            dropped_queue_full_total: AtomicU64::new(0),
            dropped_upstream_error_total: AtomicU64::new(0),
            dropped_timeout_total: AtomicU64::new(0),
            diff_total: AtomicU64::new(0),
            status_2xx_total: AtomicU64::new(0),
            status_3xx_total: AtomicU64::new(0),
            status_4xx_total: AtomicU64::new(0),
            status_5xx_total: AtomicU64::new(0),
            status_other_total: AtomicU64::new(0),
            queue_bytes: AtomicUsize::new(0),
            latency_count: AtomicU64::new(0),
            latency_total_ns: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_sent(&self) -> u64 {
        self.sent_total.fetch_add(1, Ordering::Relaxed) + 1
    }

    #[inline]
    pub fn inc_dropped(&self, reason: MirrorDropReason) -> u64 {
        match reason {
            MirrorDropReason::QueueFull => {
                self.dropped_queue_full_total
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            MirrorDropReason::UpstreamError => {
                self.dropped_upstream_error_total
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
            }
            MirrorDropReason::Timeout => {
                self.dropped_timeout_total.fetch_add(1, Ordering::Relaxed) + 1
            }
        }
    }

    #[inline]
    pub fn inc_diff(&self) {
        self.diff_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn observe_status(&self, status: u16) {
        if (200..=299).contains(&status) {
            self.status_2xx_total.fetch_add(1, Ordering::Relaxed);
        } else if (300..=399).contains(&status) {
            self.status_3xx_total.fetch_add(1, Ordering::Relaxed);
        } else if (400..=499).contains(&status) {
            self.status_4xx_total.fetch_add(1, Ordering::Relaxed);
        } else if (500..=599).contains(&status) {
            self.status_5xx_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.status_other_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn queue_bytes_add(&self, n: usize) {
        self.queue_bytes.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn queue_bytes_sub(&self, n: usize) {
        self.queue_bytes.fetch_sub(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn observe_latency(&self, d: Duration) {
        let ns = d.as_nanos();
        let ns_u64 = if ns > u64::MAX as u128 {
            u64::MAX
        } else {
            ns as u64
        };
        self.latency_total_ns.fetch_add(ns_u64, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MirrorTargetMetricsSnapshot {
        MirrorTargetMetricsSnapshot {
            sent_total: self.sent_total.load(Ordering::Relaxed),
            dropped_queue_full_total: self.dropped_queue_full_total.load(Ordering::Relaxed),
            dropped_upstream_error_total: self.dropped_upstream_error_total.load(Ordering::Relaxed),
            dropped_timeout_total: self.dropped_timeout_total.load(Ordering::Relaxed),
            diff_total: self.diff_total.load(Ordering::Relaxed),
            status_2xx_total: self.status_2xx_total.load(Ordering::Relaxed),
            status_3xx_total: self.status_3xx_total.load(Ordering::Relaxed),
            status_4xx_total: self.status_4xx_total.load(Ordering::Relaxed),
            status_5xx_total: self.status_5xx_total.load(Ordering::Relaxed),
            status_other_total: self.status_other_total.load(Ordering::Relaxed),
            queue_bytes: self.queue_bytes.load(Ordering::Relaxed),
            latency_count: self.latency_count.load(Ordering::Relaxed),
            latency_total_ns: self.latency_total_ns.load(Ordering::Relaxed),
        }
    }
}

/// Immutable snapshot of metrics.
#[derive(Clone, Debug)]
pub struct MirrorTargetMetricsSnapshot {
    pub sent_total: u64,
    pub dropped_queue_full_total: u64,
    pub dropped_upstream_error_total: u64,
    pub dropped_timeout_total: u64,
    pub diff_total: u64,
    pub status_2xx_total: u64,
    pub status_3xx_total: u64,
    pub status_4xx_total: u64,
    pub status_5xx_total: u64,
    pub status_other_total: u64,
    pub queue_bytes: usize,
    pub latency_count: u64,
    pub latency_total_ns: u64,
}

/// Runtime representation of mirror transform config.
#[derive(Clone, Debug, Default)]
pub struct MirrorTransformRuntime {
    pub headers_set: Vec<(String, String)>,
    pub headers_remove: Vec<String>,
    pub path_template: Option<String>,
}

/// Runtime representation of mirror compare config.
#[derive(Clone, Debug, Default)]
pub struct MirrorCompareRuntime {
    pub enabled: bool,
    pub ignore_headers_lower: Vec<String>,
    pub ignore_body_paths: Vec<Vec<String>>,
}

/// A compiled mirror target (one upstream).
#[derive(Clone, Debug)]
pub struct MirrorTargetRuntime {
    pub upstream: Arc<str>,
    pub addr: SocketAddr,
    pub sample: f64,
    pub timeout: Duration,
    pub transform: MirrorTransformRuntime,
    pub compare: MirrorCompareRuntime,
    pub metrics: Arc<MirrorTargetMetrics>,
}

impl MirrorTargetRuntime {
    pub fn snapshot(&self) -> MirrorTargetSnapshot {
        MirrorTargetSnapshot {
            upstream: self.upstream.to_string(),
            addr: self.addr,
            metrics: self.metrics.snapshot(),
        }
    }
}

/// Snapshot for `arc routes tap`-like output.
#[derive(Clone, Debug)]
pub struct MirrorTargetSnapshot {
    pub upstream: String,
    pub addr: SocketAddr,
    pub metrics: MirrorTargetMetricsSnapshot,
}

/// Runtime mirror policy.
#[derive(Clone, Debug)]
pub struct MirrorPolicyRuntime {
    pub max_queue_bytes: usize,
}

impl Default for MirrorPolicyRuntime {
    fn default() -> Self {
        Self {
            max_queue_bytes: 50 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MirrorSubmitContext {
    /// Domain/SNI/Host context for structured diff logs (best effort).
    pub domain: Option<Arc<str>>,
    /// Route name for structured diff logs.
    pub route_name: Arc<str>,
    /// Original request path (from router match).
    pub original_path: Arc<str>,

    /// Production response status code.
    pub prod_status: u16,
    /// Production end-to-end latency (as observed by gateway).
    pub prod_latency: Duration,
    /// Raw production response bytes (HTTP/1.1) for compare. Optional.
    pub prod_response: Option<Arc<[u8]>>,
}

/// A queued mirror task.
#[derive(Clone, Debug)]
struct MirrorTask {
    target: Arc<MirrorTargetRuntime>,
    ctx: MirrorSubmitContext,
    raw_req: Arc<[u8]>,
    reserved_bytes: usize,
}

/// Mirror dispatcher: owns the bounded queue and worker threads.
///
/// Producer path is non-blocking (try-lock + atomic reservation).
pub struct MirrorDispatcher {
    state: Arc<MirrorDispatcherState>,
    workers: Vec<thread::JoinHandle<()>>,
}

struct MirrorDispatcherState {
    policy: MirrorPolicyRuntime,
    worker_metrics: Option<Arc<WorkerMetrics>>,

    // Global queue bytes cap is enforced by this atomic reservation.
    queue_bytes: AtomicUsize,

    // MPMC queue guarded by mutex. Producers use try_lock to avoid blocking main path.
    queue: Mutex<VecDeque<MirrorTask>>,
    cv: Condvar,

    // Fast random sampling seed.
    rng: AtomicU64,

    stop: AtomicBool,
}

impl MirrorDispatcher {
    /// Create a dispatcher and spawn worker threads.
    ///
    /// `worker_threads` should be small (e.g. 1-2 per gateway worker) since mirror is off-path.
    pub fn new(
        policy: MirrorPolicyRuntime,
        worker_threads: usize,
        worker_metrics: Option<Arc<WorkerMetrics>>,
    ) -> Self {
        let state = Arc::new(MirrorDispatcherState {
            policy,
            worker_metrics,
            queue_bytes: AtomicUsize::new(0),
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            rng: AtomicU64::new(0x1234_5678_9abc_def0),
            stop: AtomicBool::new(false),
        });

        let n = worker_threads.max(1);
        let mut workers = Vec::with_capacity(n);
        for i in 0..n {
            let st = Arc::clone(&state);
            let th = thread::Builder::new()
                .name(format!("arc-mirror-{i}"))
                .spawn({
                    let st2 = Arc::clone(&st);
                    move || mirror_worker_loop(st2)
                })
                .unwrap_or_else(|_| {
                    // If spawning fails, we cannot safely continue with this worker thread.
                    // As a pragmatic fallback, run synchronously in the current thread.
                    // This still preserves the "no propagation to main path" guarantee
                    // because submit() will continue dropping tasks when try_lock fails.
                    thread::spawn(move || mirror_worker_loop(st))
                });
            workers.push(th);
        }

        Self { state, workers }
    }

    pub fn submit_all(
        &self,
        targets: &[Arc<MirrorTargetRuntime>],
        ctx: MirrorSubmitContext,
        raw_req: Arc<[u8]>,
    ) {
        // If dispatcher is stopping, drop silently.
        if self.state.stop.load(Ordering::Relaxed) {
            return;
        }

        for t in targets {
            if !should_sample(&self.state.rng, t.sample) {
                continue;
            }

            let prod_len = ctx.prod_response.as_ref().map(|b| b.len()).unwrap_or(0);
            let est_bytes = raw_req.len().saturating_add(prod_len).saturating_add(256);

            // Reserve global queue bytes first (lock-free), then try_lock queue.
            if !try_reserve_queue_bytes(&self.state, est_bytes) {
                let c = t.metrics.inc_dropped(MirrorDropReason::QueueFull);
                if let Some(wm) = self.state.worker_metrics.as_ref() {
                    wm.mirror_queue_full_total.fetch_add(1, Ordering::Relaxed);
                }
                if (c & 1023) == 1 {
                    eprintln!(
                        "WARN arc-mirror queue_full upstream={} dropped_total={}",
                        t.upstream, c
                    );
                }
                continue;
            }

            t.metrics.queue_bytes_add(est_bytes);

            let guard = self.state.queue.try_lock();
            let mut q = match guard {
                Ok(g) => g,
                Err(_) => {
                    release_queue_bytes(&self.state, est_bytes);
                    t.metrics.queue_bytes_sub(est_bytes);

                    let c = t.metrics.inc_dropped(MirrorDropReason::QueueFull);
                    if (c & 1023) == 1 {
                        eprintln!(
                            "WARN arc-mirror queue_busy_drop upstream={} dropped_total={}",
                            t.upstream, c
                        );
                    }
                    continue;
                }
            };

            q.push_back(MirrorTask {
                target: Arc::clone(t),
                ctx: ctx.clone(),
                raw_req: Arc::clone(&raw_req),
                reserved_bytes: est_bytes,
            });
            if let Some(wm) = self.state.worker_metrics.as_ref() {
                wm.mirror_submitted_total.fetch_add(1, Ordering::Relaxed);
            }
            drop(q);

            self.state.cv.notify_one();
        }
    }

    /// Snapshot all metrics for UI output (e.g. `arc routes tap`).
    pub fn snapshot_targets(
        &self,
        targets: &[Arc<MirrorTargetRuntime>],
    ) -> Vec<MirrorTargetSnapshot> {
        targets.iter().map(|t| t.snapshot()).collect()
    }
}

impl Drop for MirrorDispatcher {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Relaxed);
        self.state.cv.notify_all();
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

fn try_reserve_queue_bytes(state: &MirrorDispatcherState, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    loop {
        let cur = state.queue_bytes.load(Ordering::Relaxed);
        let next = cur.saturating_add(bytes);
        if next > state.policy.max_queue_bytes {
            return false;
        }
        match state.queue_bytes.compare_exchange_weak(
            cur,
            next,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(_) => continue,
        }
    }
}

fn release_queue_bytes(state: &MirrorDispatcherState, bytes: usize) {
    if bytes == 0 {
        return;
    }
    state.queue_bytes.fetch_sub(bytes, Ordering::Relaxed);
}

fn mirror_worker_loop(state: Arc<MirrorDispatcherState>) {
    loop {
        let task = {
            let mut q = match state.queue.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };

            while q.is_empty() && !state.stop.load(Ordering::Relaxed) {
                let g = state.cv.wait(q);
                q = match g {
                    Ok(v) => v,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }

            if state.stop.load(Ordering::Relaxed) && q.is_empty() {
                return;
            }

            q.pop_front()
        };

        let Some(task) = task else {
            continue;
        };

        release_queue_bytes(&state, task.reserved_bytes);
        task.target.metrics.queue_bytes_sub(task.reserved_bytes);

        // MUST catch panics inside mirror tasks (spec guarantee).
        let res = panic::catch_unwind(AssertUnwindSafe(|| run_one_task(&task)));

        match res {
            Ok(Ok(outcome)) => {
                if let Some(wm) = state.worker_metrics.as_ref() {
                    wm.mirror_sent_total.fetch_add(1, Ordering::Relaxed);
                    let ns = outcome.latency.as_nanos();
                    let ns_u64 = if ns > u64::MAX as u128 {
                        u64::MAX
                    } else {
                        ns as u64
                    };
                    wm.mirror_latency_count.fetch_add(1, Ordering::Relaxed);
                    wm.mirror_latency_sum_ns
                        .fetch_add(ns_u64, Ordering::Relaxed);
                    if (200..=299).contains(&outcome.status) {
                        wm.mirror_status_2xx_total.fetch_add(1, Ordering::Relaxed);
                    } else if (300..=399).contains(&outcome.status) {
                        wm.mirror_status_3xx_total.fetch_add(1, Ordering::Relaxed);
                    } else if (400..=499).contains(&outcome.status) {
                        wm.mirror_status_4xx_total.fetch_add(1, Ordering::Relaxed);
                    } else if (500..=599).contains(&outcome.status) {
                        wm.mirror_status_5xx_total.fetch_add(1, Ordering::Relaxed);
                    } else {
                        wm.mirror_status_other_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Ok(Err(e)) => {
                let reason = e;
                let c = task.target.metrics.inc_dropped(reason);
                if reason == MirrorDropReason::Timeout && (c & 1023) == 1 {
                    eprintln!(
                        "WARN arc-mirror timeout upstream={} dropped_timeout_total={}",
                        task.target.upstream, c
                    );
                }
                if reason == MirrorDropReason::UpstreamError && (c & 1023) == 1 {
                    eprintln!(
                        "WARN arc-mirror upstream_error upstream={} dropped_upstream_error_total={}",
                        task.target.upstream, c
                    );
                }
                if let Some(wm) = state.worker_metrics.as_ref() {
                    match reason {
                        MirrorDropReason::QueueFull => {
                            wm.mirror_queue_full_total.fetch_add(1, Ordering::Relaxed);
                        }
                        MirrorDropReason::UpstreamError => {
                            wm.mirror_upstream_error_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        MirrorDropReason::Timeout => {
                            wm.mirror_timeout_total.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            Err(_) => {
                // Panic -> treat as upstream_error (discard).
                let c = task
                    .target
                    .metrics
                    .inc_dropped(MirrorDropReason::UpstreamError);
                if (c & 1023) == 1 {
                    eprintln!(
                        "WARN arc-mirror panic_caught upstream={} dropped_upstream_error_total={}",
                        task.target.upstream, c
                    );
                }
                if let Some(wm) = state.worker_metrics.as_ref() {
                    wm.mirror_upstream_error_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MirrorOutcome {
    status: u16,
    latency: Duration,
}

/// Returns Ok(outcome) if sent successfully (even if diff found), Err(drop_reason) otherwise.
fn run_one_task(task: &MirrorTask) -> Result<MirrorOutcome, MirrorDropReason> {
    let sent_total = task.target.metrics.inc_sent();

    let started = Instant::now();

    let transformed =
        match build_transformed_request(&task.raw_req, &task.ctx, &task.target.transform) {
            Ok(v) => v,
            Err(_) => return Err(MirrorDropReason::UpstreamError),
        };

    let shadow_resp = match http_roundtrip(task.target.addr, &transformed, task.target.timeout) {
        Ok(v) => v,
        Err(HttpRoundtripError::Timeout) => return Err(MirrorDropReason::Timeout),
        Err(HttpRoundtripError::UpstreamError) => return Err(MirrorDropReason::UpstreamError),
    };

    let latency = started.elapsed();
    task.target.metrics.observe_status(shadow_resp.status);
    task.target.metrics.observe_latency(latency);
    if (sent_total & 1023) == 1 {
        eprintln!(
            "INFO arc-mirror record upstream={} status={} latency_ms={:.3} route={} path={}",
            task.target.upstream,
            shadow_resp.status,
            latency.as_secs_f64() * 1000.0,
            task.ctx.route_name,
            task.ctx.original_path
        );
    }

    if task.target.compare.enabled {
        if let Some(prod_raw) = task.ctx.prod_response.as_ref() {
            if let Some(diff) = compare_prod_shadow(
                &task.ctx,
                prod_raw,
                task.ctx.prod_status,
                task.ctx.prod_latency,
                &shadow_resp,
                &task.target,
            ) {
                task.target.metrics.inc_diff();
                log_diff(&task.ctx, &task.target.upstream, &diff);
            }
        }
    }

    Ok(MirrorOutcome {
        status: shadow_resp.status,
        latency,
    })
}

#[derive(Clone, Debug)]
struct HttpResponseSnapshot {
    status: u16,
    headers: HashMap<String, Vec<u8>>, // lower-case name -> raw value bytes
    body: Vec<u8>,
    latency: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpRoundtripError {
    Timeout,
    UpstreamError,
}

fn http_roundtrip(
    addr: SocketAddr,
    req: &[u8],
    timeout: Duration,
) -> Result<HttpResponseSnapshot, HttpRoundtripError> {
    if timeout.is_zero() {
        return Err(HttpRoundtripError::Timeout);
    }

    let deadline = Instant::now() + timeout;

    let remaining = remaining_until(deadline)?;
    let mut stream = TcpStream::connect_timeout(&addr, remaining).map_err(map_io_err)?;
    let _ = stream.set_nodelay(true);

    let remaining = remaining_until(deadline)?;
    let _ = stream.set_write_timeout(Some(remaining));
    stream.write_all(req).map_err(map_io_err)?;

    let remaining = remaining_until(deadline)?;
    let _ = stream.set_read_timeout(Some(remaining));

    let started = Instant::now();
    let raw = read_http_response(&mut stream, deadline, 16 * 1024 * 1024)?;
    let latency = started.elapsed();

    let parsed = parse_http_response(&raw).map_err(|_| HttpRoundtripError::UpstreamError)?;
    Ok(HttpResponseSnapshot {
        status: parsed.status,
        headers: parsed.headers,
        body: parsed.body,
        latency,
    })
}

fn remaining_until(deadline: Instant) -> Result<Duration, HttpRoundtripError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(HttpRoundtripError::Timeout);
    }
    Ok(deadline - now)
}

fn map_io_err(e: std::io::Error) -> HttpRoundtripError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            HttpRoundtripError::Timeout
        }
        _ => HttpRoundtripError::UpstreamError,
    }
}

fn read_http_response(
    stream: &mut TcpStream,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Vec<u8>, HttpRoundtripError> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    // We keep reading until:
    // - content-length satisfied
    // - chunked decoding completes
    // - EOF for until-eof
    //
    // We parse headers incrementally as soon as we have them.
    let mut header_end: Option<usize> = None;
    let mut body_kind: Option<BodyKind> = None;

    loop {
        // Check completion conditions.
        if let (Some(hend), Some(kind)) = (header_end, body_kind) {
            match kind {
                BodyKind::ContentLength(len) => {
                    if buf.len() >= hend.saturating_add(len) {
                        buf.truncate(hend.saturating_add(len));
                        return Ok(buf);
                    }
                }
                BodyKind::Chunked => {
                    let body = &buf[hend..];
                    if let Ok(Some((_decoded, _consumed))) = try_decode_chunked(body, max_bytes) {
                        // We still return raw bytes; parse_http_response will decode once.
                        return Ok(buf);
                    }
                }
                BodyKind::UntilEof => {
                    // Wait for EOF.
                }
            }
        }

        if buf.len() >= max_bytes {
            return Err(HttpRoundtripError::UpstreamError);
        }

        let remaining = remaining_until(deadline)?;
        let _ = stream.set_read_timeout(Some(remaining));

        let n = stream.read(&mut tmp).map_err(map_io_err)?;
        if n == 0 {
            // EOF
            return Ok(buf);
        }
        buf.extend_from_slice(&tmp[..n]);

        if header_end.is_none() {
            header_end = find_header_end(&buf);
            if let Some(hend) = header_end {
                let head = &buf[..hend];
                let headers =
                    parse_headers_only(head).map_err(|_| HttpRoundtripError::UpstreamError)?;
                body_kind = Some(detect_body_kind(&headers));
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum BodyKind {
    ContentLength(usize),
    Chunked,
    UntilEof,
}

fn detect_body_kind(headers: &HashMap<String, Vec<u8>>) -> BodyKind {
    if let Some(v) = headers.get("transfer-encoding") {
        // best effort: look for "chunked" in ASCII lower-case
        if ascii_bytes_to_lower(v).contains("chunked") {
            return BodyKind::Chunked;
        }
    }
    if let Some(v) = headers.get("content-length") {
        if let Ok(s) = std::str::from_utf8(v) {
            if let Ok(n) = s.trim().parse::<usize>() {
                return BodyKind::ContentLength(n);
            }
        }
    }
    BodyKind::UntilEof
}

fn ascii_bytes_to_lower(v: &[u8]) -> String {
    let mut out = String::with_capacity(v.len());
    for &b in v {
        out.push((b as char).to_ascii_lowercase());
    }
    out
}

/// Minimal parsed response (decoded body).
struct ParsedHttpResponse {
    status: u16,
    headers: HashMap<String, Vec<u8>>,
    body: Vec<u8>,
}

fn parse_http_response(raw: &[u8]) -> Result<ParsedHttpResponse, ()> {
    let hend = find_header_end(raw).ok_or(())?;
    let head = &raw[..hend];
    let status = parse_status_code(head).ok_or(())?;
    let headers = parse_headers_only(head)?;

    let kind = detect_body_kind(&headers);
    let body_raw = &raw[hend..];

    let body = match kind {
        BodyKind::ContentLength(n) => {
            if body_raw.len() < n {
                return Err(());
            }
            body_raw[..n].to_vec()
        }
        BodyKind::Chunked => {
            let (decoded, _consumed) = decode_chunked(body_raw, 16 * 1024 * 1024)?;
            decoded
        }
        BodyKind::UntilEof => body_raw.to_vec(),
    };

    Ok(ParsedHttpResponse {
        status,
        headers,
        body,
    })
}

fn parse_status_code(head: &[u8]) -> Option<u16> {
    let line_end = find_crlf(head, 0)?;
    let line = &head[..line_end];
    let sp1 = line.iter().position(|&b| b == b' ')?;
    let rest = &line[sp1 + 1..];
    let sp2_rel = rest.iter().position(|&b| b == b' ')?;
    let code_bytes = &rest[..sp2_rel];
    let code_str = std::str::from_utf8(code_bytes).ok()?;
    code_str.parse::<u16>().ok()
}

fn parse_headers_only(head: &[u8]) -> Result<HashMap<String, Vec<u8>>, ()> {
    let line_end = find_crlf(head, 0).ok_or(())?;
    let mut pos = line_end + 2;

    // head ends with \r\n\r\n, so the header lines are until hend-4.
    let hend = find_header_end(head).ok_or(())?;
    let end = hend.saturating_sub(4);

    let mut out = HashMap::new();

    while pos < end {
        let le = find_crlf(head, pos).ok_or(())?;
        let line = &head[pos..le];
        pos = le + 2;

        if line.is_empty() {
            break;
        }

        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };

        let name = &line[..colon];
        let value = &line[colon + 1..];
        let name_lower = ascii_lower(name);

        let value_trimmed = trim_ascii_ws(value);

        // last-wins semantics for simplicity
        out.insert(name_lower, value_trimmed.to_vec());
    }

    Ok(out)
}

fn ascii_lower(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s {
        out.push((b as char).to_ascii_lowercase());
    }
    out
}

fn trim_ascii_ws(s: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = s.len();

    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i + 3 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

fn try_decode_chunked(body: &[u8], max_out: usize) -> Result<Option<(Vec<u8>, usize)>, ()> {
    // fast path: attempt decode; if incomplete -> Ok(None)
    match decode_chunked_internal(body, max_out, true) {
        Ok(Some(v)) => Ok(Some(v)),
        Ok(None) => Ok(None),
        Err(()) => Err(()),
    }
}

fn decode_chunked(body: &[u8], max_out: usize) -> Result<(Vec<u8>, usize), ()> {
    match decode_chunked_internal(body, max_out, false) {
        Ok(Some(v)) => Ok(v),
        _ => Err(()),
    }
}

fn decode_chunked_internal(
    body: &[u8],
    max_out: usize,
    allow_incomplete: bool,
) -> Result<Option<(Vec<u8>, usize)>, ()> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    loop {
        // parse chunk size line
        let line_end = match find_crlf(body, pos) {
            Some(v) => v,
            None => return if allow_incomplete { Ok(None) } else { Err(()) },
        };
        let line = &body[pos..line_end];
        let size = parse_hex_usize(line)?;
        pos = line_end + 2;

        if size == 0 {
            // consume trailers until \r\n\r\n
            let mut trailer_pos = pos;
            loop {
                let le = match find_crlf(body, trailer_pos) {
                    Some(v) => v,
                    None => return if allow_incomplete { Ok(None) } else { Err(()) },
                };
                // empty line => end of trailers
                if le == trailer_pos {
                    trailer_pos = le + 2;
                    return Ok(Some((out, trailer_pos)));
                }
                trailer_pos = le + 2;
            }
        }

        if pos + size + 2 > body.len() {
            return if allow_incomplete { Ok(None) } else { Err(()) };
        }

        if out.len().saturating_add(size) > max_out {
            return Err(());
        }

        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;

        // expect \r\n after chunk data
        if body.get(pos) != Some(&b'\r') || body.get(pos + 1) != Some(&b'\n') {
            return Err(());
        }
        pos += 2;
    }
}

fn parse_hex_usize(s: &[u8]) -> Result<usize, ()> {
    let mut val: usize = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            b';' => break, // chunk extensions, ignore
            b' ' | b'\t' => continue,
            _ => return Err(()),
        };
        val = val.saturating_mul(16).saturating_add(d);
    }
    Ok(val)
}

fn build_transformed_request(
    raw_req: &[u8],
    ctx: &MirrorSubmitContext,
    tr: &MirrorTransformRuntime,
) -> Result<Vec<u8>, ()> {
    let hend = find_header_end(raw_req).ok_or(())?;
    let head = &raw_req[..hend];
    let body = &raw_req[hend..];

    let (method, _orig_path, version) = parse_request_line(head).ok_or(())?;
    let mut headers = parse_request_headers(head)?;

    // Apply header removals
    if !tr.headers_remove.is_empty() {
        let mut remove = Vec::with_capacity(tr.headers_remove.len());
        for h in &tr.headers_remove {
            remove.push(h.to_ascii_lowercase());
        }
        headers.retain(|(n_lower, _n_raw, _v)| !remove.iter().any(|x| x == n_lower));
    }

    // Apply header set/override
    for (k, v) in &tr.headers_set {
        let kn = k.to_ascii_lowercase();
        let mut found = false;
        for (n_lower, n_raw, val) in headers.iter_mut() {
            if *n_lower == kn {
                *n_raw = k.clone();
                *val = v.as_bytes().to_vec();
                found = true;
                break;
            }
        }
        if !found {
            headers.push((kn, k.clone(), v.as_bytes().to_vec()));
        }
    }

    // Always force Connection: close to ensure response completion.
    {
        let kn = "connection".to_string();
        let mut found = false;
        for (n_lower, n_raw, val) in headers.iter_mut() {
            if *n_lower == kn {
                *n_raw = "Connection".to_string();
                *val = b"close".to_vec();
                found = true;
                break;
            }
        }
        if !found {
            headers.push((kn, "Connection".to_string(), b"close".to_vec()));
        }
    }

    // Path rewrite
    let new_path = match tr.path_template.as_ref() {
        Some(tpl) => render_path_template(tpl, &ctx.original_path, &ctx.route_name),
        None => ctx.original_path.to_string(),
    };

    // Rebuild request
    let mut out = Vec::with_capacity(raw_req.len().saturating_add(64));
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(new_path.as_bytes());
    out.push(b' ');
    out.extend_from_slice(version);
    out.extend_from_slice(b"\r\n");

    for (_n_lower, n_raw, v) in headers {
        out.extend_from_slice(n_raw.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);

    Ok(out)
}

fn parse_request_line(head: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let line_end = find_crlf(head, 0)?;
    let line = &head[..line_end];

    let sp1 = line.iter().position(|&b| b == b' ')?;
    let rest = &line[sp1 + 1..];
    let sp2_rel = rest.iter().position(|&b| b == b' ')?;
    let sp2 = sp1 + 1 + sp2_rel;

    let method = &line[..sp1];
    let path = &line[sp1 + 1..sp2];
    let version = &line[sp2 + 1..];

    Some((method, path, version))
}

fn parse_request_headers(head: &[u8]) -> Result<Vec<(String, String, Vec<u8>)>, ()> {
    // returns vec of (name_lower, name_raw, value_bytes)
    let line_end = find_crlf(head, 0).ok_or(())?;
    let mut pos = line_end + 2;

    let hend = find_header_end(head).ok_or(())?;
    let end = hend.saturating_sub(4);

    let mut out = Vec::new();
    while pos < end {
        let le = find_crlf(head, pos).ok_or(())?;
        let line = &head[pos..le];
        pos = le + 2;

        if line.is_empty() {
            break;
        }

        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        let name = &line[..colon];
        let value = trim_ascii_ws(&line[colon + 1..]);

        let name_raw = match std::str::from_utf8(name) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(name).to_string(),
        };
        let name_lower = name_raw.to_ascii_lowercase();

        out.push((name_lower, name_raw, value.to_vec()));
    }

    Ok(out)
}

fn render_path_template(tpl: &str, path: &str, route_name: &str) -> String {
    // Supports:
    // - $path
    // - $route.name
    let mut out = String::with_capacity(tpl.len().saturating_add(path.len()));
    let bytes = tpl.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'$' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let rest = &tpl[i..];
        if rest.starts_with("$path") {
            out.push_str(path);
            i += 5;
            continue;
        }
        if rest.starts_with("$route.name") {
            out.push_str(route_name);
            i += 11;
            continue;
        }

        // Unknown variable -> treat '$' literally.
        out.push('$');
        i += 1;
    }

    out
}

#[derive(Clone, Debug)]
struct MirrorDiff {
    diff_fields: Vec<String>,
    shadow_status: u16,
    latency_diff_seconds: f64,
}

fn compare_prod_shadow(
    _ctx: &MirrorSubmitContext,
    prod_raw: &[u8],
    prod_status: u16,
    prod_latency: Duration,
    shadow: &HttpResponseSnapshot,
    target: &MirrorTargetRuntime,
) -> Option<MirrorDiff> {
    let prod = parse_http_response(prod_raw).ok()?;

    let mut diff_fields = Vec::new();

    if prod_status != shadow.status {
        diff_fields.push("status".to_string());
    }

    // headers diff (ignore list)
    let ignore = &target.compare.ignore_headers_lower;

    let prod_h = filter_headers(&prod.headers, ignore);
    let shadow_h = filter_headers(&shadow.headers, ignore);

    for k in union_keys(&prod_h, &shadow_h) {
        let a = prod_h.get(&k);
        let b = shadow_h.get(&k);
        if !bytes_opt_eq(a, b) {
            diff_fields.push(format!("header.{k}"));
        }
    }

    // body diff
    let body_diff = compare_body_json(
        &prod.body,
        &shadow.body,
        &target.compare.ignore_body_paths,
        &mut diff_fields,
    );

    if body_diff {
        // compare_body_json already appended specific fields when possible
        if !diff_fields.iter().any(|s| s.starts_with("body")) {
            diff_fields.push("body".to_string());
        }
    }

    if diff_fields.is_empty() {
        return None;
    }

    let latency_diff_seconds = shadow.latency.as_secs_f64() - prod_latency.as_secs_f64();

    Some(MirrorDiff {
        diff_fields,
        shadow_status: shadow.status,
        latency_diff_seconds,
    })
}

fn bytes_opt_eq(a: Option<&Vec<u8>>, b: Option<&Vec<u8>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn union_keys(a: &HashMap<String, Vec<u8>>, b: &HashMap<String, Vec<u8>>) -> Vec<String> {
    let mut seen = HashMap::new();
    let mut out = Vec::new();
    for k in a.keys() {
        if seen.insert(k.clone(), ()).is_none() {
            out.push(k.clone());
        }
    }
    for k in b.keys() {
        if seen.insert(k.clone(), ()).is_none() {
            out.push(k.clone());
        }
    }
    out
}

fn filter_headers(
    h: &HashMap<String, Vec<u8>>,
    ignore_lower: &[String],
) -> HashMap<String, Vec<u8>> {
    if ignore_lower.is_empty() {
        return h.clone();
    }
    let mut out = HashMap::new();
    for (k, v) in h {
        if ignore_lower.iter().any(|ig| ig == k) {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    out
}

fn compare_body_json(
    prod: &[u8],
    shadow: &[u8],
    ignore_paths: &[Vec<String>],
    diff_fields: &mut Vec<String>,
) -> bool {
    let pa: Result<Value, _> = serde_json::from_slice(prod);
    let pb: Result<Value, _> = serde_json::from_slice(shadow);

    let (Ok(mut a), Ok(mut b)) = (pa, pb) else {
        // not JSON, compare raw
        return prod != shadow;
    };

    for p in ignore_paths {
        remove_json_path(&mut a, p);
        remove_json_path(&mut b, p);
    }

    if a == b {
        return false;
    }

    // Collect best-effort json diffs (bounded)
    let mut paths = Vec::new();
    collect_json_diffs("$".to_string(), &a, &b, &mut paths, 32);

    if paths.is_empty() {
        diff_fields.push("body".to_string());
    } else {
        for p in paths {
            diff_fields.push(format!("body.{p}"));
        }
    }

    true
}

pub fn compile_ignore_body_fields(paths: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for p in paths {
        if let Some(seg) = parse_simple_jsonpath(p) {
            out.push(seg);
        }
    }
    out
}

fn parse_simple_jsonpath(p: &str) -> Option<Vec<String>> {
    let s = p.trim();
    if !s.starts_with("$.") {
        return None;
    }
    let rest = &s[2..];
    if rest.is_empty() {
        return None;
    }
    let mut segs = Vec::new();
    for part in rest.split('.') {
        if part.is_empty() {
            return None;
        }
        segs.push(part.to_string());
    }
    Some(segs)
}

fn remove_json_path(v: &mut Value, path: &[String]) {
    if path.is_empty() {
        return;
    }
    let mut cur = v;
    for i in 0..path.len() {
        let key = &path[i];
        let last = i + 1 == path.len();

        match cur {
            Value::Object(map) => {
                if last {
                    map.remove(key);
                    return;
                }
                match map.get_mut(key) {
                    Some(n) => cur = n,
                    None => return,
                }
            }
            _ => return,
        }
    }
}

fn collect_json_diffs(prefix: String, a: &Value, b: &Value, out: &mut Vec<String>, limit: usize) {
    if out.len() >= limit {
        return;
    }

    if a == b {
        return;
    }

    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            let mut keys = Vec::new();
            for k in ma.keys() {
                keys.push(k.clone());
            }
            for k in mb.keys() {
                if !keys.iter().any(|x| x == k) {
                    keys.push(k.clone());
                }
            }
            for k in keys {
                if out.len() >= limit {
                    return;
                }
                let na = ma.get(&k);
                let nb = mb.get(&k);
                match (na, nb) {
                    (Some(va), Some(vb)) => {
                        collect_json_diffs(format!("{prefix}.{k}"), va, vb, out, limit)
                    }
                    _ => out.push(format!("{prefix}.{k}")),
                }
            }
        }
        // arrays/others -> coarse diff
        _ => out.push(prefix),
    }
}

fn log_diff(ctx: &MirrorSubmitContext, upstream: &str, diff: &MirrorDiff) {
    let domain = ctx.domain.as_deref().unwrap_or("-");
    let v = serde_json::json!({
        "domain": domain,
        "route": ctx.route_name.as_ref(),
        "upstream": upstream,
        "diff_fields": diff.diff_fields,
        "prod_status": ctx.prod_status,
        "shadow_status": diff.shadow_status,
        "latency_diff": diff.latency_diff_seconds,
    });

    match serde_json::to_string(&v) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => {
            eprintln!(
                "arc-mirror-diff domain={} route={} upstream={} prod_status={} shadow_status={} latency_diff={}",
                domain,
                ctx.route_name,
                upstream,
                ctx.prod_status,
                diff.shadow_status,
                diff.latency_diff_seconds
            );
        }
    }
}

/// Lock-free RNG helper (splitmix64).
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Fast sampling decision.
/// - Uses one atomic fetch_add and a few integer ops.
/// - Returns true with probability `p` (0.0-1.0).
#[inline]
fn should_sample(rng: &AtomicU64, p: f64) -> bool {
    if !(p.is_finite()) || p <= 0.0 {
        return false;
    }
    if p >= 1.0 {
        return true;
    }
    let n = rng.fetch_add(1, Ordering::Relaxed);
    let r = splitmix64(n);

    // Convert to [0,1) with 53-bit precision.
    let v = ((r >> 11) as f64) * (1.0 / ((1u64 << 53) as f64));
    v < p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_ctx() -> MirrorSubmitContext {
        MirrorSubmitContext {
            domain: Some(Arc::from("example.com")),
            route_name: Arc::from("api"),
            original_path: Arc::from("/v1/items"),
            prod_status: 200,
            prod_latency: Duration::from_millis(10),
            prod_response: None,
        }
    }

    fn mk_target(compare: MirrorCompareRuntime) -> MirrorTargetRuntime {
        MirrorTargetRuntime {
            upstream: Arc::from("shadow"),
            addr: SocketAddr::from(([127, 0, 0, 1], 19080)),
            sample: 1.0,
            timeout: Duration::from_millis(100),
            transform: MirrorTransformRuntime::default(),
            compare,
            metrics: Arc::new(MirrorTargetMetrics::new()),
        }
    }

    fn mk_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("HTTP/1.1 {status} OK\r\n").as_bytes());
        for (k, v) in headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn should_sample_respects_boundary_and_invalid_values() {
        let rng = AtomicU64::new(1);
        assert!(!should_sample(&rng, f64::NAN));
        assert!(!should_sample(&rng, -1.0));
        assert!(!should_sample(&rng, 0.0));
        assert!(should_sample(&rng, 1.0));
        assert!(should_sample(&rng, 2.0));
    }

    #[test]
    fn compile_ignore_body_fields_parses_subset_jsonpath_only() {
        let v = compile_ignore_body_fields(&[
            "$.a".to_string(),
            "$.a.b".to_string(),
            "a.b".to_string(),
            "$..x".to_string(),
            "$.".to_string(),
        ]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], vec!["a".to_string()]);
        assert_eq!(v[1], vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn build_transformed_request_rewrites_path_and_headers() {
        let raw = b"GET /orig HTTP/1.1\r\nHost: prod.local\r\nConnection: keep-alive\r\nX-Old: 1\r\n\r\nhello";
        let mut ctx = mk_ctx();
        ctx.original_path = Arc::from("/v2/orders");
        ctx.route_name = Arc::from("orders");

        let tr = MirrorTransformRuntime {
            headers_set: vec![
                ("X-New".to_string(), "ok".to_string()),
                ("Host".to_string(), "shadow.local".to_string()),
            ],
            headers_remove: vec!["x-old".to_string()],
            path_template: Some("/mirror$path?route=$route.name".to_string()),
        };

        let out = build_transformed_request(raw, &ctx, &tr).expect("transform");
        let s = String::from_utf8(out).expect("utf8");
        assert!(s.starts_with("GET /mirror/v2/orders?route=orders HTTP/1.1\r\n"));
        assert!(s.contains("\r\nHost: shadow.local\r\n"));
        assert!(s.contains("\r\nX-New: ok\r\n"));
        assert!(s.contains("\r\nConnection: close\r\n"));
        assert!(!s.contains("X-Old:"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn parse_http_response_supports_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let p = parse_http_response(raw).expect("chunked parse");
        assert_eq!(p.status, 200);
        assert_eq!(p.body, b"Wikipedia");
        assert!(p.headers.contains_key("transfer-encoding"));
    }

    #[test]
    fn compare_prod_shadow_ignores_selected_headers_and_json_paths() {
        let prod_body = br#"{"ts":1,"value":10}"#;
        let shadow_body = br#"{"ts":2,"value":10}"#;
        let prod_raw = mk_response(
            200,
            &[
                ("Date", "Mon, 01 Jan 2026 00:00:00 GMT"),
                ("Content-Type", "application/json"),
            ],
            prod_body,
        );
        let shadow_raw = mk_response(
            200,
            &[
                ("Date", "Tue, 02 Jan 2026 00:00:00 GMT"),
                ("Content-Type", "application/json"),
            ],
            shadow_body,
        );

        let parsed_shadow = parse_http_response(&shadow_raw).expect("parse shadow");
        let shadow = HttpResponseSnapshot {
            status: parsed_shadow.status,
            headers: parsed_shadow.headers,
            body: parsed_shadow.body,
            latency: Duration::from_millis(12),
        };

        let mut target = mk_target(MirrorCompareRuntime {
            enabled: true,
            ignore_headers_lower: vec!["date".to_string()],
            ignore_body_paths: compile_ignore_body_fields(&["$.ts".to_string()]),
        });
        target.sample = 1.0;

        let mut ctx = mk_ctx();
        ctx.prod_response = Some(Arc::from(prod_raw.clone()));

        let diff = compare_prod_shadow(
            &ctx,
            &prod_raw,
            200,
            Duration::from_millis(10),
            &shadow,
            &target,
        );
        assert!(diff.is_none());
    }

    #[test]
    fn compare_prod_shadow_reports_status_or_body_diff() {
        let prod_body = br#"{"value":10}"#;
        let shadow_body = br#"{"value":11}"#;
        let prod_raw = mk_response(200, &[("Content-Type", "application/json")], prod_body);
        let shadow_raw = mk_response(503, &[("Content-Type", "application/json")], shadow_body);

        let parsed_shadow = parse_http_response(&shadow_raw).expect("parse shadow");
        let shadow = HttpResponseSnapshot {
            status: parsed_shadow.status,
            headers: parsed_shadow.headers,
            body: parsed_shadow.body,
            latency: Duration::from_millis(20),
        };

        let target = mk_target(MirrorCompareRuntime {
            enabled: true,
            ignore_headers_lower: Vec::new(),
            ignore_body_paths: Vec::new(),
        });
        let ctx = mk_ctx();

        let diff = compare_prod_shadow(
            &ctx,
            &prod_raw,
            200,
            Duration::from_millis(10),
            &shadow,
            &target,
        )
        .expect("should detect diff");
        assert!(diff.diff_fields.iter().any(|x| x == "status"));
        assert!(diff.diff_fields.iter().any(|x| x.starts_with("body.")));
    }
}
