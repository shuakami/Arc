use arc_common::{ArcError, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

pub const PHASE_COUNT: usize = 5;

#[repr(C, align(64))]
pub struct WorkerMetrics {
    pub accepted_total: AtomicU64,
    pub accept_rejected_total: AtomicU64,
    pub active_current: AtomicU64,
    pub closed_total: AtomicU64,

    pub req_total: AtomicU64,
    pub resp_total: AtomicU64,

    pub bytes_cli_in: AtomicU64,
    pub bytes_cli_out: AtomicU64,
    pub bytes_up_in: AtomicU64,
    pub bytes_up_out: AtomicU64,

    pub phase_time_sum_ns: [AtomicU64; PHASE_COUNT],
    pub phase_count: [AtomicU64; PHASE_COUNT],
    pub phase_timeouts: [AtomicU64; PHASE_COUNT],

    pub ring_sq_dropped: AtomicU64,
    pub ring_cq_overflow: AtomicU64,

    pub mirror_submitted_total: AtomicU64,
    pub mirror_sent_total: AtomicU64,
    pub mirror_queue_full_total: AtomicU64,
    pub mirror_timeout_total: AtomicU64,
    pub mirror_upstream_error_total: AtomicU64,
    pub mirror_status_2xx_total: AtomicU64,
    pub mirror_status_3xx_total: AtomicU64,
    pub mirror_status_4xx_total: AtomicU64,
    pub mirror_status_5xx_total: AtomicU64,
    pub mirror_status_other_total: AtomicU64,
    pub mirror_latency_count: AtomicU64,
    pub mirror_latency_sum_ns: AtomicU64,

    pub upstream_pool_open_current: AtomicU64,
    pub upstream_pool_idle_current: AtomicU64,
    pub upstream_pool_busy_current: AtomicU64,
    pub upstream_pool_keepalive_capacity_current: AtomicU64,
}

impl WorkerMetrics {
    pub fn new() -> Self {
        Self {
            accepted_total: AtomicU64::new(0),
            accept_rejected_total: AtomicU64::new(0),
            active_current: AtomicU64::new(0),
            closed_total: AtomicU64::new(0),

            req_total: AtomicU64::new(0),
            resp_total: AtomicU64::new(0),

            bytes_cli_in: AtomicU64::new(0),
            bytes_cli_out: AtomicU64::new(0),
            bytes_up_in: AtomicU64::new(0),
            bytes_up_out: AtomicU64::new(0),

            phase_time_sum_ns: new_atomic_u64_array(),
            phase_count: new_atomic_u64_array(),
            phase_timeouts: new_atomic_u64_array(),

            ring_sq_dropped: AtomicU64::new(0),
            ring_cq_overflow: AtomicU64::new(0),

            mirror_submitted_total: AtomicU64::new(0),
            mirror_sent_total: AtomicU64::new(0),
            mirror_queue_full_total: AtomicU64::new(0),
            mirror_timeout_total: AtomicU64::new(0),
            mirror_upstream_error_total: AtomicU64::new(0),
            mirror_status_2xx_total: AtomicU64::new(0),
            mirror_status_3xx_total: AtomicU64::new(0),
            mirror_status_4xx_total: AtomicU64::new(0),
            mirror_status_5xx_total: AtomicU64::new(0),
            mirror_status_other_total: AtomicU64::new(0),
            mirror_latency_count: AtomicU64::new(0),
            mirror_latency_sum_ns: AtomicU64::new(0),

            upstream_pool_open_current: AtomicU64::new(0),
            upstream_pool_idle_current: AtomicU64::new(0),
            upstream_pool_busy_current: AtomicU64::new(0),
            upstream_pool_keepalive_capacity_current: AtomicU64::new(0),
        }
    }
}

const fn new_atomic_u64_array() -> [AtomicU64; PHASE_COUNT] {
    // AtomicU64::new is const, so we can build fixed array without runtime heap.
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ]
}

#[derive(Clone)]
pub struct MetricsRegistry {
    pub workers: Arc<[Arc<WorkerMetrics>]>,
}

impl MetricsRegistry {
    pub fn new(worker_count: usize) -> Self {
        let mut v: Vec<Arc<WorkerMetrics>> = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            v.push(Arc::new(WorkerMetrics::new()));
        }
        Self { workers: v.into() }
    }

    pub fn worker(&self, id: usize) -> Arc<WorkerMetrics> {
        self.workers
            .get(id)
            .cloned()
            .unwrap_or_else(|| Arc::new(WorkerMetrics::new()))
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // helpers
        fn push_counter(out: &mut String, name: &str, help: &str, val: u64) {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" counter\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&val.to_string());
            out.push('\n');
        }

        fn push_gauge(out: &mut String, name: &str, help: &str, val: u64) {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" gauge\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&val.to_string());
            out.push('\n');
        }

        let mut accepted = 0u64;
        let mut accept_rejected = 0u64;
        let mut active = 0u64;
        let mut closed = 0u64;

        let mut req = 0u64;
        let mut resp = 0u64;

        let mut bci = 0u64;
        let mut bco = 0u64;
        let mut bui = 0u64;
        let mut buo = 0u64;

        let mut phase_sum = [0u64; PHASE_COUNT];
        let mut phase_cnt = [0u64; PHASE_COUNT];
        let mut phase_to = [0u64; PHASE_COUNT];

        let mut sqd = 0u64;
        let mut cqo = 0u64;

        let mut m_submitted = 0u64;
        let mut m_sent = 0u64;
        let mut m_queue_full = 0u64;
        let mut m_timeout = 0u64;
        let mut m_up_err = 0u64;
        let mut m_2xx = 0u64;
        let mut m_3xx = 0u64;
        let mut m_4xx = 0u64;
        let mut m_5xx = 0u64;
        let mut m_other = 0u64;
        let mut m_lat_cnt = 0u64;
        let mut m_lat_sum_ns = 0u64;
        let mut up_pool_open = 0u64;
        let mut up_pool_idle = 0u64;
        let mut up_pool_busy = 0u64;
        let mut up_pool_keepalive_cap = 0u64;

        for w in self.workers.iter() {
            accepted = accepted.saturating_add(w.accepted_total.load(Ordering::Relaxed));
            accept_rejected =
                accept_rejected.saturating_add(w.accept_rejected_total.load(Ordering::Relaxed));
            active = active.saturating_add(w.active_current.load(Ordering::Relaxed));
            closed = closed.saturating_add(w.closed_total.load(Ordering::Relaxed));

            req = req.saturating_add(w.req_total.load(Ordering::Relaxed));
            resp = resp.saturating_add(w.resp_total.load(Ordering::Relaxed));

            bci = bci.saturating_add(w.bytes_cli_in.load(Ordering::Relaxed));
            bco = bco.saturating_add(w.bytes_cli_out.load(Ordering::Relaxed));
            bui = bui.saturating_add(w.bytes_up_in.load(Ordering::Relaxed));
            buo = buo.saturating_add(w.bytes_up_out.load(Ordering::Relaxed));

            for i in 0..PHASE_COUNT {
                phase_sum[i] =
                    phase_sum[i].saturating_add(w.phase_time_sum_ns[i].load(Ordering::Relaxed));
                phase_cnt[i] =
                    phase_cnt[i].saturating_add(w.phase_count[i].load(Ordering::Relaxed));
                phase_to[i] =
                    phase_to[i].saturating_add(w.phase_timeouts[i].load(Ordering::Relaxed));
            }

            sqd = sqd.saturating_add(w.ring_sq_dropped.load(Ordering::Relaxed));
            cqo = cqo.saturating_add(w.ring_cq_overflow.load(Ordering::Relaxed));

            m_submitted =
                m_submitted.saturating_add(w.mirror_submitted_total.load(Ordering::Relaxed));
            m_sent = m_sent.saturating_add(w.mirror_sent_total.load(Ordering::Relaxed));
            m_queue_full =
                m_queue_full.saturating_add(w.mirror_queue_full_total.load(Ordering::Relaxed));
            m_timeout = m_timeout.saturating_add(w.mirror_timeout_total.load(Ordering::Relaxed));
            m_up_err =
                m_up_err.saturating_add(w.mirror_upstream_error_total.load(Ordering::Relaxed));
            m_2xx = m_2xx.saturating_add(w.mirror_status_2xx_total.load(Ordering::Relaxed));
            m_3xx = m_3xx.saturating_add(w.mirror_status_3xx_total.load(Ordering::Relaxed));
            m_4xx = m_4xx.saturating_add(w.mirror_status_4xx_total.load(Ordering::Relaxed));
            m_5xx = m_5xx.saturating_add(w.mirror_status_5xx_total.load(Ordering::Relaxed));
            m_other = m_other.saturating_add(w.mirror_status_other_total.load(Ordering::Relaxed));
            m_lat_cnt = m_lat_cnt.saturating_add(w.mirror_latency_count.load(Ordering::Relaxed));
            m_lat_sum_ns =
                m_lat_sum_ns.saturating_add(w.mirror_latency_sum_ns.load(Ordering::Relaxed));
            up_pool_open =
                up_pool_open.saturating_add(w.upstream_pool_open_current.load(Ordering::Relaxed));
            up_pool_idle =
                up_pool_idle.saturating_add(w.upstream_pool_idle_current.load(Ordering::Relaxed));
            up_pool_busy =
                up_pool_busy.saturating_add(w.upstream_pool_busy_current.load(Ordering::Relaxed));
            up_pool_keepalive_cap = up_pool_keepalive_cap.saturating_add(
                w.upstream_pool_keepalive_capacity_current
                    .load(Ordering::Relaxed),
            );
        }

        push_counter(
            &mut out,
            "arc_accepted_total",
            "Total accepted downstream connections",
            accepted,
        );
        push_counter(
            &mut out,
            "arc_accept_rejected_total",
            "Total downstream accepts rejected by local resource limits",
            accept_rejected,
        );
        push_gauge(
            &mut out,
            "arc_active_current",
            "Current active downstream connections",
            active,
        );
        push_counter(
            &mut out,
            "arc_closed_total",
            "Total closed downstream connections",
            closed,
        );

        push_counter(
            &mut out,
            "arc_requests_total",
            "Total completed requests",
            req,
        );
        push_counter(
            &mut out,
            "arc_responses_total",
            "Total completed responses",
            resp,
        );

        push_counter(
            &mut out,
            "arc_bytes_client_in_total",
            "Bytes read from client",
            bci,
        );
        push_counter(
            &mut out,
            "arc_bytes_client_out_total",
            "Bytes written to client",
            bco,
        );
        push_counter(
            &mut out,
            "arc_bytes_upstream_in_total",
            "Bytes read from upstream",
            bui,
        );
        push_counter(
            &mut out,
            "arc_bytes_upstream_out_total",
            "Bytes written to upstream",
            buo,
        );

        let phase_names = ["cli_read", "up_conn", "up_write", "up_read", "cli_write"];
        for i in 0..PHASE_COUNT {
            let sum_name = format!("arc_phase_time_sum_ns_{}", phase_names[i]);
            let cnt_name = format!("arc_phase_count_{}", phase_names[i]);
            let to_name = format!("arc_phase_timeouts_{}", phase_names[i]);

            push_counter(&mut out, &sum_name, "Phase time sum in ns", phase_sum[i]);
            push_counter(&mut out, &cnt_name, "Phase count", phase_cnt[i]);
            push_counter(&mut out, &to_name, "Phase timeouts", phase_to[i]);
        }

        push_counter(
            &mut out,
            "arc_ring_sq_dropped_total",
            "io_uring SQ dropped",
            sqd,
        );
        push_counter(
            &mut out,
            "arc_ring_cq_overflow_total",
            "io_uring CQ overflow",
            cqo,
        );

        push_counter(
            &mut out,
            "arc_mirror_submitted_total",
            "Total mirror tasks submitted from request path",
            m_submitted,
        );
        push_counter(
            &mut out,
            "arc_mirror_sent_total",
            "Total mirror tasks that completed successfully",
            m_sent,
        );
        push_counter(
            &mut out,
            "arc_mirror_queue_full_total",
            "Total mirror tasks dropped due to queue memory cap",
            m_queue_full,
        );
        push_counter(
            &mut out,
            "arc_mirror_timeout_total",
            "Total mirror tasks dropped due to timeout",
            m_timeout,
        );
        push_counter(
            &mut out,
            "arc_mirror_upstream_error_total",
            "Total mirror tasks dropped due to upstream errors/panic",
            m_up_err,
        );
        push_counter(
            &mut out,
            "arc_mirror_status_2xx_total",
            "Total mirror upstream responses with 2xx status",
            m_2xx,
        );
        push_counter(
            &mut out,
            "arc_mirror_status_3xx_total",
            "Total mirror upstream responses with 3xx status",
            m_3xx,
        );
        push_counter(
            &mut out,
            "arc_mirror_status_4xx_total",
            "Total mirror upstream responses with 4xx status",
            m_4xx,
        );
        push_counter(
            &mut out,
            "arc_mirror_status_5xx_total",
            "Total mirror upstream responses with 5xx status",
            m_5xx,
        );
        push_counter(
            &mut out,
            "arc_mirror_status_other_total",
            "Total mirror upstream responses with non-2xx/3xx/4xx/5xx status",
            m_other,
        );
        push_counter(
            &mut out,
            "arc_mirror_latency_count",
            "Mirror latency sample count",
            m_lat_cnt,
        );
        push_counter(
            &mut out,
            "arc_mirror_latency_sum_ns",
            "Mirror latency sum in nanoseconds",
            m_lat_sum_ns,
        );
        push_gauge(
            &mut out,
            "arc_upstream_pool_open_current",
            "Current open upstream connections (idle + busy)",
            up_pool_open,
        );
        push_gauge(
            &mut out,
            "arc_upstream_pool_idle_current",
            "Current idle upstream connections in keepalive pools",
            up_pool_idle,
        );
        push_gauge(
            &mut out,
            "arc_upstream_pool_busy_current",
            "Current busy upstream connections (open minus idle)",
            up_pool_busy,
        );
        push_gauge(
            &mut out,
            "arc_upstream_pool_keepalive_capacity_current",
            "Current keepalive capacity across upstream pools",
            up_pool_keepalive_cap,
        );

        let log_metrics = arc_logging::global_metrics_render_prometheus();
        if !log_metrics.is_empty() {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&log_metrics);
        }

        out
    }
}

const METRICS_CACHE_REFRESH_MS: u64 = 250;

#[derive(Clone)]
struct AdminServeState {
    metrics_cache: Arc<RwLock<String>>,
    auth_token: Option<Arc<str>>,
}

pub fn start_admin_server(
    addr: SocketAddr,
    reg: MetricsRegistry,
    auth_token: Option<Arc<str>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| ArcError::io("bind admin_listen", e))?;
    let metrics_cache = Arc::new(RwLock::new(reg.render_prometheus()));

    {
        let reg = reg.clone();
        let cache = metrics_cache.clone();
        thread::Builder::new()
            .name("arc-admin-metrics-cache".to_string())
            .spawn(move || loop {
                let snapshot = reg.render_prometheus();
                match cache.write() {
                    Ok(mut g) => *g = snapshot,
                    Err(poisoned) => *poisoned.into_inner() = snapshot,
                }
                thread::sleep(Duration::from_millis(METRICS_CACHE_REFRESH_MS));
            })
            .map_err(|e| ArcError::io("spawn admin metrics cache", e))?;
    }

    let state = Arc::new(AdminServeState {
        metrics_cache,
        auth_token,
    });

    thread::Builder::new()
        .name("arc-admin".to_string())
        .spawn(move || loop {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let _ = handle_admin_conn(&mut stream, &state);
        })
        .map_err(|e| ArcError::io("spawn admin server", e))?;

    Ok(())
}

fn handle_admin_conn(stream: &mut TcpStream, state: &AdminServeState) -> Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream
        .read(&mut buf)
        .map_err(|e| ArcError::io("admin read", e))?;
    if n == 0 {
        return Ok(());
    }
    let req = &buf[..n];

    if !admin_authorized(req, state.auth_token.as_deref(), stream.peer_addr().ok()) {
        return write_plain_response(stream, "401 Unauthorized", "unauthorized\n");
    }

    let is_metrics = req.starts_with(b"GET /metrics ");
    let is_health = req.starts_with(b"GET /healthz ");
    let body = if is_metrics {
        match state.metrics_cache.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    } else if is_health {
        "ok\n".to_string()
    } else {
        "not found\n".to_string()
    };

    let status = if is_metrics || is_health {
        "200 OK"
    } else {
        "404 Not Found"
    };

    write_plain_response(stream, status, body.as_str())?;
    Ok(())
}

fn write_plain_response(stream: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| ArcError::io("admin write", e))
}

fn admin_authorized(req: &[u8], token: Option<&str>, peer_addr: Option<SocketAddr>) -> bool {
    let Some(token) = token else {
        return peer_addr.map(|a| a.ip().is_loopback()).unwrap_or(false);
    };
    let expected = format!("Bearer {token}");
    for raw_line in req.split(|b| *b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (name, rest) = line.split_at(colon);
        if !name.eq_ignore_ascii_case(b"authorization") {
            continue;
        }
        let value = trim_ascii_http_ws(&rest[1..]);
        return value == expected.as_bytes();
    }
    false
}

fn trim_ascii_http_ws(mut s: &[u8]) -> &[u8] {
    while let Some(b) = s.first() {
        if *b == b' ' || *b == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(b) = s.last() {
        if *b == b' ' || *b == b'\t' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_authorized_without_token_allows_only_loopback() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(admin_authorized(
            req,
            None,
            Some(SocketAddr::from(([127, 0, 0, 1], 12000)))
        ));
        assert!(!admin_authorized(
            req,
            None,
            Some(SocketAddr::from(([10, 0, 0, 2], 12000)))
        ));
        assert!(!admin_authorized(req, None, None));
    }

    #[test]
    fn admin_authorized_with_token_requires_matching_bearer_header() {
        let ok = b"GET /metrics HTTP/1.1\r\nAuthorization:   Bearer tkn  \r\n\r\n";
        assert!(admin_authorized(
            ok,
            Some("tkn"),
            Some(SocketAddr::from(([10, 0, 0, 1], 9999)))
        ));

        let wrong = b"GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n";
        assert!(!admin_authorized(
            wrong,
            Some("tkn"),
            Some(SocketAddr::from(([127, 0, 0, 1], 9999)))
        ));

        let basic = b"GET /metrics HTTP/1.1\r\nAuthorization: Basic abc\r\n\r\n";
        assert!(!admin_authorized(
            basic,
            Some("tkn"),
            Some(SocketAddr::from(([127, 0, 0, 1], 9999)))
        ));
    }

    #[test]
    fn render_prometheus_aggregates_worker_counters() {
        let reg = MetricsRegistry::new(2);
        let w0 = reg.worker(0);
        let w1 = reg.worker(1);

        w0.accepted_total.store(2, Ordering::Relaxed);
        w1.accepted_total.store(3, Ordering::Relaxed);
        w0.active_current.store(1, Ordering::Relaxed);
        w1.active_current.store(4, Ordering::Relaxed);
        w0.mirror_submitted_total.store(5, Ordering::Relaxed);
        w1.mirror_submitted_total.store(7, Ordering::Relaxed);
        w0.mirror_status_2xx_total.store(11, Ordering::Relaxed);
        w1.mirror_status_2xx_total.store(13, Ordering::Relaxed);
        w0.upstream_pool_open_current.store(6, Ordering::Relaxed);
        w1.upstream_pool_open_current.store(4, Ordering::Relaxed);
        w0.upstream_pool_idle_current.store(2, Ordering::Relaxed);
        w1.upstream_pool_idle_current.store(3, Ordering::Relaxed);
        w0.upstream_pool_busy_current.store(4, Ordering::Relaxed);
        w1.upstream_pool_busy_current.store(1, Ordering::Relaxed);
        w0.upstream_pool_keepalive_capacity_current
            .store(8, Ordering::Relaxed);
        w1.upstream_pool_keepalive_capacity_current
            .store(10, Ordering::Relaxed);

        let out = reg.render_prometheus();
        assert!(out.contains("arc_accepted_total 5"));
        assert!(out.contains("arc_active_current 5"));
        assert!(out.contains("arc_mirror_submitted_total 12"));
        assert!(out.contains("arc_mirror_status_2xx_total 24"));
        assert!(out.contains("arc_upstream_pool_open_current 10"));
        assert!(out.contains("arc_upstream_pool_idle_current 5"));
        assert!(out.contains("arc_upstream_pool_busy_current 5"));
        assert!(out.contains("arc_upstream_pool_keepalive_capacity_current 18"));
    }
}
