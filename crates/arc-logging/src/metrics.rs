use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Prometheus histogram buckets for `arc_log_write_duration_seconds`.
///
/// Exposed for tests/inspection; buckets are in seconds.
pub const LOG_WRITE_DURATION_BUCKETS_SECONDS: [f64; 12] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

const LOG_WRITE_DURATION_BUCKETS_NS: [u64; 12] = [
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_500_000_000,
];

#[derive(Debug)]
pub struct LogMetrics {
    written_access: AtomicU64,
    written_system: AtomicU64,
    written_debug: AtomicU64,
    write_errors: AtomicU64,

    dropped_buffer_full: AtomicU64,
    dropped_sampling: AtomicU64,
    compress_dropped: AtomicU64,

    buffer_depth: AtomicU64,

    force_written_status: AtomicU64,
    force_written_error_record: AtomicU64,
    force_written_slow: AtomicU64,

    write_dur_count: AtomicU64,
    write_dur_sum_ns: AtomicU64,
    write_dur_buckets: [AtomicU64; LOG_WRITE_DURATION_BUCKETS_NS.len()],
}

impl Default for LogMetrics {
    fn default() -> Self {
        Self {
            written_access: AtomicU64::new(0),
            written_system: AtomicU64::new(0),
            written_debug: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            dropped_buffer_full: AtomicU64::new(0),
            dropped_sampling: AtomicU64::new(0),
            compress_dropped: AtomicU64::new(0),
            buffer_depth: AtomicU64::new(0),
            force_written_status: AtomicU64::new(0),
            force_written_error_record: AtomicU64::new(0),
            force_written_slow: AtomicU64::new(0),
            write_dur_count: AtomicU64::new(0),
            write_dur_sum_ns: AtomicU64::new(0),
            write_dur_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl LogMetrics {
    /// Increment dropped due to ring buffer full.
    pub fn inc_dropped_buffer_full(&self) {
        self.dropped_buffer_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment dropped due to sampling decision.
    pub fn inc_dropped_sampling(&self) {
        self.dropped_sampling.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment dropped compression task count (bounded compression queue full/disconnected).
    pub fn inc_compress_dropped(&self) {
        self.compress_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment log writer write-error count.
    pub fn inc_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment forced written (status in force_on_status).
    pub fn inc_force_written_status(&self) {
        self.force_written_status.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment forced written (explicit access-error record).
    pub fn inc_force_written_error_record(&self) {
        self.force_written_error_record
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment forced written (slow).
    pub fn inc_force_written_slow(&self) {
        self.force_written_slow.fetch_add(1, Ordering::Relaxed);
    }

    /// Set ring buffer depth gauge (typically sum of all per-worker ring depths).
    pub fn set_buffer_depth(&self, depth: u64) {
        self.buffer_depth.store(depth, Ordering::Relaxed);
    }

    /// Increment written access logs.
    pub fn add_written_access(&self, n: u64) {
        self.written_access.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment written system logs.
    pub fn add_written_system(&self, n: u64) {
        self.written_system.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment written debug logs.
    pub fn add_written_debug(&self, n: u64) {
        self.written_debug.fetch_add(n, Ordering::Relaxed);
    }

    /// Record write duration into histogram.
    pub fn record_write_duration(&self, d: Duration) {
        let ns = d
            .as_secs()
            .saturating_mul(1_000_000_000)
            .saturating_add(d.subsec_nanos() as u64);

        self.write_dur_count.fetch_add(1, Ordering::Relaxed);
        self.write_dur_sum_ns.fetch_add(ns, Ordering::Relaxed);

        for (i, &b) in LOG_WRITE_DURATION_BUCKETS_NS.iter().enumerate() {
            if ns <= b {
                self.write_dur_buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // +Inf bucket is rendered as count; we don't store separately.
    }

    /// Render prometheus metrics text.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        // HELP/TYPE for counters with labels.
        push_help(&mut out, "arc_log_written_total", "Total written logs");
        push_type(&mut out, "arc_log_written_total", "counter");
        push_counter_labeled(
            &mut out,
            "arc_log_written_total",
            "kind",
            "access",
            self.written_access.load(Ordering::Relaxed),
        );
        push_counter_labeled(
            &mut out,
            "arc_log_written_total",
            "kind",
            "system",
            self.written_system.load(Ordering::Relaxed),
        );
        push_counter_labeled(
            &mut out,
            "arc_log_written_total",
            "kind",
            "debug",
            self.written_debug.load(Ordering::Relaxed),
        );

        push_help(&mut out, "arc_log_dropped_total", "Total dropped logs");
        push_type(&mut out, "arc_log_dropped_total", "counter");
        push_counter_labeled(
            &mut out,
            "arc_log_dropped_total",
            "reason",
            "buffer_full",
            self.dropped_buffer_full.load(Ordering::Relaxed),
        );
        push_counter_labeled(
            &mut out,
            "arc_log_dropped_total",
            "reason",
            "sampling",
            self.dropped_sampling.load(Ordering::Relaxed),
        );
        push_counter_labeled(
            &mut out,
            "arc_log_dropped_total",
            "reason",
            "compress_queue_full",
            self.compress_dropped.load(Ordering::Relaxed),
        );

        push_help(
            &mut out,
            "arc_log_write_errors_total",
            "Total io_uring/stdout/file write failures in log writer",
        );
        push_type(&mut out, "arc_log_write_errors_total", "counter");
        push_counter(
            &mut out,
            "arc_log_write_errors_total",
            self.write_errors.load(Ordering::Relaxed),
        );

        push_help(
            &mut out,
            "arc_log_compress_dropped_total",
            "Total dropped gzip compression tasks due to bounded queue pressure",
        );
        push_type(&mut out, "arc_log_compress_dropped_total", "counter");
        push_counter(
            &mut out,
            "arc_log_compress_dropped_total",
            self.compress_dropped.load(Ordering::Relaxed),
        );

        push_help(
            &mut out,
            "arc_log_buffer_depth",
            "Current total ring buffer depth",
        );
        push_type(&mut out, "arc_log_buffer_depth", "gauge");
        push_gauge(
            &mut out,
            "arc_log_buffer_depth",
            self.buffer_depth.load(Ordering::Relaxed),
        );

        push_help(
            &mut out,
            "arc_log_force_written_total",
            "Total forced-written access logs",
        );
        push_type(&mut out, "arc_log_force_written_total", "counter");
        push_counter_labeled(
            &mut out,
            "arc_log_force_written_total",
            "reason",
            "status",
            self.force_written_status.load(Ordering::Relaxed),
        );
        push_counter_labeled(
            &mut out,
            "arc_log_force_written_total",
            "reason",
            "error_record",
            self.force_written_error_record.load(Ordering::Relaxed),
        );
        push_counter_labeled(
            &mut out,
            "arc_log_force_written_total",
            "reason",
            "slow",
            self.force_written_slow.load(Ordering::Relaxed),
        );

        // Histogram
        push_help(
            &mut out,
            "arc_log_write_duration_seconds",
            "io_uring batch write duration in seconds",
        );
        push_type(&mut out, "arc_log_write_duration_seconds", "histogram");

        let count = self.write_dur_count.load(Ordering::Relaxed);
        let sum_ns = self.write_dur_sum_ns.load(Ordering::Relaxed);
        let sum_sec = (sum_ns as f64) / 1_000_000_000.0;

        // Prometheus histogram buckets are cumulative; we stored "first matching bucket" increments.
        // Convert to cumulative at render time.
        let mut cum = 0u64;
        for (i, &sec) in LOG_WRITE_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            let v = self.write_dur_buckets[i].load(Ordering::Relaxed);
            cum = cum.saturating_add(v);
            push_hist_bucket(&mut out, "arc_log_write_duration_seconds", sec, cum);
        }
        // +Inf bucket equals total count
        push_hist_bucket_inf(&mut out, "arc_log_write_duration_seconds", count);
        push_hist_sum(&mut out, "arc_log_write_duration_seconds", sum_sec);
        push_hist_count(&mut out, "arc_log_write_duration_seconds", count);

        out
    }
}

fn push_help(out: &mut String, name: &str, help: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
}

fn push_type(out: &mut String, name: &str, typ: &str) {
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(typ);
    out.push('\n');
}

fn push_counter_labeled(out: &mut String, name: &str, k: &str, v: &str, val: u64) {
    out.push_str(name);
    out.push('{');
    out.push_str(k);
    out.push_str("=\"");
    out.push_str(v);
    out.push_str("\"} ");
    out.push_str(&val.to_string());
    out.push('\n');
}

fn push_counter(out: &mut String, name: &str, val: u64) {
    out.push_str(name);
    out.push(' ');
    out.push_str(&val.to_string());
    out.push('\n');
}

fn push_gauge(out: &mut String, name: &str, val: u64) {
    out.push_str(name);
    out.push(' ');
    out.push_str(&val.to_string());
    out.push('\n');
}

fn push_hist_bucket(out: &mut String, name: &str, le: f64, val: u64) {
    out.push_str(name);
    out.push_str("_bucket{le=\"");
    out.push_str(&format!("{le}"));
    out.push_str("\"} ");
    out.push_str(&val.to_string());
    out.push('\n');
}

fn push_hist_bucket_inf(out: &mut String, name: &str, val: u64) {
    out.push_str(name);
    out.push_str("_bucket{le=\"+Inf\"} ");
    out.push_str(&val.to_string());
    out.push('\n');
}

fn push_hist_sum(out: &mut String, name: &str, sum: f64) {
    out.push_str(name);
    out.push_str("_sum ");
    out.push_str(&format!("{sum}"));
    out.push('\n');
}

fn push_hist_count(out: &mut String, name: &str, count: u64) {
    out.push_str(name);
    out.push_str("_count ");
    out.push_str(&count.to_string());
    out.push('\n');
}
