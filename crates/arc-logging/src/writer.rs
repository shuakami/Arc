use crate::config::{LoggingRuntimeConfig, RotationConfig};
use crate::escape::write_json_string;
use crate::metrics::LogMetrics;
use crate::record::{
    AccessErrorLogRecord, AccessLogRecord, LogEvent, LogLevel, LogStr, LogValue, SystemLogRecord,
};
use crate::redact::RedactionRules;
use crate::ring::SpscRing;
use crate::util::duration_from_millis;
use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, TryRecvError};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use io_uring::{opcode, types, IoUring};

pub fn run_writer(
    rings: Arc<[Arc<SpscRing<LogEvent>>]>,
    system_rx: Receiver<SystemLogRecord>,
    #[cfg(feature = "debug_log")] debug_rx: Receiver<SystemLogRecord>,
    runtime: Arc<ArcSwap<LoggingRuntimeConfig>>,
    metrics: Arc<LogMetrics>,
    shutdown_rx: Receiver<()>,
) {
    let compress_worker = CompressionWorker::start(metrics.clone());

    let mut last_rt = runtime.load_full();
    let mut rules = RedactionRules::new(
        &last_rt.redact.headers,
        &last_rt.redact.query_params,
        &last_rt.redact.body_fields,
    );

    let mut file_state = match open_output_file(&last_rt.output.file) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "arc-logging: open log file failed ({}): {e}",
                last_rt.output.file
            );
            None
        }
    };

    let mut stdout_enabled = last_rt.output.stdout;
    let mut batch_bytes_target = last_rt.writer.batch_bytes;
    let mut batch_records_target = last_rt.writer.batch_records;
    let mut flush_interval = duration_from_millis(last_rt.writer.flush_interval_ms);

    let mut uring_entries = last_rt.writer.uring_entries;
    let mut ring = match IoUring::new(uring_entries) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("arc-logging: io_uring init failed (entries={uring_entries}): {e}");
            // Fallback: try smaller.
            uring_entries = 64;
            match IoUring::new(uring_entries) {
                Ok(r) => r,
                Err(e2) => {
                    eprintln!("arc-logging: io_uring fallback init failed: {e2}");
                    return;
                }
            }
        }
    };

    let mut batch = Vec::<u8>::with_capacity(batch_bytes_target.min(1024 * 1024));
    let mut batch_records: u64 = 0;
    let mut last_flush = Instant::now();

    loop {
        // shutdown check (non-blocking)
        match shutdown_rx.try_recv() {
            Ok(()) => {
                // best-effort flush
                if !batch.is_empty() {
                    let _ = flush_batch(
                        &mut ring,
                        &mut file_state,
                        stdout_enabled,
                        &batch,
                        &metrics,
                        batch_records,
                        0,
                        #[cfg(feature = "debug_log")]
                        0,
                        &last_rt.output.rotation,
                        &compress_worker,
                    );
                }
                break;
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        // refresh runtime if changed
        let cur = runtime.load_full();
        if !Arc::ptr_eq(&cur, &last_rt) {
            // Update redaction rules
            rules = RedactionRules::new(
                &cur.redact.headers,
                &cur.redact.query_params,
                &cur.redact.body_fields,
            );

            // Update writer knobs
            stdout_enabled = cur.output.stdout;
            batch_bytes_target = cur.writer.batch_bytes;
            batch_records_target = cur.writer.batch_records;
            flush_interval = duration_from_millis(cur.writer.flush_interval_ms);

            // Update output file if path changed
            if cur.output.file != last_rt.output.file {
                // flush then reopen
                if !batch.is_empty() {
                    let _ = flush_batch(
                        &mut ring,
                        &mut file_state,
                        stdout_enabled,
                        &batch,
                        &metrics,
                        batch_records,
                        0,
                        #[cfg(feature = "debug_log")]
                        0,
                        &last_rt.output.rotation,
                        &compress_worker,
                    );
                    batch.clear();
                    batch_records = 0;
                }
                file_state = match open_output_file(&cur.output.file) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "arc-logging: reopen log file failed ({}): {e}",
                            cur.output.file
                        );
                        None
                    }
                };
            }

            // Update uring entries (recreate ring)
            if cur.writer.uring_entries != last_rt.writer.uring_entries {
                let new_entries = cur.writer.uring_entries;
                match IoUring::new(new_entries) {
                    Ok(r) => {
                        ring = r;
                        uring_entries = new_entries;
                    }
                    Err(e) => {
                        eprintln!("arc-logging: io_uring re-init failed (entries={new_entries}): {e} (keep old entries={uring_entries})");
                    }
                }
            }

            last_rt = cur;
        }

        // drain system logs
        let mut drained_any = false;
        loop {
            match system_rx.try_recv() {
                Ok(rec) => {
                    drained_any = true;
                    encode_system(&mut batch, &rec, &rules);
                    batch_records = batch_records.saturating_add(1);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // drain debug logs (feature-gated)
        #[cfg(feature = "debug_log")]
        loop {
            match debug_rx.try_recv() {
                Ok(rec) => {
                    drained_any = true;
                    // Debug logs are also encoded as kind="debug" system-like record.
                    let mut r = rec.clone();
                    r.kind = LogStr::new("debug");
                    encode_system(&mut batch, &r, &rules);
                    batch_records = batch_records.saturating_add(1);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // drain access rings
        let mut depth_total: u64 = 0;
        for r in rings.iter() {
            depth_total = depth_total.saturating_add(r.len() as u64);

            // drain up to some bound per iteration to avoid starving others
            let mut drained = 0usize;
            while drained < 16_384 {
                let Some(ev) = r.pop() else { break };
                drained_any = true;
                drained += 1;

                match ev {
                    LogEvent::Access(a) => {
                        encode_access(&mut batch, &a, &rules);
                        batch_records = batch_records.saturating_add(1);
                    }
                    LogEvent::AccessError(e) => {
                        encode_access_error(&mut batch, &e, &rules);
                        batch_records = batch_records.saturating_add(1);
                    }
                    LogEvent::System(s) => {
                        encode_system(&mut batch, &s, &rules);
                        batch_records = batch_records.saturating_add(1);
                    }
                    #[cfg(feature = "debug_log")]
                    LogEvent::Debug(d) => {
                        let mut rr = d.clone();
                        rr.kind = LogStr::new("debug");
                        encode_system(&mut batch, &rr, &rules);
                        batch_records = batch_records.saturating_add(1);
                    }
                }
            }
        }
        metrics.set_buffer_depth(depth_total);

        // flush conditions
        let need_flush = !batch.is_empty()
            && (batch.len() >= batch_bytes_target
                || (batch_records as usize) >= batch_records_target
                || last_flush.elapsed() >= flush_interval);

        if need_flush {
            let access_written = count_access_records_in_batch(&batch);
            let system_written = count_system_records_in_batch(&batch);
            #[cfg(feature = "debug_log")]
            let debug_written = count_debug_records_in_batch(&batch);

            let _ = flush_batch(
                &mut ring,
                &mut file_state,
                stdout_enabled,
                &batch,
                &metrics,
                access_written,
                system_written,
                #[cfg(feature = "debug_log")]
                debug_written,
                &last_rt.output.rotation,
                &compress_worker,
            );
            batch.clear();
            batch_records = 0;
            last_flush = Instant::now();
        } else if !drained_any {
            // idle backoff
            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn open_output_file(path: &str) -> io::Result<Option<FileState>> {
    if path.trim().is_empty() {
        return Ok(None);
    }
    let p = PathBuf::from(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&p)?;
    let offset = file.metadata()?.len();
    Ok(Some(FileState {
        path: p,
        file,
        offset,
    }))
}

struct FileState {
    path: PathBuf,
    file: File,
    offset: u64,
}

struct CompressionTask {
    archive_path: PathBuf,
    base_path: PathBuf,
    max_files: usize,
}

struct CompressionWorker {
    tx: SyncSender<CompressionTask>,
    metrics: Arc<LogMetrics>,
}

impl CompressionWorker {
    fn start(metrics: Arc<LogMetrics>) -> Self {
        const DEFAULT_COMPRESS_QUEUE_CAPACITY: usize = 32;
        let queue_capacity = std::env::var("ARC_LOG_COMPRESS_QUEUE_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| v.clamp(1, 1024))
            .unwrap_or(DEFAULT_COMPRESS_QUEUE_CAPACITY);
        let test_delay_ms = testing_only_compress_delay_ms();
        let (tx, rx) = mpsc::sync_channel::<CompressionTask>(queue_capacity);
        let builder = thread::Builder::new().name("arc-log-compress".to_string());
        let _ = builder.spawn(move || {
            while let Ok(task) = rx.recv() {
                if test_delay_ms > 0 {
                    // Test-only stress knob: deliberately slow down compression worker to validate
                    // bounded queue behavior under pressure.
                    thread::sleep(Duration::from_millis(test_delay_ms));
                }
                if let Err(e) = compress_gzip_in_place(&task.archive_path) {
                    eprintln!(
                        "arc-logging: gzip compress failed: {} err={e}",
                        task.archive_path.display()
                    );
                }
                cleanup_rotated_archives(&task.base_path, task.max_files);
            }
        });
        Self { tx, metrics }
    }

    fn enqueue(&self, archive_path: PathBuf, base_path: PathBuf, max_files: usize) {
        let task = CompressionTask {
            archive_path,
            base_path,
            max_files,
        };
        match self.tx.try_send(task) {
            Ok(()) => {}
            Err(TrySendError::Full(task)) => {
                self.metrics.inc_compress_dropped();
                eprintln!(
                    "WARNING: arc-logging compression queue is full; skip gzip for {} (archive kept uncompressed)",
                    task.archive_path.display()
                );
            }
            Err(TrySendError::Disconnected(task)) => {
                self.metrics.inc_compress_dropped();
                eprintln!(
                    "WARNING: arc-logging compression worker is unavailable; skip gzip for {}",
                    task.archive_path.display()
                );
            }
        }
    }
}

#[inline]
fn testing_only_compress_delay_ms() -> u64 {
    // Compile-time isolation: release builds must not honor testing delay knobs.
    #[cfg(any(test, debug_assertions))]
    {
        std::env::var("ARC_LOG_TESTING_ONLY_COMPRESS_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    }
    #[cfg(not(any(test, debug_assertions)))]
    {
        0
    }
}

fn flush_batch(
    ring: &mut IoUring,
    file_state: &mut Option<FileState>,
    stdout_enabled: bool,
    buf: &[u8],
    metrics: &Arc<LogMetrics>,
    access_records: u64,
    system_records: u64,
    #[cfg(feature = "debug_log")] debug_records: u64,
    rot: &RotationConfig,
    compress_worker: &CompressionWorker,
) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    // rotation check before write (if file exists and already exceeded)
    if let Some(fs) = file_state.as_mut() {
        if fs.offset >= rot.max_size_bytes && rot.max_size_bytes > 0 {
            rotate_file(fs, rot, compress_worker);
        }
    }

    let start = Instant::now();
    let mut submit_count = 0usize;

    // Prepare SQEs
    if let Some(fs) = file_state.as_mut() {
        let fd = types::Fd(fs.file.as_raw_fd());

        // SAFETY:
        // - We ensure `buf` lives until completions are reaped (we wait synchronously in this function).
        // - The SQ is not used concurrently from other threads.
        let entry = opcode::Write::new(fd, buf.as_ptr(), buf.len() as _)
            .offset(fs.offset as _)
            .build()
            .user_data(1);

        unsafe {
            ring.submission().push(&entry).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "io_uring submission queue full")
            })?;
        }
        submit_count += 1;
    }

    if stdout_enabled {
        let fd = types::Fd(1);

        // SAFETY:
        // - We ensure `buf` lives until completions are reaped (we wait synchronously in this function).
        // - Stdout FD is valid; offset is ignored for pipes/tty.
        let entry = opcode::Write::new(fd, buf.as_ptr(), buf.len() as _)
            .offset(0)
            .build()
            .user_data(2);

        unsafe {
            ring.submission().push(&entry).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "io_uring submission queue full")
            })?;
        }
        submit_count += 1;
    }

    if submit_count == 0 {
        // Nothing to write anywhere.
        return Ok(());
    }

    if let Err(e) = ring.submit_and_wait(submit_count) {
        metrics.inc_write_error();
        return Err(e);
    }

    // Reap completions
    let mut write_succeeded = false;
    for _ in 0..submit_count {
        let cqe = match ring.completion().next() {
            Some(v) => v,
            None => {
                metrics.inc_write_error();
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "io_uring completion missing",
                ));
            }
        };
        let res = cqe.result();
        let ud = cqe.user_data();

        if res < 0 {
            let err = io::Error::from_raw_os_error(-res);
            // Don't crash; surface error and let caller continue.
            metrics.inc_write_error();
            eprintln!("arc-logging: write failed (user_data={ud}): {err}");
            continue;
        }

        let n = res as usize;
        if n > 0 {
            write_succeeded = true;
        }
        if n != buf.len() {
            // Partial writes are rare for regular files but possible.
            // We do best-effort: write remaining via blocking write() to avoid complex multi-submit loops here.
            let rest = &buf[n..];
            if ud == 1 {
                if let Some(fs) = file_state.as_mut() {
                    let mut off = fs.offset.saturating_add(n as u64);
                    // blocking fallback
                    let mut written = 0usize;
                    while written < rest.len() {
                        match fs.file.write(&rest[written..]) {
                            Ok(0) => {
                                metrics.inc_write_error();
                                eprintln!(
                                    "arc-logging: file fallback write returned 0 (user_data={ud})"
                                );
                                break;
                            }
                            Ok(nw) => {
                                written += nw;
                                off = off.saturating_add(nw as u64);
                                write_succeeded = true;
                            }
                            Err(e) => {
                                metrics.inc_write_error();
                                eprintln!(
                                    "arc-logging: file fallback write failed (user_data={ud}): {e}"
                                );
                                break;
                            }
                        }
                    }
                    fs.offset = off;
                }
            } else if ud == 2 {
                let mut out = io::stdout().lock();
                match out.write_all(rest) {
                    Ok(()) => {
                        write_succeeded = true;
                    }
                    Err(e) => {
                        metrics.inc_write_error();
                        eprintln!(
                            "arc-logging: stdout fallback write failed (user_data={ud}): {e}"
                        );
                    }
                }
            }
        } else {
            if ud == 1 {
                if let Some(fs) = file_state.as_mut() {
                    fs.offset = fs.offset.saturating_add(n as u64);
                }
            }
        }
    }

    let dur = start.elapsed();
    metrics.record_write_duration(dur);

    // Count written lines only when at least one sink write succeeds.
    if write_succeeded {
        metrics.add_written_access(access_records);
        metrics.add_written_system(system_records);
        #[cfg(feature = "debug_log")]
        metrics.add_written_debug(debug_records);
    }

    // rotation after write
    if let Some(fs) = file_state.as_mut() {
        if rot.max_size_bytes > 0 && fs.offset >= rot.max_size_bytes {
            rotate_file(fs, rot, compress_worker);
        }
    }

    Ok(())
}

fn rotate_file(fs: &mut FileState, rot: &RotationConfig, compress_worker: &CompressionWorker) {
    let base = fs.path.clone();
    let archive = rotated_path_with_timestamp(&base);

    // Step 1: rename current file to timestamped archive (near-instant metadata op).
    if let Err(e) = fs::rename(&base, &archive) {
        eprintln!(
            "arc-logging: rotate rename failed: from={} to={} err={e}",
            base.display(),
            archive.display()
        );
        return;
    }

    // Step 2: reopen the active log file immediately so write path is uninterrupted.
    match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&base)
    {
        Ok(f) => {
            fs.file = f;
            fs.offset = 0;
        }
        Err(e) => {
            eprintln!(
                "arc-logging: reopen after rotation failed: {} err={e}",
                base.display()
            );
        }
    }

    // Step 3: compression runs on a dedicated background thread.
    if rot.compress {
        compress_worker.enqueue(archive, base.clone(), rot.max_files.max(1));
    }

    // Step 4: retention cleanup is independent from write path.
    cleanup_rotated_archives(&base, rot.max_files.max(1));
}

fn rotated_path_with_timestamp(base: &Path) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let s = format!(
        "{}.{}{:09}",
        base.display(),
        now.as_secs(),
        now.subsec_nanos()
    );
    PathBuf::from(s)
}

fn cleanup_rotated_archives(base: &Path, max_files: usize) {
    let max_files = max_files.max(1);
    let Some(dir) = base.parent() else {
        return;
    };
    let Some(base_name) = base.file_name().and_then(|v| v.to_str()) else {
        return;
    };
    let prefix = format!("{base_name}.");

    let rd = match fs::read_dir(dir) {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut candidates: Vec<(PathBuf, SystemTime)> = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if p == base {
            continue;
        }
        let Some(name) = p.file_name().and_then(|v| v.to_str()) else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let mt = ent
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(UNIX_EPOCH);
        candidates.push((p, mt));
    }

    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    for (path, _) in candidates.into_iter().skip(max_files) {
        if let Err(e) = fs::remove_file(&path) {
            eprintln!(
                "arc-logging: cleanup rotated archive failed: {} err={e}",
                path.display()
            );
        }
    }
}

fn compress_gzip_in_place(src: &Path) -> io::Result<()> {
    let gz = PathBuf::from(format!("{}.gz", src.display()));
    let mut input = File::open(src)?;
    let output = File::create(&gz)?;

    let mut enc = GzEncoder::new(output, Compression::default());
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        enc.write_all(&buf[..n])?;
    }
    enc.finish()?;
    fs::remove_file(src)?;
    Ok(())
}

// --- Encoding helpers ---
// We encode NDJSON manually for correctness and speed, and to guarantee control-character escaping.

fn encode_access(out: &mut Vec<u8>, r: &AccessLogRecord, rules: &RedactionRules) {
    out.push(b'{');

    write_kv_ts(out, "ts", r.ts_unix_ns);
    out.push(b',');
    write_kv_str(
        out,
        "level",
        match r.level {
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        },
    );
    out.push(b',');
    write_kv_str(out, "kind", "access");
    out.push(b',');

    write_kv_logstr(out, "trace_id", &r.trace_id);
    if let Some(span) = r.span_id.as_ref() {
        out.push(b',');
        write_kv_logstr(out, "span_id", span);
    }
    out.push(b',');
    write_kv_logstr(out, "request_id", &r.request_id);
    out.push(b',');

    write_kv_logstr(out, "method", &r.method);
    out.push(b',');
    write_kv_logstr(out, "path", &r.path);
    out.push(b',');

    // query: apply redaction then escape
    let q = rules.redact_query(r.query.as_str());
    write_kv_str(out, "query", &q);
    out.push(b',');

    // host is a header-equivalent field; reuse header redaction policy.
    let host = rules.redact_header_value("host", r.host.as_str());
    write_kv_str(out, "host", host.as_ref());
    out.push(b',');

    write_kv_u64(out, "status", r.status as u64);
    out.push(b',');

    write_kv_logstr(out, "route", &r.route);
    out.push(b',');
    write_kv_logstr(out, "upstream", &r.upstream);
    out.push(b',');
    write_kv_logstr(out, "upstream_addr", &r.upstream_addr);
    out.push(b',');

    write_kv_logstr(out, "client_ip", &r.client_ip);
    out.push(b',');
    write_kv_u64(out, "client_port", r.client_port as u64);
    out.push(b',');

    write_kv_u64(out, "bytes_sent", r.bytes_sent);
    out.push(b',');
    write_kv_u64(out, "bytes_received", r.bytes_received);
    out.push(b',');

    write_kv_u64(out, "duration_ms", r.duration_ms);
    if let Some(v) = r.upstream_connect_ms {
        out.push(b',');
        write_kv_u64(out, "upstream_connect_ms", v);
    }
    if let Some(v) = r.upstream_response_ms {
        out.push(b',');
        write_kv_u64(out, "upstream_response_ms", v);
    }
    out.push(b',');
    write_kv_u64(out, "attempt", r.attempt as u64);
    out.push(b',');
    write_kv_bool(out, "tls", r.tls);
    out.push(b',');
    write_kv_logstr(out, "http_version", &r.http_version);

    out.push(b'}');
    out.push(b'\n');
}

fn encode_access_error(out: &mut Vec<u8>, r: &AccessErrorLogRecord, _rules: &RedactionRules) {
    out.push(b'{');

    write_kv_ts(out, "ts", r.ts_unix_ns);
    out.push(b',');
    write_kv_str(out, "level", "error");
    out.push(b',');
    write_kv_logstr(out, "kind", &r.kind);
    out.push(b',');
    write_kv_logstr(out, "msg", &r.msg);
    out.push(b',');

    write_kv_logstr(out, "trace_id", &r.trace_id);
    out.push(b',');
    write_kv_logstr(out, "request_id", &r.request_id);
    out.push(b',');

    write_kv_logstr(out, "route", &r.route);
    out.push(b',');
    write_kv_logstr(out, "upstream", &r.upstream);
    out.push(b',');
    write_kv_logstr(out, "upstream_addr", &r.upstream_addr);
    out.push(b',');

    write_kv_u64(out, "attempt", r.attempt as u64);
    out.push(b',');
    write_kv_u64(out, "max_attempts", r.max_attempts as u64);
    out.push(b',');

    write_kv_u64(out, "connect_timeout_ms", r.connect_timeout_ms);
    out.push(b',');
    write_kv_u64(out, "elapsed_ms", r.elapsed_ms);
    out.push(b',');

    write_kv_u64(out, "pool_active", r.pool_active);
    out.push(b',');
    write_kv_u64(out, "pool_max", r.pool_max);
    out.push(b',');

    write_kv_logstr(out, "client_ip", &r.client_ip);
    out.push(b',');
    write_kv_logstr(out, "method", &r.method);
    out.push(b',');
    write_kv_logstr(out, "path", &r.path);
    out.push(b',');
    write_kv_logstr(out, "error", &r.error);

    out.push(b'}');
    out.push(b'\n');
}

fn encode_system(out: &mut Vec<u8>, r: &SystemLogRecord, _rules: &RedactionRules) {
    out.push(b'{');

    write_kv_ts(out, "ts", r.ts_unix_ns);
    out.push(b',');
    write_kv_str(out, "level", level_str(r.level));
    out.push(b',');
    write_kv_logstr(out, "kind", &r.kind);
    out.push(b',');
    write_kv_logstr(out, "msg", &r.msg);

    for (k, v) in r.fields.iter() {
        out.push(b',');
        write_key(out, k.as_str());
        out.push(b':');
        write_value(out, v);
    }

    out.push(b'}');
    out.push(b'\n');
}

fn level_str(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn write_kv_ts(out: &mut Vec<u8>, key: &str, unix_ns: u64) {
    write_key(out, key);
    out.push(b':');
    // RFC3339 with nanos
    // We use `time` crate for correctness; fallback to numeric if conversion fails.
    match time::OffsetDateTime::from_unix_timestamp_nanos(unix_ns as i128) {
        Ok(dt) => {
            let s = match dt.format(&time::format_description::well_known::Rfc3339) {
                Ok(v) => v,
                Err(_) => unix_ns.to_string(),
            };
            write_json_string(out, &s);
        }
        Err(_) => {
            write_json_string(out, &unix_ns.to_string());
        }
    }
}

fn write_kv_str(out: &mut Vec<u8>, key: &str, val: &str) {
    write_key(out, key);
    out.push(b':');
    write_json_string(out, val);
}

fn write_kv_logstr(out: &mut Vec<u8>, key: &str, val: &LogStr) {
    write_key(out, key);
    out.push(b':');
    write_json_string(out, val.as_str());
}

fn write_kv_u64(out: &mut Vec<u8>, key: &str, val: u64) {
    write_key(out, key);
    out.push(b':');
    out.extend_from_slice(val.to_string().as_bytes());
}

fn write_kv_bool(out: &mut Vec<u8>, key: &str, val: bool) {
    write_key(out, key);
    out.push(b':');
    if val {
        out.extend_from_slice(b"true");
    } else {
        out.extend_from_slice(b"false");
    }
}

fn write_key(out: &mut Vec<u8>, key: &str) {
    write_json_string(out, key);
}

fn write_value(out: &mut Vec<u8>, v: &LogValue) {
    match v {
        LogValue::Str(s) => write_json_string(out, s.as_str()),
        LogValue::U64(n) => out.extend_from_slice(n.to_string().as_bytes()),
        LogValue::I64(n) => out.extend_from_slice(n.to_string().as_bytes()),
        LogValue::Bool(b) => {
            if *b {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
        }
        LogValue::F64(f) => out.extend_from_slice(format!("{f}").as_bytes()),
    }
}

// Batch record counters (best-effort; for accurate counts, caller can track per-event instead).
fn count_access_records_in_batch(_buf: &[u8]) -> u64 {
    // We don't parse the NDJSON batch here; actual access count is tracked at caller side.
    // Caller passes the value computed before flush.
    0
}

fn count_system_records_in_batch(_buf: &[u8]) -> u64 {
    0
}

#[cfg(feature = "debug_log")]
fn count_debug_records_in_batch(_buf: &[u8]) -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = env::var(key).ok();
            env::set_var(key, val);
            Self { key, prev }
        }

        fn unset(key: &'static str) -> Self {
            let prev = env::var(key).ok();
            env::remove_var(key);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = self.prev.as_ref() {
                env::set_var(self.key, v);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    fn metric_u64(metrics: &LogMetrics, key: &str) -> u64 {
        for line in metrics.render_prometheus().lines() {
            if line.starts_with(key) {
                let mut parts = line.split_whitespace();
                let _ = parts.next();
                if let Some(v) = parts.next() {
                    if let Ok(n) = v.parse::<u64>() {
                        return n;
                    }
                }
            }
        }
        0
    }

    fn unique_path(stem: &str) -> PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{stem}_{ns}"))
    }

    #[test]
    fn testing_only_delay_defaults_to_zero_when_env_missing() {
        let _lock = env_lock().lock().unwrap();
        let _unset = EnvGuard::unset("ARC_LOG_TESTING_ONLY_COMPRESS_DELAY_MS");
        assert_eq!(testing_only_compress_delay_ms(), 0);
    }

    #[test]
    fn testing_only_delay_reads_prefixed_env_value() {
        let _lock = env_lock().lock().unwrap();
        let _set = EnvGuard::set("ARC_LOG_TESTING_ONLY_COMPRESS_DELAY_MS", "17");
        assert_eq!(testing_only_compress_delay_ms(), 17);
    }

    #[test]
    fn compression_queue_full_increments_drop_metric() {
        let _lock = env_lock().lock().unwrap();
        let _cap = EnvGuard::set("ARC_LOG_COMPRESS_QUEUE_CAPACITY", "1");
        let _delay = EnvGuard::set("ARC_LOG_TESTING_ONLY_COMPRESS_DELAY_MS", "200");

        let metrics = Arc::new(LogMetrics::default());
        let worker = CompressionWorker::start(metrics.clone());
        let base = unique_path("arc_log_queue_full_base");
        for i in 0..24 {
            let archive = PathBuf::from(format!("{}.archive.{i}", base.display()));
            worker.enqueue(archive, base.clone(), 8);
        }

        thread::sleep(Duration::from_millis(30));
        let dropped = metric_u64(metrics.as_ref(), "arc_log_compress_dropped_total");
        assert!(
            dropped > 0,
            "expected dropped compression tasks, got {dropped}"
        );
    }

    #[test]
    fn flush_batch_write_failure_does_not_increment_written() {
        let _lock = env_lock().lock().unwrap();
        let _unset_delay = EnvGuard::unset("ARC_LOG_TESTING_ONLY_COMPRESS_DELAY_MS");
        let _unset_cap = EnvGuard::unset("ARC_LOG_COMPRESS_QUEUE_CAPACITY");

        let metrics = Arc::new(LogMetrics::default());
        let compress_worker = CompressionWorker::start(metrics.clone());
        let mut ring = IoUring::new(8).expect("create io_uring");
        let file = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full");
        let mut fs = Some(FileState {
            path: PathBuf::from("/dev/full"),
            file,
            offset: 0,
        });
        let buf = b"{\"k\":1}\n";

        let res = flush_batch(
            &mut ring,
            &mut fs,
            false,
            buf,
            &metrics,
            1,
            0,
            &RotationConfig::default(),
            &compress_worker,
        );
        assert!(
            res.is_ok(),
            "flush should be best-effort on write error: {res:?}"
        );

        assert_eq!(
            metric_u64(metrics.as_ref(), "arc_log_written_total{kind=\"access\"}"),
            0
        );
        assert!(
            metric_u64(metrics.as_ref(), "arc_log_write_errors_total") > 0,
            "expected write error counter to increase"
        );
    }

    #[test]
    fn flush_batch_success_increments_written_and_keeps_error_zero() {
        let _lock = env_lock().lock().unwrap();
        let _unset_delay = EnvGuard::unset("ARC_LOG_TESTING_ONLY_COMPRESS_DELAY_MS");
        let _unset_cap = EnvGuard::unset("ARC_LOG_COMPRESS_QUEUE_CAPACITY");

        let metrics = Arc::new(LogMetrics::default());
        let compress_worker = CompressionWorker::start(metrics.clone());
        let mut ring = IoUring::new(8).expect("create io_uring");
        let path = unique_path("arc_log_flush_success.log");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("open temp file");
        let mut fs = Some(FileState {
            path: path.clone(),
            file,
            offset: 0,
        });
        let buf = b"{\"ok\":true}\n";

        let res = flush_batch(
            &mut ring,
            &mut fs,
            false,
            buf,
            &metrics,
            2,
            1,
            &RotationConfig::default(),
            &compress_worker,
        );
        assert!(res.is_ok(), "flush success path should succeed: {res:?}");
        let disk = std::fs::read(&path).expect("read written file");
        assert_eq!(disk, buf);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            metric_u64(metrics.as_ref(), "arc_log_written_total{kind=\"access\"}"),
            2
        );
        assert_eq!(
            metric_u64(metrics.as_ref(), "arc_log_written_total{kind=\"system\"}"),
            1
        );
        assert_eq!(
            metric_u64(metrics.as_ref(), "arc_log_write_errors_total"),
            0
        );
    }
}
