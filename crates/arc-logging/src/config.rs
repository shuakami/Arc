use crate::util::{clamp_u64, parse_duration_millis, parse_size_bytes};
use serde_json::Value;
use std::path::Path;

const DEFAULT_OUTPUT_FILE: &str = "/var/log/arc/access.log";
const DEFAULT_ROTATION_MAX_SIZE_BYTES: u64 = 500 * 1024 * 1024;
const DEFAULT_ROTATION_MIN_SIZE_BYTES: u64 = 1024 * 1024;
const DEFAULT_ROTATION_MAX_FILES: usize = 30;

/// Logging runtime configuration parsed from Arc canonical `raw_json`.
///
/// This is intentionally decoupled from Arc config schema: unknown fields are ignored.
#[derive(Debug, Clone)]
pub struct LoggingRuntimeConfig {
    /// Output targets and rotation.
    pub output: OutputConfig,
    /// Access log sampling behavior (tail-based at request end).
    pub access: AccessConfig,
    /// Sensitive data redaction rules.
    pub redact: RedactConfig,
    /// Writer thread + ring settings.
    pub writer: WriterConfig,
}

impl Default for LoggingRuntimeConfig {
    fn default() -> Self {
        Self {
            output: OutputConfig::default(),
            access: AccessConfig::default(),
            redact: RedactConfig::default(),
            writer: WriterConfig::default(),
        }
    }
}

impl LoggingRuntimeConfig {
    /// Parse from Arc canonical `raw_json`.
    ///
    /// On any parse error, returns defaults (never fails).
    pub fn parse_from_raw_json(raw_json: &str) -> Self {
        let mut out = Self::default();
        let mut output_explicit = false;

        let root: Value = match serde_json::from_str(raw_json) {
            Ok(v) => v,
            Err(_) => return out,
        };

        // logging.output = "stdout" | "file" | "both"
        if let Some(v) = get_path(&root, &["logging", "output"]) {
            if let Some(mode) = v.as_str() {
                output_explicit = apply_output_selector(&mut out.output, mode);
            }
        }

        // logging.output.file
        if let Some(v) = get_path(&root, &["logging", "output", "file"]) {
            if let Some(s) = v.as_str() {
                out.output.file = s.to_string();
                output_explicit = true;
            }
        }

        // logging.output.stdout
        if let Some(v) = get_path(&root, &["logging", "output", "stdout"]) {
            if let Some(b) = v.as_bool() {
                out.output.stdout = b;
                output_explicit = true;
            }
        }

        // logging.max_size_mb (alias)
        if let Some(v) = get_path(&root, &["logging", "max_size_mb"]) {
            if let Some(n) = v.as_u64() {
                let bytes = n.saturating_mul(1024 * 1024);
                apply_rotation_max_size(&mut out.output.rotation, bytes, "logging.max_size_mb");
            }
        }

        // logging.min_size_mb (alias)
        if let Some(v) = get_path(&root, &["logging", "min_size_mb"]) {
            if let Some(n) = v.as_u64() {
                let bytes = n.saturating_mul(1024 * 1024);
                apply_rotation_min_size(&mut out.output.rotation, bytes, "logging.min_size_mb");
            }
        }

        // logging.max_files (alias)
        if let Some(v) = get_path(&root, &["logging", "max_files"]) {
            if let Some(n) = v.as_u64() {
                out.output.rotation.max_files = (n as usize).clamp(1, 1024);
            }
        }

        // logging.output.rotation.*
        if let Some(v) = get_path(&root, &["logging", "output", "rotation", "min_size"]) {
            if let Some(bytes) = parse_size_to_bytes(v) {
                apply_rotation_min_size(
                    &mut out.output.rotation,
                    bytes,
                    "logging.output.rotation.min_size",
                );
            }
        }

        if let Some(v) = get_path(&root, &["logging", "output", "rotation", "max_size"]) {
            if let Some(bytes) = parse_size_to_bytes(v) {
                apply_rotation_max_size(
                    &mut out.output.rotation,
                    bytes,
                    "logging.output.rotation.max_size",
                );
            }
        }

        if let Some(v) = get_path(&root, &["logging", "output", "rotation", "max_files"]) {
            if let Some(n) = v.as_u64() {
                out.output.rotation.max_files = (n as usize).clamp(1, 1024);
            }
        }

        if let Some(v) = get_path(&root, &["logging", "output", "rotation", "compress"]) {
            if let Some(b) = v.as_bool() {
                out.output.rotation.compress = b;
            }
        }

        if !output_explicit {
            apply_auto_output_detection(&mut out.output);
        }

        // logging.access.sample
        if let Some(v) = get_path(&root, &["logging", "access", "sample"]) {
            if let Some(f) = v.as_f64() {
                out.access.sample = f.clamp(0.0, 1.0);
            } else if let Some(n) = v.as_u64() {
                // interpret integer 0/1 as bool-ish
                out.access.sample = if n == 0 { 0.0 } else { 1.0 };
            }
        }

        // logging.access.force_on_status
        if let Some(v) = get_path(&root, &["logging", "access", "force_on_status"]) {
            if let Some(arr) = v.as_array() {
                let mut statuses = Vec::with_capacity(arr.len());
                for it in arr.iter() {
                    match it {
                        Value::Number(n) => {
                            let Some(code) = n.as_u64() else { continue };
                            if (100..=599).contains(&code) {
                                statuses.push(code as u16);
                            }
                        }
                        Value::String(s) => {
                            let Ok(code) = s.parse::<u16>() else { continue };
                            if (100..=599).contains(&(code as u64)) {
                                statuses.push(code);
                            }
                        }
                        _ => {}
                    }
                }
                statuses.sort_unstable();
                statuses.dedup();
                out.access.force_on_status = statuses;
            }
        }

        // logging.access.force_on_slow
        if let Some(v) = get_path(&root, &["logging", "access", "force_on_slow"]) {
            match v {
                Value::String(s) => {
                    if let Some(ms) = parse_duration_millis(s) {
                        out.access.force_on_slow_ms = ms;
                    }
                }
                Value::Number(n) => {
                    if let Some(ms) = n.as_u64() {
                        out.access.force_on_slow_ms = ms;
                    }
                }
                _ => {}
            }
        }

        // logging.redact.headers
        if let Some(v) = get_path(&root, &["logging", "redact", "headers"]) {
            if let Some(arr) = v.as_array() {
                let mut headers = Vec::with_capacity(arr.len());
                for it in arr.iter() {
                    let Some(s) = it.as_str() else { continue };
                    headers.push(s.to_string());
                }
                out.redact.headers = headers;
            }
        }

        // logging.redact.query_params
        if let Some(v) = get_path(&root, &["logging", "redact", "query_params"]) {
            if let Some(arr) = v.as_array() {
                let mut params = Vec::with_capacity(arr.len());
                for it in arr.iter() {
                    let Some(s) = it.as_str() else { continue };
                    params.push(s.to_string());
                }
                out.redact.query_params = params;
            }
        }

        // logging.redact.body_fields
        if let Some(v) = get_path(&root, &["logging", "redact", "body_fields"]) {
            if let Some(arr) = v.as_array() {
                let mut fields = Vec::with_capacity(arr.len());
                for it in arr.iter() {
                    let Some(s) = it.as_str() else { continue };
                    fields.push(s.to_string());
                }
                out.redact.body_fields = fields;
            }
        }

        // logging.writer.ring_capacity
        if let Some(v) = get_path(&root, &["logging", "writer", "ring_capacity"]) {
            if let Some(n) = v.as_u64() {
                out.writer.ring_capacity = (n as usize).clamp(1024, 1_048_576);
            }
        }

        // logging.writer.batch_bytes
        if let Some(v) = get_path(&root, &["logging", "writer", "batch_bytes"]) {
            if let Some(n) = v.as_u64() {
                out.writer.batch_bytes = (n as usize).clamp(4 * 1024, 16 * 1024 * 1024);
            }
        }

        // logging.writer.batch_records
        if let Some(v) = get_path(&root, &["logging", "writer", "batch_records"]) {
            if let Some(n) = v.as_u64() {
                out.writer.batch_records = (n as usize).clamp(1, 1_000_000);
            }
        }

        // logging.writer.flush_interval
        if let Some(v) = get_path(&root, &["logging", "writer", "flush_interval"]) {
            match v {
                Value::String(s) => {
                    if let Some(ms) = parse_duration_millis(s) {
                        out.writer.flush_interval_ms = ms.clamp(1, 10_000);
                    }
                }
                Value::Number(n) => {
                    if let Some(ms) = n.as_u64() {
                        out.writer.flush_interval_ms = ms.clamp(1, 10_000);
                    }
                }
                _ => {}
            }
        }

        // logging.writer.uring_entries
        if let Some(v) = get_path(&root, &["logging", "writer", "uring_entries"]) {
            if let Some(n) = v.as_u64() {
                out.writer.uring_entries = (n as u32).clamp(8, 4096);
            }
        }

        out
    }
}

/// Output config (file + optional stdout) and rotation.
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Primary output file path. Empty means "disabled" (not recommended).
    pub file: String,
    /// Also write to stdout.
    pub stdout: bool,
    /// Rotation policy.
    pub rotation: RotationConfig,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            file: DEFAULT_OUTPUT_FILE.to_string(),
            stdout: false,
            rotation: RotationConfig::default(),
        }
    }
}

/// Rotation config.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotate when current file size exceeds this many bytes.
    ///
    /// Default: 500MB.
    pub max_size_bytes: u64,
    pub min_size_bytes: u64,
    /// Keep this many rotated history files (".1" .. ".N").
    ///
    /// Default: 30.
    pub max_files: usize,
    /// Compress rotated file using gzip.
    ///
    /// Default: true.
    pub compress: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: DEFAULT_ROTATION_MAX_SIZE_BYTES,
            min_size_bytes: DEFAULT_ROTATION_MIN_SIZE_BYTES,
            max_files: DEFAULT_ROTATION_MAX_FILES,
            compress: true,
        }
    }
}

/// Tail-based sampling for access logs.
#[derive(Debug, Clone)]
pub struct AccessConfig {
    /// Sampling rate for normal requests. 0.01 => 1%.
    pub sample: f64,
    /// Force write on these response status codes.
    ///
    /// This list is explicit by design: Arc does not infer status classes implicitly.
    pub force_on_status: Vec<u16>,
    /// Force write on slow requests (ms). 0 disables.
    pub force_on_slow_ms: u64,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            sample: 0.01,
            force_on_status: vec![401, 403, 429, 500, 502, 503, 504],
            force_on_slow_ms: 500,
        }
    }
}

/// Redaction config.
#[derive(Debug, Clone)]
pub struct RedactConfig {
    /// Header names to redact (Authorization/Cookie/...).
    pub headers: Vec<String>,
    /// Query param keys to redact.
    pub query_params: Vec<String>,
    /// Body fields to redact (only when caller already parsed JSON body).
    pub body_fields: Vec<String>,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            headers: vec![
                "Authorization".to_string(),
                "Cookie".to_string(),
                "X-API-Key".to_string(),
                "X-Auth-Token".to_string(),
            ],
            query_params: vec![
                "token".to_string(),
                "secret".to_string(),
                "api_key".to_string(),
                "password".to_string(),
            ],
            body_fields: vec![
                "$.password".to_string(),
                "$.credit_card".to_string(),
                "$.ssn".to_string(),
            ],
        }
    }
}

/// Writer/ring config.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Per-worker ring buffer capacity (SPSC). Must be >= 1024.
    ///
    /// Default: 8192.
    pub ring_capacity: usize,
    /// Flush batch bytes target. Writer will flush once buffer >= this threshold.
    ///
    /// Default: 256KB.
    pub batch_bytes: usize,
    /// Flush batch record target. Writer will flush once record count >= this threshold.
    ///
    /// Default: 4096.
    pub batch_records: usize,
    /// Flush interval in ms (time-based flush even if batch not full).
    ///
    /// Default: 50ms.
    pub flush_interval_ms: u64,
    /// io_uring SQ/CQ entries for the writer thread.
    ///
    /// Default: 256.
    pub uring_entries: u32,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            ring_capacity: 8192,
            batch_bytes: 256 * 1024,
            batch_records: 4096,
            flush_interval_ms: 50,
            uring_entries: 256,
        }
    }
}

fn get_path<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for &k in path {
        match cur {
            Value::Object(map) => {
                cur = map.get(k)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn parse_size_to_bytes(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => parse_size_bytes(s),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn apply_rotation_min_size(rot: &mut RotationConfig, min_size_bytes: u64, source: &str) {
    if min_size_bytes < DEFAULT_ROTATION_MIN_SIZE_BYTES {
        eprintln!(
            "WARNING: {source}={} bytes is below recommended min_size={} bytes",
            min_size_bytes, DEFAULT_ROTATION_MIN_SIZE_BYTES
        );
    }
    let min = clamp_u64(min_size_bytes, 64 * 1024, u64::MAX);
    if min != min_size_bytes {
        eprintln!(
            "WARNING: {source}={} bytes is below hard floor 65536 bytes; using {} bytes",
            min_size_bytes, min
        );
    }
    rot.min_size_bytes = min;
    if rot.max_size_bytes < min {
        eprintln!(
            "WARNING: {source}={} bytes is higher than current rotation max_size={} bytes; max_size is clamped to {} bytes",
            min,
            rot.max_size_bytes,
            min
        );
        rot.max_size_bytes = min;
    }
}

fn apply_rotation_max_size(rot: &mut RotationConfig, requested_bytes: u64, source: &str) {
    let requested = requested_bytes.max(1);
    let min = rot.min_size_bytes.max(1);
    if requested < min {
        eprintln!(
            "WARNING: {source}={} bytes is below rotation min_size={} bytes; using {} bytes",
            requested, min, min
        );
        rot.max_size_bytes = min;
        return;
    }
    rot.max_size_bytes = requested;
}

fn apply_output_selector(out: &mut OutputConfig, mode: &str) -> bool {
    match mode.trim().to_ascii_lowercase().as_str() {
        "stdout" => {
            out.stdout = true;
            out.file.clear();
            true
        }
        "file" => {
            out.stdout = false;
            if out.file.trim().is_empty() {
                out.file = DEFAULT_OUTPUT_FILE.to_string();
            }
            true
        }
        "both" => {
            out.stdout = true;
            if out.file.trim().is_empty() {
                out.file = DEFAULT_OUTPUT_FILE.to_string();
            }
            true
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EnvironmentSignals {
    has_journal_stream: bool,
    has_container_env: bool,
    has_dockerenv: bool,
}

impl EnvironmentSignals {
    fn detect() -> Self {
        Self {
            has_journal_stream: std::env::var_os("JOURNAL_STREAM").is_some(),
            has_container_env: std::env::var_os("container").is_some(),
            has_dockerenv: Path::new("/.dockerenv").exists(),
        }
    }
}

fn apply_auto_output_detection(out: &mut OutputConfig) {
    let signals = EnvironmentSignals::detect();
    apply_auto_output_detection_with_signals(out, signals);
}

fn apply_auto_output_detection_with_signals(out: &mut OutputConfig, signals: EnvironmentSignals) {
    if signals.has_journal_stream || signals.has_container_env || signals.has_dockerenv {
        out.stdout = true;
        out.file.clear();
        return;
    }
    // Binary default outside systemd/container: write both file and stdout.
    out.stdout = true;
    if out.file.trim().is_empty() {
        out.file = DEFAULT_OUTPUT_FILE.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_force_on_status_dedup_and_sort() {
        let raw = r#"
        {
          "logging": {
            "access": {
              "force_on_status": [503, "401", 429, 503, 700, "bad"]
            }
          }
        }
        "#;
        let cfg = LoggingRuntimeConfig::parse_from_raw_json(raw);
        assert_eq!(cfg.access.force_on_status, vec![401, 429, 503]);
    }

    #[test]
    fn keep_default_when_force_on_status_missing() {
        let raw = r#"{"logging":{"access":{"sample":0.1}}}"#;
        let cfg = LoggingRuntimeConfig::parse_from_raw_json(raw);
        assert_eq!(
            cfg.access.force_on_status,
            vec![401, 403, 429, 500, 502, 503, 504]
        );
    }

    #[test]
    fn default_rotation_is_500mb_and_30_files() {
        let cfg = LoggingRuntimeConfig::default();
        assert_eq!(cfg.output.rotation.max_size_bytes, 500 * 1024 * 1024);
        assert_eq!(cfg.output.rotation.min_size_bytes, 1024 * 1024);
        assert_eq!(cfg.output.rotation.max_files, 30);
    }

    #[test]
    fn output_shorthand_stdout_is_explicit_and_disables_file() {
        let raw = r#"{"logging":{"output":"stdout"}}"#;
        let cfg = LoggingRuntimeConfig::parse_from_raw_json(raw);
        assert!(cfg.output.stdout);
        assert!(cfg.output.file.is_empty());
    }

    #[test]
    fn logging_alias_max_size_mb_and_max_files_are_parsed() {
        let raw = r#"{"logging":{"max_size_mb":123,"max_files":77}}"#;
        let cfg = LoggingRuntimeConfig::parse_from_raw_json(raw);
        assert_eq!(cfg.output.rotation.max_size_bytes, 123 * 1024 * 1024);
        assert_eq!(cfg.output.rotation.max_files, 77);
    }

    #[test]
    fn max_size_below_min_is_clamped_to_min() {
        let raw = r#"{
            "logging": {
                "output": {
                    "rotation": {
                        "min_size": "2mb",
                        "max_size": "512kb"
                    }
                }
            }
        }"#;
        let cfg = LoggingRuntimeConfig::parse_from_raw_json(raw);
        assert_eq!(cfg.output.rotation.min_size_bytes, 2 * 1024 * 1024);
        assert_eq!(cfg.output.rotation.max_size_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn auto_detect_uses_stdout_when_journal_stream_exists() {
        let mut out = OutputConfig::default();
        apply_auto_output_detection_with_signals(
            &mut out,
            EnvironmentSignals {
                has_journal_stream: true,
                has_container_env: false,
                has_dockerenv: false,
            },
        );
        assert!(out.stdout);
        assert!(out.file.is_empty());
    }

    #[test]
    fn auto_detect_uses_both_when_no_signal() {
        let mut out = OutputConfig {
            file: String::new(),
            stdout: false,
            rotation: RotationConfig::default(),
        };
        apply_auto_output_detection_with_signals(
            &mut out,
            EnvironmentSignals {
                has_journal_stream: false,
                has_container_env: false,
                has_dockerenv: false,
            },
        );
        assert!(out.stdout);
        assert_eq!(out.file, DEFAULT_OUTPUT_FILE);
    }
}
