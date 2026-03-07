use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn now_unix_ns() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d
            .as_secs()
            .saturating_mul(1_000_000_000)
            .saturating_add(d.subsec_nanos() as u64),
        Err(_) => 0,
    }
}

/// Current unix timestamp in milliseconds.
pub fn now_unix_ms() -> u64 {
    now_unix_ns() / 1_000_000
}

/// Lowercase ASCII for header/query keys comparison (case-insensitive matching).
///
/// Non-ASCII bytes are left as-is.
pub fn lowercase_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if (b'A'..=b'Z').contains(b) {
            out.push((b + 32) as char);
        } else {
            out.push(*b as char);
        }
    }
    out
}

/// Clamp `val` into `[min, max]`.
pub fn clamp_u64(val: u64, min: u64, max: u64) -> u64 {
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

pub fn parse_duration_millis(s: &str) -> Option<u64> {
    let ss = s.trim();
    if ss.is_empty() {
        return None;
    }
    if ss == "0" {
        return Some(0);
    }

    fn parse_num(prefix: &str) -> Option<u64> {
        prefix.trim().parse::<u64>().ok()
    }

    if let Some(v) = ss.strip_suffix("ms") {
        return parse_num(v);
    }
    if let Some(v) = ss.strip_suffix('s') {
        return parse_num(v).map(|n| n.saturating_mul(1_000));
    }
    if let Some(v) = ss.strip_suffix('m') {
        return parse_num(v).map(|n| n.saturating_mul(60_000));
    }
    if let Some(v) = ss.strip_suffix('h') {
        return parse_num(v).map(|n| n.saturating_mul(3_600_000));
    }

    // default: milliseconds
    ss.parse::<u64>().ok()
}

pub fn parse_size_bytes(s: &str) -> Option<u64> {
    let ss = s.trim();
    if ss.is_empty() {
        return None;
    }

    // numeric bytes
    if let Ok(v) = ss.parse::<u64>() {
        return Some(v);
    }

    let upper = ss.to_ascii_uppercase();
    fn parse_num(prefix: &str) -> Option<u64> {
        prefix.trim().parse::<u64>().ok()
    }

    if let Some(v) = upper.strip_suffix("KB") {
        return parse_num(v).map(|n| n.saturating_mul(1024));
    }
    if let Some(v) = upper.strip_suffix("MB") {
        return parse_num(v).map(|n| n.saturating_mul(1024 * 1024));
    }
    if let Some(v) = upper.strip_suffix("GB") {
        return parse_num(v).map(|n| n.saturating_mul(1024 * 1024 * 1024));
    }

    None
}

/// Convert milliseconds to `Duration`.
pub fn duration_from_millis(ms: u64) -> Duration {
    Duration::from_millis(ms)
}
