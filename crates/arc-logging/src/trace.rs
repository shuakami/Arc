use getrandom::getrandom;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed or generated trace context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    trace_flags: u8,
}

impl TraceContext {
    pub fn resolve_from_traceparent(traceparent: Option<&str>) -> Self {
        traceparent
            .and_then(Self::parse_traceparent)
            .unwrap_or_else(Self::generate)
    }

    pub fn parse_traceparent(v: &str) -> Option<Self> {
        let b = v.as_bytes();
        if b.len() != 55 || b[2] != b'-' || b[35] != b'-' || b[52] != b'-' {
            return None;
        }

        let version = parse_hex_byte(b[0], b[1])?;
        if version == 0xff {
            return None;
        }

        let trace_id = parse_hex_array::<16>(&v[3..35])?;
        if trace_id.iter().all(|x| *x == 0) {
            return None;
        }

        let span_id = parse_hex_array::<8>(&v[36..52])?;
        if span_id.iter().all(|x| *x == 0) {
            return None;
        }

        let trace_flags = parse_hex_byte(b[53], b[54])?;
        Some(Self {
            trace_id,
            span_id,
            trace_flags,
        })
    }

    /// Generate a new trace context.
    pub fn generate() -> Self {
        Self {
            trace_id: random_non_zero::<16>(),
            span_id: random_non_zero::<8>(),
            trace_flags: 0x01, // sampled
        }
    }

    /// Generate a child span for upstream forwarding while keeping the same trace_id.
    pub fn child_for_upstream(&self) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id: random_non_zero::<8>(),
            trace_flags: self.trace_flags,
        }
    }

    /// Render W3C `traceparent`.
    pub fn to_traceparent(&self) -> String {
        let mut out = String::with_capacity(55);
        out.push_str("00-");
        write_hex(&mut out, &self.trace_id);
        out.push('-');
        write_hex(&mut out, &self.span_id);
        out.push('-');
        write_hex_byte(&mut out, self.trace_flags);
        out
    }

    /// Trace id as lowercase hex.
    pub fn trace_id_hex(&self) -> String {
        let mut out = String::with_capacity(32);
        write_hex(&mut out, &self.trace_id);
        out
    }

    /// Span id as lowercase hex.
    pub fn span_id_hex(&self) -> String {
        let mut out = String::with_capacity(16);
        write_hex(&mut out, &self.span_id);
        out
    }
}

fn parse_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0usize;
    while i < N {
        out[i] = parse_hex_byte(b[i * 2], b[i * 2 + 1])?;
        i += 1;
    }
    Some(out)
}

fn parse_hex_byte(h: u8, l: u8) -> Option<u8> {
    let hi = hex_nibble(h)?;
    let lo = hex_nibble(l)?;
    Some((hi << 4) | lo)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn random_non_zero<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    if getrandom(&mut out).is_ok() && out.iter().any(|b| *b != 0) {
        return out;
    }

    // Fallback path: deterministic xorshift seeded by current time.
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    if seed == 0 {
        seed = 0x9e37_79b9_7f4a_7c15;
    }
    for slot in out.iter_mut() {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        seed = seed.wrapping_mul(0x2545F4914F6CDD1D);
        *slot = (seed & 0xff) as u8;
    }
    if out.iter().all(|b| *b == 0) {
        out[0] = 1;
    }
    out
}

fn write_hex(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        write_hex_byte(out, b);
    }
}

fn write_hex_byte(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 0x0f) as usize] as char);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_traceparent() {
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tc = TraceContext::parse_traceparent(raw).expect("parse");
        assert_eq!(tc.to_traceparent(), raw);
    }

    #[test]
    fn reject_all_zero_ids() {
        let bad_trace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        assert!(TraceContext::parse_traceparent(bad_trace).is_none());

        let bad_span = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        assert!(TraceContext::parse_traceparent(bad_span).is_none());
    }

    #[test]
    fn resolve_generates_when_missing() {
        let tc = TraceContext::resolve_from_traceparent(None);
        assert_eq!(tc.trace_id_hex().len(), 32);
        assert_eq!(tc.span_id_hex().len(), 16);
    }

    #[test]
    fn child_keeps_trace_changes_span() {
        let parent = TraceContext::generate();
        let child = parent.child_for_upstream();
        assert_eq!(parent.trace_id_hex(), child.trace_id_hex());
        assert_ne!(parent.span_id_hex(), child.span_id_hex());
    }
}
