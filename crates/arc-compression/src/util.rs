//! Small, allocation-free helpers used by the compression decision/codec paths.

/// Trim ASCII HTTP whitespace (SP / HTAB).
#[inline]
pub fn trim_ascii_http_ws(mut s: &[u8]) -> &[u8] {
    while let Some(&b) = s.first() {
        if b == b' ' || b == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&b) = s.last() {
        if b == b' ' || b == b'\t' {
            s = &s[..s.len().saturating_sub(1)];
        } else {
            break;
        }
    }
    s
}

/// ASCII case-insensitive equality check where `b_lower` must already be lowercase ASCII.
#[inline]
pub fn eq_ascii_case(a: &[u8], b_lower: &[u8]) -> bool {
    if a.len() != b_lower.len() {
        return false;
    }
    for (x, y) in a.iter().copied().zip(b_lower.iter().copied()) {
        let xl = if x.is_ascii_uppercase() { x + 32 } else { x };
        if xl != y {
            return false;
        }
    }
    true
}

/// ASCII case-insensitive prefix check where `prefix_lower` must already be lowercase ASCII.
#[inline]
pub fn starts_with_ascii_case(s: &[u8], prefix_lower: &[u8]) -> bool {
    if s.len() < prefix_lower.len() {
        return false;
    }
    eq_ascii_case(&s[..prefix_lower.len()], prefix_lower)
}

/// Extract `Content-Type` token (bytes before `;`), trimmed.
#[inline]
pub fn content_type_token(v: &[u8]) -> &[u8] {
    let v = trim_ascii_http_ws(v);
    if v.is_empty() {
        return v;
    }
    let mut end = v.len();
    for (i, &b) in v.iter().enumerate() {
        if b == b';' {
            end = i;
            break;
        }
    }
    trim_ascii_http_ws(&v[..end])
}

#[inline]
pub fn content_encoding_token(v: &[u8]) -> &[u8] {
    let v = trim_ascii_http_ws(v);
    if v.is_empty() {
        return v;
    }
    let mut end = v.len();
    for (i, &b) in v.iter().enumerate() {
        if b == b',' || b == b';' {
            end = i;
            break;
        }
    }
    trim_ascii_http_ws(&v[..end])
}
