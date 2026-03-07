use crate::util::{content_type_token, eq_ascii_case, starts_with_ascii_case};

/// MIME matcher used by the decision path.
///
/// Internals are allocation-free on hot path; extra lists are stored as lowercase bytes.
#[derive(Clone, Debug, Default)]
pub struct MimeMatcher {
    extra_include: Vec<Vec<u8>>,
    extra_exclude: Vec<Vec<u8>>,
}

impl MimeMatcher {
    /// Build a matcher with extra include/exclude lists (append-only semantics).
    pub fn new(extra_include: &[String], extra_exclude: &[String]) -> Self {
        let mut inc: Vec<Vec<u8>> = Vec::with_capacity(extra_include.len());
        let mut exc: Vec<Vec<u8>> = Vec::with_capacity(extra_exclude.len());

        for s in extra_include {
            let t = s.trim();
            if t.is_empty() {
                continue;
            }
            inc.push(ascii_lower_vec(t.as_bytes()));
        }
        for s in extra_exclude {
            let t = s.trim();
            if t.is_empty() {
                continue;
            }
            exc.push(ascii_lower_vec(t.as_bytes()));
        }

        Self {
            extra_include: inc,
            extra_exclude: exc,
        }
    }

    #[inline]
    pub fn should_compress(&self, content_type: Option<&[u8]>) -> bool {
        let Some(ct) = content_type else {
            return false;
        };
        let tok = content_type_token(ct);
        if tok.is_empty() {
            return false;
        }

        // Exclude first (default + extra)
        if is_default_excluded(tok) {
            return false;
        }
        for x in &self.extra_exclude {
            if mime_match(tok, x.as_slice()) {
                return false;
            }
        }

        // Default include
        if is_default_included(tok) {
            return true;
        }

        // Extra include
        for x in &self.extra_include {
            if mime_match(tok, x.as_slice()) {
                return true;
            }
        }

        false
    }
}

#[inline]
fn is_default_included(tok: &[u8]) -> bool {
    // text/*
    if starts_with_ascii_case(tok, b"text/") {
        return true;
    }

    // exact matches
    eq_ascii_case(tok, b"application/json")
        || eq_ascii_case(tok, b"application/xml")
        || eq_ascii_case(tok, b"application/javascript")
        || eq_ascii_case(tok, b"application/wasm")
        || eq_ascii_case(tok, b"image/svg+xml")
}

#[inline]
fn is_default_excluded(tok: &[u8]) -> bool {
    // image/*
    if eq_ascii_case(tok, b"image/jpeg")
        || eq_ascii_case(tok, b"image/png")
        || eq_ascii_case(tok, b"image/gif")
        || eq_ascii_case(tok, b"image/webp")
    {
        return true;
    }

    // audio/* video/*
    if starts_with_ascii_case(tok, b"audio/") || starts_with_ascii_case(tok, b"video/") {
        return true;
    }

    // archive/binary types
    eq_ascii_case(tok, b"application/zip")
        || eq_ascii_case(tok, b"application/gzip")
        || eq_ascii_case(tok, b"application/x-tar")
        || eq_ascii_case(tok, b"application/octet-stream")
}

#[inline]
fn mime_match(tok: &[u8], pat_lower: &[u8]) -> bool {
    // support:
    // - exact match: "application/json"
    // - prefix wildcard: "text/*", "audio/*"
    if pat_lower.ends_with(b"/*") && pat_lower.len() >= 3 {
        let pref = &pat_lower[..pat_lower.len() - 1]; // keep trailing '/'
        return starts_with_ascii_case(tok, pref);
    }
    eq_ascii_case(tok, pat_lower)
}

fn ascii_lower_vec(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len());
    for &b in s {
        v.push(if b.is_ascii_uppercase() { b + 32 } else { b });
    }
    v
}
