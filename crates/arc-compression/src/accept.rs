use crate::util::{eq_ascii_case, trim_ascii_http_ws};
use crate::Algorithm;

/// Negotiation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedEncoding {
    /// Selected algorithm (Identity means "do not compress").
    pub algorithm: Algorithm,
    /// Selected q (0..=1000).
    pub q_millis: u16,
}

#[inline]
pub fn negotiate_encoding(accept: Option<&[u8]>, supported: &[Algorithm]) -> NegotiatedEncoding {
    let Some(raw) = accept else {
        return NegotiatedEncoding {
            algorithm: Algorithm::Identity,
            q_millis: 1000,
        };
    };
    let raw = trim_ascii_http_ws(raw);
    if raw.is_empty() {
        return NegotiatedEncoding {
            algorithm: Algorithm::Identity,
            q_millis: 1000,
        };
    }

    let mut q_zstd: Option<u16> = None;
    let mut q_br: Option<u16> = None;
    let mut q_gzip: Option<u16> = None;
    let mut q_identity: Option<u16> = None;
    let mut q_star: Option<u16> = None;

    for part in raw.split(|&b| b == b',') {
        let item = trim_ascii_http_ws(part);
        if item.is_empty() {
            continue;
        }

        let (enc_raw, params) = split_once(item, b';');
        let enc = trim_ascii_http_ws(enc_raw);
        if enc.is_empty() {
            continue;
        }

        let qv = params.and_then(|p| parse_q_from_params(p)).unwrap_or(1000);

        if eq_ascii_case(enc, b"*") {
            q_star = Some(max_u16(q_star.unwrap_or(0), qv));
            continue;
        }

        if eq_ascii_case(enc, b"zstd") {
            q_zstd = Some(max_u16(q_zstd.unwrap_or(0), qv));
            continue;
        }

        if eq_ascii_case(enc, b"br") {
            q_br = Some(max_u16(q_br.unwrap_or(0), qv));
            continue;
        }

        if eq_ascii_case(enc, b"gzip") || eq_ascii_case(enc, b"x-gzip") {
            q_gzip = Some(max_u16(q_gzip.unwrap_or(0), qv));
            continue;
        }

        if eq_ascii_case(enc, b"identity") {
            q_identity = Some(max_u16(q_identity.unwrap_or(0), qv));
            continue;
        }

        // ignore unknown encodings (but they can be covered by '*')
    }

    let identity_q = match (q_identity, q_star) {
        (Some(v), _) => v,
        (None, Some(v)) => v,
        (None, None) => 1000,
    };

    let mut best_alg = Algorithm::Identity;
    let mut best_q = identity_q;

    // For each supported algo, compute its q (explicit or wildcard).
    for &alg in supported {
        if alg == Algorithm::Identity {
            continue;
        }
        let q_alg = match alg {
            Algorithm::Zstd => q_zstd.or(q_star).unwrap_or(0),
            Algorithm::Br => q_br.or(q_star).unwrap_or(0),
            Algorithm::Gzip => q_gzip.or(q_star).unwrap_or(0),
            Algorithm::Identity => identity_q,
        };

        if q_alg == 0 {
            continue;
        }

        if q_alg > best_q {
            best_q = q_alg;
            best_alg = alg;
            continue;
        }
        if q_alg == best_q {
            // tie-break priority: zstd > br > gzip > identity
            if priority(alg) < priority(best_alg) {
                best_alg = alg;
                best_q = q_alg;
            }
        }
    }

    if best_alg != Algorithm::Identity && best_q == 0 {
        return NegotiatedEncoding {
            algorithm: Algorithm::Identity,
            q_millis: identity_q,
        };
    }

    NegotiatedEncoding {
        algorithm: best_alg,
        q_millis: best_q,
    }
}

#[inline]
fn priority(a: Algorithm) -> u8 {
    match a {
        Algorithm::Zstd => 0,
        Algorithm::Br => 1,
        Algorithm::Gzip => 2,
        Algorithm::Identity => 3,
    }
}

#[inline]
fn max_u16(a: u16, b: u16) -> u16 {
    if a >= b {
        a
    } else {
        b
    }
}

#[inline]
fn split_once(s: &[u8], delim: u8) -> (&[u8], Option<&[u8]>) {
    for (i, &b) in s.iter().enumerate() {
        if b == delim {
            return (&s[..i], Some(&s[i + 1..]));
        }
    }
    (s, None)
}

fn parse_q_from_params(params: &[u8]) -> Option<u16> {
    // params: "q=0.8; x=y"
    for p in params.split(|&b| b == b';') {
        let p = trim_ascii_http_ws(p);
        if p.len() < 2 {
            continue;
        }
        // accept both "q=..." and "Q=..."
        let k = p[0];
        if (k == b'q' || k == b'Q') && p[1] == b'=' {
            let v = trim_ascii_http_ws(&p[2..]);
            return parse_qvalue(v);
        }
    }
    None
}

fn parse_qvalue(v: &[u8]) -> Option<u16> {
    // RFC qvalue: 0..1 with up to 3 decimal digits.
    if v.is_empty() {
        return None;
    }

    if v[0] == b'1' {
        if v.len() == 1 {
            return Some(1000);
        }
        if v.len() >= 2 && v[1] == b'.' {
            for &b in &v[2..] {
                if b != b'0' {
                    return Some(1000);
                }
            }
            return Some(1000);
        }
        return None;
    }

    if v[0] != b'0' {
        return None;
    }

    if v.len() == 1 {
        return Some(0);
    }

    if v[1] != b'.' {
        return None;
    }

    let frac = &v[2..];
    if frac.is_empty() {
        return Some(0);
    }

    let mut acc: u16 = 0;
    let mut digits: u16 = 0;
    for &b in frac {
        if !b.is_ascii_digit() {
            return None;
        }
        if digits >= 3 {
            // ignore extra digits (treat as truncated)
            break;
        }
        acc = acc.saturating_mul(10).saturating_add((b - b'0') as u16);
        digits += 1;
    }

    let q = match digits {
        0 => 0,
        1 => acc * 100,
        2 => acc * 10,
        3 => acc,
        _ => acc,
    };
    Some(q.min(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_basic_priority() {
        let supported = [Algorithm::Zstd, Algorithm::Br, Algorithm::Gzip];
        let r = negotiate_encoding(Some(b"gzip, br, zstd"), &supported);
        assert_eq!(r.algorithm, Algorithm::Zstd);
    }

    #[test]
    fn negotiate_qvalues() {
        let supported = [Algorithm::Zstd, Algorithm::Br, Algorithm::Gzip];
        let r = negotiate_encoding(Some(b"gzip;q=1.0, br;q=0.8, zstd;q=0.9"), &supported);
        assert_eq!(r.algorithm, Algorithm::Gzip);
    }

    #[test]
    fn negotiate_star_applies() {
        let supported = [Algorithm::Zstd, Algorithm::Br, Algorithm::Gzip];
        let r = negotiate_encoding(Some(b"*;q=0.7, identity;q=0.1"), &supported);
        assert_eq!(r.algorithm, Algorithm::Zstd);
        assert_eq!(r.q_millis, 700);
    }

    #[test]
    fn negotiate_missing_header_is_identity() {
        let supported = [Algorithm::Zstd, Algorithm::Br, Algorithm::Gzip];
        let r = negotiate_encoding(None, &supported);
        assert_eq!(r.algorithm, Algorithm::Identity);
    }

    #[test]
    fn identity_can_be_disabled_by_star_zero() {
        let supported = [Algorithm::Zstd, Algorithm::Br, Algorithm::Gzip];
        let r = negotiate_encoding(Some(b"*;q=0"), &supported);
        // Arc 的数据面策略：即便都 q=0，也不发 406，直接按 identity 透传更安全。
        assert_eq!(r.algorithm, Algorithm::Identity);
    }
}
