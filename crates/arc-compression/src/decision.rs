use crate::accept::negotiate_encoding;
use crate::magic::is_known_compressed_magic;
use crate::mime::MimeMatcher;
use crate::util::{content_encoding_token, eq_ascii_case};
use crate::{Algorithm, SizeBucket, SkipReason};

use std::sync::Arc;

use crate::adaptive::AdaptiveController;

/// Global compression config (fully resolved).
#[derive(Clone, Debug)]
pub struct GlobalCompressionConfig {
    /// Global enable switch.
    pub enabled: bool,

    /// Minimum size threshold in bytes. If Content-Length < min_size => skip.
    pub min_size: usize,

    /// Supported algorithms in priority order (used only for tie-break; q is primary).
    ///
    /// Typical: [zstd, br, gzip]
    pub algorithms: Vec<Algorithm>,

    /// zstd base level from config.
    ///
    /// Valid range: 1..=5
    pub zstd_level: i32,

    /// gzip base level from config.
    ///
    /// Valid range: 1..=9
    pub gzip_level: i32,

    /// brotli base level from config.
    ///
    /// Valid range: 4..=6
    pub br_level: i32,

    /// MIME matcher (default lists + extra include/exclude).
    pub mime: MimeMatcher,

    /// Adaptive controller (optional, enabled by default per spec).
    pub adaptive: Option<Arc<AdaptiveController>>,
}

impl Default for GlobalCompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size: 1024,
            algorithms: vec![Algorithm::Zstd, Algorithm::Br, Algorithm::Gzip],
            zstd_level: 3,
            gzip_level: 6,
            br_level: 5,
            mime: MimeMatcher::default(),
            adaptive: Some(Arc::new(AdaptiveController::new(
                crate::adaptive::AdaptiveConfig::default(),
            ))),
        }
    }
}

/// Per-route overrides (resolved at route compile time).
#[derive(Clone, Debug, Default)]
pub struct RouteCompressionOverrides {
    /// Override enable.
    pub enabled: Option<bool>,
    /// Override fixed algorithm (must still be accepted by client, else skip).
    pub algorithm: Option<Algorithm>,
    /// Override fixed level (within algorithm range).
    pub level: Option<i32>,
    /// Override min_size.
    pub min_size: Option<usize>,
    /// SSE 场景：每个 event 立即 flush。
    pub flush_per_event: bool,
}

/// Request info used for decision.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestInfo<'a> {
    /// Raw `Accept-Encoding` header value (without name).
    pub accept_encoding: Option<&'a [u8]>,
    /// Whether this request is HEAD (no response body).
    pub is_head: bool,
}

/// Response info used for decision.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseInfo<'a> {
    /// Status code.
    pub status: u16,
    /// Parsed Content-Length (if present).
    pub content_length: Option<u64>,
    /// Raw Content-Type header value.
    pub content_type: Option<&'a [u8]>,
    /// Raw Content-Encoding header value (if present).
    pub content_encoding: Option<&'a [u8]>,
}

/// Compression decision output.
#[derive(Clone, Debug)]
pub struct CompressionDecision {
    /// If Some => compress with this plan.
    pub plan: Option<CompressionPlan>,
    /// If plan is None => skip reason (for metrics).
    pub skipped: Option<SkipReason>,
}

impl CompressionDecision {
    fn skip(reason: SkipReason) -> Self {
        Self {
            plan: None,
            skipped: Some(reason),
        }
    }

    fn compress(plan: CompressionPlan) -> Self {
        Self {
            plan: Some(plan),
            skipped: None,
        }
    }
}

/// Concrete compression plan for a single response stream.
#[derive(Clone, Debug)]
pub struct CompressionPlan {
    /// Selected algorithm.
    pub algorithm: Algorithm,
    /// Selected level (already includes adaptive adjustment).
    pub level: i32,
    /// Size bucket used for metrics label.
    pub size_bucket: SizeBucket,
    /// SSE flush behavior.
    pub flush_per_event: bool,
}

#[inline]
pub fn decide_response_compression(
    global: &GlobalCompressionConfig,
    route: &RouteCompressionOverrides,
    req: RequestInfo<'_>,
    resp: ResponseInfo<'_>,
    body_prefix: Option<&[u8]>,
) -> CompressionDecision {
    // 1) global/route enabled
    if !global.enabled {
        return CompressionDecision::skip(SkipReason::Disabled);
    }
    if let Some(false) = route.enabled {
        return CompressionDecision::skip(SkipReason::Disabled);
    }

    // 2) status/method no-body
    if req.is_head {
        return CompressionDecision::skip(SkipReason::Disabled);
    }
    if resp.status < 200 || resp.status == 204 || resp.status == 304 {
        // 1xx/204/304: no response body
        return CompressionDecision::skip(SkipReason::Disabled);
    }

    // 3) MIME filter
    if !global.mime.should_compress(resp.content_type) {
        return CompressionDecision::skip(SkipReason::MimeExcluded);
    }

    // 4) already encoded check by Content-Encoding header (first token only)
    if let Some(ce_raw) = resp.content_encoding {
        let tok = content_encoding_token(ce_raw);
        if !tok.is_empty() && !eq_ascii_case(tok, b"identity") {
            return CompressionDecision::skip(SkipReason::AlreadyCompressed);
        }
    }

    // 5) magic bytes fallback (when no encoding or identity)
    if let Some(p) = body_prefix {
        let n = p.len().min(8);
        if n > 0 && is_known_compressed_magic(&p[..n]) {
            return CompressionDecision::skip(SkipReason::AlreadyCompressed);
        }
    }

    // 6) min_size (Content-Length only)
    let min_size = route.min_size.unwrap_or(global.min_size) as u64;
    if let Some(cl) = resp.content_length {
        if cl < min_size {
            return CompressionDecision::skip(SkipReason::TooSmall);
        }
        if cl == 0 {
            return CompressionDecision::skip(SkipReason::TooSmall);
        }
    }

    // 7) size bucket (Content-Length only)
    let size_bucket = match resp.content_length {
        None => SizeBucket::Unknown,
        Some(n) => {
            if n < 100 * 1024 {
                SizeBucket::Small
            } else if n <= 10 * 1024 * 1024 {
                SizeBucket::Medium
            } else {
                SizeBucket::Large
            }
        }
    };

    // 8) supported algorithms for this request (route-fixed or global list)
    let mut supported: [Algorithm; 3] = [
        Algorithm::Identity,
        Algorithm::Identity,
        Algorithm::Identity,
    ];
    let mut supported_len = 0usize;

    if let Some(a) = route.algorithm {
        supported[0] = a;
        supported_len = 1;
    } else {
        // copy global algorithms (zstd/br/gzip subset)
        for &a in &global.algorithms {
            if a == Algorithm::Identity {
                continue;
            }
            if supported_len < supported.len() {
                supported[supported_len] = a;
                supported_len += 1;
            }
        }
        if supported_len == 0 {
            return CompressionDecision::skip(SkipReason::Disabled);
        }
    }

    let supported_slice = &supported[..supported_len];

    // 9) negotiate by Accept-Encoding
    let negotiated = negotiate_encoding(req.accept_encoding, supported_slice);
    let alg = negotiated.algorithm;
    if alg == Algorithm::Identity {
        return CompressionDecision::skip(SkipReason::ClientNotSupported);
    }

    // If route fixed algorithm, negotiation might still yield identity due to q=0;
    // here alg is not identity, ok.

    // 10) base level by config
    let configured_level = match alg {
        Algorithm::Zstd => global.zstd_level,
        Algorithm::Gzip => global.gzip_level,
        Algorithm::Br => global.br_level,
        Algorithm::Identity => 0,
    };
    let base_level = clamp_level_by_alg(alg, configured_level);

    // 11) apply per-route level override (pre-adaptive) if present
    let lvl = route.level.unwrap_or(base_level);

    // 12) adaptive is allowed to move inside algorithm range, but not above configured cap.
    let cap_max = route
        .level
        .map(|v| clamp_level_by_alg(alg, v))
        .unwrap_or(base_level);
    let adaptive_level = if let Some(ad) = global.adaptive.as_ref() {
        ad.apply_level(alg, lvl)
    } else {
        clamp_level_by_alg(alg, lvl)
    };
    let level = clamp_level_to_cap(alg, adaptive_level, cap_max);

    CompressionDecision::compress(CompressionPlan {
        algorithm: alg,
        level,
        size_bucket,
        flush_per_event: route.flush_per_event,
    })
}

#[inline]
fn clamp_level_by_alg(alg: Algorithm, lvl: i32) -> i32 {
    match alg {
        Algorithm::Zstd => crate::clamp_i32(lvl, 1, 5),
        Algorithm::Gzip => crate::clamp_i32(lvl, 1, 9),
        Algorithm::Br => crate::clamp_i32(lvl, 4, 6),
        Algorithm::Identity => lvl,
    }
}

#[inline]
fn clamp_level_to_cap(alg: Algorithm, lvl: i32, cap_max: i32) -> i32 {
    match alg {
        Algorithm::Zstd => crate::clamp_i32(lvl, 1, crate::clamp_i32(cap_max, 1, 5)),
        Algorithm::Gzip => crate::clamp_i32(lvl, 1, crate::clamp_i32(cap_max, 1, 9)),
        Algorithm::Br => crate::clamp_i32(lvl, 4, crate::clamp_i32(cap_max, 4, 6)),
        Algorithm::Identity => lvl,
    }
}
