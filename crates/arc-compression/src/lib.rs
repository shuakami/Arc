#![allow(missing_docs)]

use arc_common::ArcError;

mod accept;
mod adaptive;
mod chunked;
mod codec;
mod decision;
mod magic;
mod mime;
mod pool;
mod sse;
mod util;

pub use accept::{negotiate_encoding, NegotiatedEncoding};
pub use adaptive::{
    AdaptiveAdjustment, AdaptiveConfig, AdaptiveController, AdaptiveDirection, AdaptiveState,
};
pub use chunked::{encode_chunked, encode_chunked_end, ChunkedDecodeResult, ChunkedDecoder};
pub use decision::{
    decide_response_compression, CompressionDecision, CompressionPlan, GlobalCompressionConfig,
    RequestInfo, ResponseInfo, RouteCompressionOverrides,
};
pub use magic::is_known_compressed_magic;
pub use mime::MimeMatcher;
pub use pool::{CompressorPools, PooledCompressor};
pub use sse::SseEventSplitter;
pub use util::trim_ascii_http_ws;

/// Arc 支持在下游响应上输出的压缩算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// zstd（Content-Encoding: zstd）
    Zstd,
    /// brotli（Content-Encoding: br）
    Br,
    /// gzip（Content-Encoding: gzip）
    Gzip,
    /// 不压缩（Content-Encoding: identity / 或不写该头）
    Identity,
}

impl Algorithm {
    /// HTTP `Content-Encoding` token。
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Algorithm::Zstd => "zstd",
            Algorithm::Br => "br",
            Algorithm::Gzip => "gzip",
            Algorithm::Identity => "identity",
        }
    }

    #[inline]
    pub const fn is_identity(self) -> bool {
        matches!(self, Algorithm::Identity)
    }
}

/// 跳过压缩的原因（与 spec 的 reason 枚举一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Content-Length < min_size。
    TooSmall,
    /// 上游已经压缩（Content-Encoding 非 identity）或 magic bytes 命中已压缩格式。
    AlreadyCompressed,
    /// MIME 类型不在压缩白名单（或在黑名单）。
    MimeExcluded,
    /// 客户端不支持（Accept-Encoding 无交集）。
    ClientNotSupported,
    /// 全局/路由关闭。
    Disabled,
}

impl SkipReason {
    /// Prometheus label 值。
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            SkipReason::TooSmall => "too_small",
            SkipReason::AlreadyCompressed => "already_compressed",
            SkipReason::MimeExcluded => "mime_excluded",
            SkipReason::ClientNotSupported => "client_not_supported",
            SkipReason::Disabled => "disabled",
        }
    }
}

/// 响应体大小桶（用于默认 level 选择与 metrics 标签）。
///
/// `Unknown` 对应无 Content-Length（chunked / until-eof）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeBucket {
    /// 1KB - 100KB
    Small,
    /// 100KB - 10MB
    Medium,
    /// > 10MB
    Large,
    /// 无 Content-Length
    Unknown,
}

impl SizeBucket {
    /// Prometheus label 值。
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            SizeBucket::Small => "1k_100k",
            SizeBucket::Medium => "100k_10m",
            SizeBucket::Large => "10m_plus",
            SizeBucket::Unknown => "unknown",
        }
    }
}

/// 压缩器 flush 模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMode {
    /// 不强制 flush（仍可能产生输出）。
    None,
    /// 强制 flush（SSE 逐 event；或每 upstream chunk）。
    Flush,
    /// 结束压缩流。
    Finish,
}

/// i32 clamp helper（小函数，供 codec/decision 使用）。
#[inline]
pub const fn clamp_i32(v: i32, min_v: i32, max_v: i32) -> i32 {
    if v < min_v {
        min_v
    } else if v > max_v {
        max_v
    } else {
        v
    }
}

#[inline]
pub(crate) fn zstd_err(ctx: &'static str, e: zstd_safe::ErrorCode) -> ArcError {
    ArcError::io(
        ctx,
        std::io::Error::new(std::io::ErrorKind::Other, format!("zstd: {e:?}")),
    )
}

#[inline]
pub(crate) fn compress_err(ctx: &'static str, msg: impl std::fmt::Display) -> ArcError {
    ArcError::io(
        ctx,
        std::io::Error::new(std::io::ErrorKind::Other, msg.to_string()),
    )
}
