use crate::util::now_unix_ns;
use serde::Serialize;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Log level (string values match NDJSON output).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// debug (feature-gated for debug logs; access/system can also use it via override)
    Debug,
    /// info
    Info,
    /// warn
    Warn,
    /// error
    Error,
}

#[derive(Clone)]
pub enum LogStr {
    Inline { len: u8, buf: [u8; 32] },
    Arc(Arc<str>),
}

impl LogStr {
    /// Create from &str (UTF-8).
    pub fn new(s: &str) -> Self {
        if s.len() <= 32 {
            let mut buf = [0u8; 32];
            buf[..s.len()].copy_from_slice(s.as_bytes());
            LogStr::Inline {
                len: s.len() as u8,
                buf,
            }
        } else {
            LogStr::Arc(Arc::<str>::from(s))
        }
    }

    /// Borrow as &str.
    pub fn as_str(&self) -> &str {
        match self {
            LogStr::Inline { len, buf } => {
                let n = *len as usize;
                let slice = &buf[..n];
                // SAFETY:
                // - We only construct Inline from valid UTF-8 &str and copy bytes directly.
                unsafe { std::str::from_utf8_unchecked(slice) }
            }
            LogStr::Arc(a) => a.as_ref(),
        }
    }
}

impl fmt::Debug for LogStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LogStr").field(&self.as_str()).finish()
    }
}

impl PartialEq for LogStr {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for LogStr {}

impl Hash for LogStr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl From<&str> for LogStr {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}
impl From<String> for LogStr {
    fn from(value: String) -> Self {
        Self::new(value.as_str())
    }
}
impl From<Arc<str>> for LogStr {
    fn from(value: Arc<str>) -> Self {
        Self::Arc(value)
    }
}

/// Generic log value for system/debug extra fields.
#[derive(Debug, Clone)]
pub enum LogValue {
    /// String
    Str(LogStr),
    /// Unsigned integer
    U64(u64),
    /// Signed integer
    I64(i64),
    /// Boolean
    Bool(bool),
    /// Float (use sparingly)
    F64(f64),
}

impl From<&str> for LogValue {
    fn from(v: &str) -> Self {
        LogValue::Str(LogStr::new(v))
    }
}
impl From<String> for LogValue {
    fn from(v: String) -> Self {
        LogValue::Str(LogStr::new(&v))
    }
}
impl From<u64> for LogValue {
    fn from(v: u64) -> Self {
        LogValue::U64(v)
    }
}
impl From<i64> for LogValue {
    fn from(v: i64) -> Self {
        LogValue::I64(v)
    }
}
impl From<bool> for LogValue {
    fn from(v: bool) -> Self {
        LogValue::Bool(v)
    }
}
impl From<f64> for LogValue {
    fn from(v: f64) -> Self {
        LogValue::F64(v)
    }
}

#[derive(Debug, Clone)]
pub struct RequestContextView {
    pub trace_id: LogStr,
    pub span_id: Option<LogStr>,
    pub request_id: LogStr,
    pub route: Option<LogStr>,
    pub upstream: Option<LogStr>,
    pub client_ip: Option<LogStr>,
}

impl RequestContextView {
    /// Create a minimal view (route/upstream/client_ip optional).
    pub fn new(trace_id: &str, request_id: &str) -> Self {
        Self {
            trace_id: LogStr::new(trace_id),
            span_id: None,
            request_id: LogStr::new(request_id),
            route: None,
            upstream: None,
            client_ip: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessLogContext {
    pub trace_id: LogStr,
    pub span_id: Option<LogStr>,
    pub request_id: LogStr,

    pub method: LogStr,
    pub path: LogStr,
    pub query: LogStr,
    pub host: LogStr,

    pub route: LogStr,
    pub upstream: LogStr,
    pub upstream_addr: LogStr,

    pub client_ip: LogStr,
    pub client_port: u16,

    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub upstream_connect_ms: Option<u64>,
    pub upstream_response_ms: Option<u64>,

    pub attempt: u32,
    pub tls: bool,
    pub http_version: LogStr,
}

impl AccessLogContext {
    /// Create with minimal required fields.
    pub fn new(
        trace_id: &str,
        request_id: &str,
        method: &str,
        path: &str,
        query: &str,
        host: &str,
        route: &str,
        upstream: &str,
        upstream_addr: &str,
        client_ip: &str,
        client_port: u16,
        tls: bool,
        http_version: &str,
    ) -> Self {
        Self {
            trace_id: LogStr::new(trace_id),
            span_id: None,
            request_id: LogStr::new(request_id),
            method: LogStr::new(method),
            path: LogStr::new(path),
            query: LogStr::new(query),
            host: LogStr::new(host),
            route: LogStr::new(route),
            upstream: LogStr::new(upstream),
            upstream_addr: LogStr::new(upstream_addr),
            client_ip: LogStr::new(client_ip),
            client_port,
            bytes_sent: 0,
            bytes_received: 0,
            upstream_connect_ms: None,
            upstream_response_ms: None,
            attempt: 1,
            tls,
            http_version: LogStr::new(http_version),
        }
    }
}

/// Normal access log record (per-request, high frequency).
#[derive(Debug, Clone)]
pub struct AccessLogRecord {
    pub ts_unix_ns: u64,
    pub level: LogLevel,
    pub trace_id: LogStr,
    pub span_id: Option<LogStr>,
    pub request_id: LogStr,

    pub method: LogStr,
    pub path: LogStr,
    pub query: LogStr,
    pub host: LogStr,

    pub status: u16,

    pub route: LogStr,
    pub upstream: LogStr,
    pub upstream_addr: LogStr,

    pub client_ip: LogStr,
    pub client_port: u16,

    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub upstream_connect_ms: Option<u64>,
    pub upstream_response_ms: Option<u64>,

    pub duration_ms: u64,
    pub attempt: u32,
    pub tls: bool,
    pub http_version: LogStr,
}

impl AccessLogRecord {
    /// Build from context at request completion.
    pub fn from_ctx_success(ctx: AccessLogContext, status: u16, duration_ms: u64) -> Self {
        Self {
            ts_unix_ns: now_unix_ns(),
            level: LogLevel::Info,
            trace_id: ctx.trace_id,
            span_id: ctx.span_id,
            request_id: ctx.request_id,
            method: ctx.method,
            path: ctx.path,
            query: ctx.query,
            host: ctx.host,
            status,
            route: ctx.route,
            upstream: ctx.upstream,
            upstream_addr: ctx.upstream_addr,
            client_ip: ctx.client_ip,
            client_port: ctx.client_port,
            bytes_sent: ctx.bytes_sent,
            bytes_received: ctx.bytes_received,
            upstream_connect_ms: ctx.upstream_connect_ms,
            upstream_response_ms: ctx.upstream_response_ms,
            duration_ms,
            attempt: ctx.attempt,
            tls: ctx.tls,
            http_version: ctx.http_version,
        }
    }
}

/// Access error log record (per-request error context).
#[derive(Debug, Clone)]
pub struct AccessErrorLogRecord {
    pub ts_unix_ns: u64,
    pub level: LogLevel,
    pub kind: LogStr,
    pub msg: LogStr,

    pub trace_id: LogStr,
    pub request_id: LogStr,

    pub route: LogStr,
    pub upstream: LogStr,
    pub upstream_addr: LogStr,

    pub attempt: u32,
    pub max_attempts: u32,

    pub connect_timeout_ms: u64,
    pub elapsed_ms: u64,

    pub pool_active: u64,
    pub pool_max: u64,

    pub client_ip: LogStr,
    pub method: LogStr,
    pub path: LogStr,

    pub error: LogStr,
}

impl AccessErrorLogRecord {
    /// Build an error record from base context.
    pub fn from_ctx_error(
        ctx: AccessLogContext,
        msg: &str,
        error: &str,
        attempt: u32,
        max_attempts: u32,
        connect_timeout_ms: u64,
        elapsed_ms: u64,
        pool_active: u64,
        pool_max: u64,
    ) -> Self {
        Self {
            ts_unix_ns: now_unix_ns(),
            level: LogLevel::Error,
            kind: LogStr::new("access"),
            msg: LogStr::new(msg),
            trace_id: ctx.trace_id,
            request_id: ctx.request_id,
            route: ctx.route,
            upstream: ctx.upstream,
            upstream_addr: ctx.upstream_addr,
            attempt,
            max_attempts,
            connect_timeout_ms,
            elapsed_ms,
            pool_active,
            pool_max,
            client_ip: ctx.client_ip,
            method: ctx.method,
            path: ctx.path,
            error: LogStr::new(error),
        }
    }
}

/// System log record (low frequency, always 100% recorded).
#[derive(Debug, Clone)]
pub struct SystemLogRecord {
    pub ts_unix_ns: u64,
    pub level: LogLevel,
    pub kind: LogStr,
    pub msg: LogStr,
    pub fields: Vec<(LogStr, LogValue)>,
}

impl SystemLogRecord {
    /// Create a system log without extra fields.
    pub fn new(level: LogLevel, msg: &str) -> Self {
        Self {
            ts_unix_ns: now_unix_ns(),
            level,
            kind: LogStr::new("system"),
            msg: LogStr::new(msg),
            fields: Vec::new(),
        }
    }
}

/// Unified log event type (used by writer thread).
#[derive(Debug, Clone)]
pub enum LogEvent {
    /// Access log
    Access(AccessLogRecord),
    /// Access error log
    AccessError(AccessErrorLogRecord),
    /// System log
    System(SystemLogRecord),
    /// Debug log (feature-gated)
    #[cfg(feature = "debug_log")]
    Debug(SystemLogRecord),
}
