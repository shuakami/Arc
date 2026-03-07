use arc_common::{ArcError, Result};
use arc_compression::{
    decide_response_compression, encode_chunked, encode_chunked_end, AdaptiveConfig,
    AdaptiveController, Algorithm, CompressorPools, FlushMode, GlobalCompressionConfig,
    MimeMatcher, PooledCompressor, RequestInfo as CompressionRequestInfo,
    ResponseInfo as CompressionResponseInfo, RouteCompressionOverrides,
};
use arc_config::forward_policies::{
    CompiledHeaderMutation, CompiledLoadBalance, CompiledRewrite, CompiledSplitKey, RouteUpstreams,
};
use arc_config::policy_compression::CompressionAlgorithm as CfgCompressionAlgorithm;
use arc_config::policy_timeout::parse_deadline_budget;
use arc_config::{
    restart_required_changes, CompiledErrorPageAction, CompiledErrorPageRule,
    CompiledRequestIdConfig, ControlRole, ErrorPageWhen, RateLimitPolicy, RequestIdConflictConfig,
    RequestIdFormatConfig, RouteAction, RouteMatcher, SharedConfig, TrustedProxyCidr,
};
use arc_global_rate_limit::{Policy as GlobalRatePolicy, WorkerLimiter as GlobalWorkerLimiter};
use arc_logging::{AccessLogContext, LogLevel, LogStr, LogValue, TraceContext};
use arc_net::cpu;
use arc_net::memory::buffers::INVALID_BUF;
use arc_net::net;
use arc_net::op::{self, OpKind, Side};
use arc_net::time::monotonic_nanos;
use arc_net::uring::{sqe, sys};
use arc_net::{FixedBuffers, Key, Slab, Uring};
use arc_observability::WorkerMetrics;
use arc_proto_h2::error::H2Code;
use arc_proto_h2::hpack::Header as H2Header;
use arc_xdp_common::{BlockReason, IpKey};
use arc_xdp_userspace::config::parse_security_config_best_effort;
use arc_xdp_userspace::l7::{SlowlorisConnState, SlowlorisDecision};
use arc_xdp_userspace::manager::global_xdp_manager;
use arc_xdp_userspace::SlowlorisGuard;

use arc_proto_http1::{
    find_header_end, parse_request_head, parse_response_head, BodyKind, ChunkedState, ConsumeResult,
};
use bytes::Bytes;
use rustls::{ClientConnection, ServerConnection};

use crate::cluster_circuit::ClusterCircuit;
use crate::downstream_tls::DownstreamTls;
use crate::h2::buf::{BufChain as H2BufChain, BufOps as H2BufOpsTrait, RxChunk as H2RxChunk};
use crate::h2::down::{
    DownstreamH2, DownstreamSink as H2DownstreamSink, RequestHead as H2RequestHead,
};
use crate::h2::driver::drain_tx_to_writer as h2_drain_tx_to_writer;
use crate::h2::key::ConnKey as H2ConnKey;
use crate::h2::tx::Credit as H2Credit;
use crate::mirror_dispatcher::{
    compile_ignore_body_fields, MirrorCompareRuntime, MirrorDispatcher, MirrorPolicyRuntime,
    MirrorSubmitContext, MirrorTargetMetrics, MirrorTargetRuntime, MirrorTransformRuntime,
};
use crate::timeout_tier::{dur_to_ns_saturating, RequestTimeoutState};
use crate::tls::{build_upstream_client_config, UpstreamTlsRuntime};
use arc_swap::ArcSwap;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use uuid::Uuid;

// tail stash for pipelining (fixed, no heap). This is a pragmatic compromise.
const STASH_CAP: usize = 4096;
const REQ_ACCEPT_ENCODING_CAP: usize = 256;
const UP_MTLS_PLAIN_DRAIN_BUDGET: usize = 64 * 1024;
const UP_MTLS_MAX_RESP: usize = 16 * 1024 * 1024;

const RESP_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_408: &[u8] =
    b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_413: &[u8] =
    b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_429: &[u8] =
    b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_431: &[u8] =
    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const RESP_504: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

const MAX_TRIED_UPSTREAMS: usize = 8;
const AUTO_BLOCK_GC_INTERVAL_NS: u64 = 1_000_000_000;
const AUTO_BLOCK_KEEP_NS_FLOOR: u64 = 5_000_000_000;
#[inline]
fn cluster_mode_configured(cfg: &SharedConfig) -> bool {
    let cp = &cfg.control_plane;
    cp.enabled
        && (!cp.peers.is_empty()
            || !matches!(cp.role, ControlRole::Standalone)
            || cp.pull_from.is_some())
}

#[derive(Clone)]
struct AutoBlockPolicy {
    enabled: bool,
    threshold: u32,
    window_ns: u64,
    ttl: Duration,
    reason: BlockReason,
    whitelist: Arc<[IpKey]>,
}

impl Default for AutoBlockPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 100,
            window_ns: 10_000_000_000,
            ttl: Duration::from_secs(600),
            reason: BlockReason::Manual,
            whitelist: Arc::from([]),
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct AutoBlockCounter {
    window_start_ns: u64,
    hits: u32,
    blocked_until_ns: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    CliRead = 0,
    UpConn = 1,
    UpWrite = 2,
    UpRead = 3,
    CliWrite = 4,
}

impl Phase {
    #[inline]
    fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ConnState {
    CliReadHead,
    UpConnecting,
    UpWriteHeadAndMaybeBody,
    CliReadBody,
    UpReadHead,
    CliWriteHeadAndMaybeBody,
    UpReadBody,
    CliWriteBody,
    RetryBackoff,
    WritingErrorThenClose,
    WsTunnelReadClient,
    WsTunnelWriteUpstream,
    WsTunnelReadUpstream,
    WsTunnelWriteClient,
    Closing,
}

#[derive(Copy, Clone, Debug)]
enum HttpBodyState {
    None,
    ContentLength { remaining: u64 },
    Chunked(ChunkedState),
    UntilEof,
}

impl HttpBodyState {
    #[inline]
    fn is_done(&self) -> bool {
        matches!(self, HttpBodyState::None)
    }

    #[inline]
    fn from_kind(kind: BodyKind) -> Self {
        match kind {
            BodyKind::None => Self::None,
            BodyKind::ContentLength { remaining } => {
                if remaining == 0 {
                    Self::None
                } else {
                    Self::ContentLength { remaining }
                }
            }
            BodyKind::Chunked(st) => Self::Chunked(st),
            BodyKind::UntilEof => Self::UntilEof,
        }
    }

    /// Determine how many bytes from `buf` belong to this body (for streaming).
    /// Updates internal state optimistically (safe because failure => close anyway).
    #[inline]
    fn consume(&mut self, buf: &[u8]) -> ConsumeResult {
        match self {
            HttpBodyState::None => ConsumeResult::done(0),
            HttpBodyState::ContentLength { remaining } => {
                if *remaining == 0 {
                    *self = HttpBodyState::None;
                    return ConsumeResult::done_with_data(0, 0);
                }
                let take = (*remaining as usize).min(buf.len());
                *remaining -= take as u64;
                if *remaining == 0 {
                    *self = HttpBodyState::None;
                    ConsumeResult::done_with_data(take, take)
                } else {
                    ConsumeResult::need_more_with_data(take, take)
                }
            }
            HttpBodyState::Chunked(st) => {
                let r = st.consume(buf);
                if r.error {
                    *self = HttpBodyState::None;
                    return r;
                }
                if r.done {
                    *self = HttpBodyState::None;
                }
                r
            }
            HttpBodyState::UntilEof => {
                // close-delimited: all bytes belong to body; done only on EOF (handled by caller)
                ConsumeResult::need_more_with_data(buf.len(), buf.len())
            }
        }
    }
}

struct Conn {
    state: ConnState,

    client_fd: RawFd,
    upstream_fd: RawFd,

    // fixed-file indices
    client_fi: i32,
    upstream_fi: i32,

    buf: u16,
    buf_len: u32,
    buf_off: u32,
    tls_buf: u16,
    tls_wbuf: u16,
    tls_out_len: u32,
    tls_out_off: u32,
    tls_read_in_flight: bool,
    tls_write_in_flight: bool,
    tls: Option<ServerConnection>,
    sni_host: Option<[u8; 256]>,
    sni_len: u8,
    alpn_h2: bool,
    h2_down: Option<DownstreamH2>,

    // used for header parsing
    header_end: u32,

    // stash tail bytes (pipelining)
    stash: [u8; STASH_CAP],
    stash_len: u32,
    replay_len: u32,

    // request/response semantics
    req_keepalive: bool,
    resp_keepalive: bool,
    req_body: HttpBodyState,
    req_body_limit_bytes: u64,
    req_body_received_bytes: u64,
    resp_body: HttpBodyState,
    upstream_connect_ms: Option<u64>,
    upstream_response_ms: Option<u64>,
    upstream_connect_done_ns: u64,

    // selected route info
    route_selected: bool,
    route_id: u32,
    upstream_id: usize,
    upstream_reused: bool,
    up_write_retries: u8,
    resp_started: bool,
    split_hash: u64,
    retry_max: u32,
    retry_backoff_ns: u64,
    retry_idempotent_only: bool,
    retry_count: u32,
    retry_allowed: bool,
    tried_upstreams: [usize; MAX_TRIED_UPSTREAMS],
    tried_len: u8,
    retry_wakeup_ns: u64,
    upstream_sa: Option<net::SockAddr>,
    request_id: u64,
    request_id_text: String,
    error_page_hops: u8,
    log_active: bool,
    log_trace_id: String,
    log_span_id: String,
    log_traceparent: String,
    log_method: String,
    log_path: String,
    log_query: String,
    log_host: String,
    ws_upgrade_requested: bool,
    ws_tunnel_active: bool,
    resp_compressed: bool,
    resp_compress_alg: Algorithm,
    resp_compress_level: i32,
    resp_compressor: Option<PooledCompressor>,
    req_accept_encoding: [u8; REQ_ACCEPT_ENCODING_CAP],
    req_accept_encoding_len: u16,
    client_ip: String,
    client_port: u16,
    slowloris_ip_hash: u64,
    slowloris_state: SlowlorisConnState,
    slowloris_tracking: bool,

    // in-flight operations count (must be 0 before freeing buffer)
    in_flight: u32,

    // phase timing
    phase: Phase,
    phase_started_ns: u64,
    deadline_ns: u64,

    timeout_tier_ns: Option<RouteTimeoutTierNs>,
    timeout_state: Option<RequestTimeoutState>,
    request_started_ns: u64,
    upstream_status: u16,
}

#[derive(Copy, Clone, Debug)]
struct RouteTimeoutTierNs {
    connect_ns: u64,
    response_header_ns: u64,
    per_try_ns: u64,
}

impl Conn {
    fn new(client_fd: RawFd, client_fi: i32, buf: u16, now_ns: u64) -> Self {
        Self {
            state: ConnState::CliReadHead,
            client_fd,
            upstream_fd: -1,
            client_fi,
            upstream_fi: -1,
            buf,
            buf_len: 0,
            buf_off: 0,
            tls_buf: INVALID_BUF,
            tls_wbuf: INVALID_BUF,
            tls_out_len: 0,
            tls_out_off: 0,
            tls_read_in_flight: false,
            tls_write_in_flight: false,
            tls: None,
            sni_host: None,
            sni_len: 0,
            alpn_h2: false,
            h2_down: None,
            header_end: 0,
            stash: [0u8; STASH_CAP],
            stash_len: 0,
            replay_len: 0,
            req_keepalive: false,
            resp_keepalive: false,
            req_body: HttpBodyState::None,
            req_body_limit_bytes: 0,
            req_body_received_bytes: 0,
            resp_body: HttpBodyState::None,
            upstream_connect_ms: None,
            upstream_response_ms: None,
            upstream_connect_done_ns: 0,
            route_selected: false,
            route_id: 0,
            upstream_id: 0,
            upstream_reused: false,
            up_write_retries: 0,
            resp_started: false,
            split_hash: 0,
            retry_max: 0,
            retry_backoff_ns: 0,
            retry_idempotent_only: true,
            retry_count: 0,
            retry_allowed: false,
            tried_upstreams: [0; MAX_TRIED_UPSTREAMS],
            tried_len: 0,
            retry_wakeup_ns: 0,
            upstream_sa: None,
            request_id: 0,
            request_id_text: String::new(),
            error_page_hops: 0,
            log_active: false,
            log_trace_id: String::new(),
            log_span_id: String::new(),
            log_traceparent: String::new(),
            log_method: String::new(),
            log_path: String::new(),
            log_query: String::new(),
            log_host: String::new(),
            ws_upgrade_requested: false,
            ws_tunnel_active: false,
            resp_compressed: false,
            resp_compress_alg: Algorithm::Identity,
            resp_compress_level: 0,
            resp_compressor: None,
            req_accept_encoding: [0u8; REQ_ACCEPT_ENCODING_CAP],
            req_accept_encoding_len: 0,
            client_ip: String::new(),
            client_port: 0,
            slowloris_ip_hash: 0,
            slowloris_state: SlowlorisConnState {
                started_ns: 0,
                bytes_in_headers: 0,
            },
            slowloris_tracking: false,
            in_flight: 0,
            phase: Phase::CliRead,
            phase_started_ns: now_ns,
            deadline_ns: 0,
            timeout_tier_ns: None,
            timeout_state: None,
            request_started_ns: 0,
            upstream_status: 0,
        }
    }
}

struct FixedFiles {
    // fd table registered to io_uring. Slots contain raw fd or -1.
    table: Vec<RawFd>,
    free: Vec<u32>,
}

impl FixedFiles {
    fn new(capacity: usize) -> Self {
        let mut table = Vec::with_capacity(capacity);
        table.resize(capacity, -1);
        let mut free = Vec::with_capacity(capacity.saturating_sub(1));
        // reserve slot 0 for listener
        for i in (1..capacity).rev() {
            free.push(i as u32);
        }
        Self { table, free }
    }

    #[inline]
    fn alloc(&mut self) -> Option<u32> {
        self.free.pop()
    }

    #[inline]
    fn free_slot(&mut self, idx: u32) {
        if idx == 0 {
            return;
        }
        self.table[idx as usize] = -1;
        self.free.push(idx);
    }
}

struct IdleUpstream {
    fd: RawFd,
    fi: i32,
    upstream_id: usize,
    ts_ns: u64,
    watch_tag: u64,
}

struct UpstreamPool {
    keepalive: usize,
    idle_ttl_ns: u64,
    idle: Vec<IdleUpstream>,
}

impl UpstreamPool {
    fn new(keepalive: usize, idle_ttl_ms: u64) -> Self {
        Self {
            keepalive: keepalive.max(1),
            idle_ttl_ns: idle_ttl_ms.saturating_mul(1_000_000),
            idle: Vec::with_capacity(keepalive.max(1)),
        }
    }

    #[inline]
    fn checkout(&mut self) -> Option<IdleUpstream> {
        self.idle.pop()
    }

    fn checkin(&mut self, item: IdleUpstream) -> Option<IdleUpstream> {
        if self.idle.len() >= self.keepalive {
            return Some(item);
        }
        self.idle.push(item);
        None
    }

    fn take_by_tag(&mut self, tag: u64) -> Option<IdleUpstream> {
        let pos = self.idle.iter().position(|it| it.watch_tag == tag)?;
        Some(self.idle.swap_remove(pos))
    }

    fn drain_all(&mut self, out: &mut Vec<IdleUpstream>) {
        out.extend(self.idle.drain(..));
    }
}

struct TimeoutWheel {
    res_ns: u64,
    mask: usize,
    slots: Vec<Vec<Key>>,
    cursor: u64,
}

impl TimeoutWheel {
    fn new(res_ns: u64, slots_pow2: usize) -> Self {
        assert!(slots_pow2.is_power_of_two());
        Self {
            res_ns: res_ns.max(1),
            mask: slots_pow2 - 1,
            slots: (0..slots_pow2).map(|_| Vec::new()).collect(),
            cursor: 0,
        }
    }

    #[inline]
    fn push(&mut self, deadline_ns: u64, key: Key) {
        let slot = ((deadline_ns / self.res_ns) as usize) & self.mask;
        self.slots[slot].push(key);
    }

    fn expire<F: FnMut(Key)>(&mut self, now_ns: u64, mut f: F) {
        let cur = now_ns / self.res_ns;
        if self.cursor == 0 {
            self.cursor = cur;
        }
        let max_steps = 8u64;
        let mut steps = 0u64;
        while self.cursor <= cur && steps < max_steps {
            let idx = (self.cursor as usize) & self.mask;
            let mut bucket = Vec::new();
            std::mem::swap(&mut bucket, &mut self.slots[idx]);
            for k in bucket {
                f(k);
            }
            self.cursor += 1;
            steps += 1;
        }
    }
}

struct WorkerH2BufOps<'a> {
    bufs: &'a mut FixedBuffers,
}

impl H2BufOpsTrait for WorkerH2BufOps<'_> {
    fn slice<'a>(&'a self, buf_id: u16, off: u32, len: u32) -> &'a [u8] {
        self.bufs.slice(buf_id, off, len)
    }

    fn release(&mut self, buf_id: u16) {
        self.bufs.release(buf_id);
    }

    fn retain(&mut self, buf_id: u16) {
        self.bufs.retain(buf_id);
    }
}

#[derive(Default)]
struct H2PendingRequest {
    head: Option<H2RequestHead>,
    body: Vec<H2BufChain>,
    end_stream: bool,
}

#[derive(Default)]
struct H2RequestCollector {
    pending: HashMap<u32, H2PendingRequest>,
    ready: Vec<u32>,
    dropped: Vec<H2BufChain>,
}

impl H2RequestCollector {
    fn take_ready(&mut self) -> Vec<(u32, H2RequestHead, Vec<H2BufChain>)> {
        let mut out = Vec::new();
        for sid in self.ready.drain(..) {
            let Some(mut p) = self.pending.remove(&sid) else {
                continue;
            };
            let Some(head) = p.head.take() else {
                continue;
            };
            out.push((sid, head, p.body));
        }
        out
    }

    fn release_dropped(&mut self, ops: &mut dyn H2BufOpsTrait) {
        while let Some(mut c) = self.dropped.pop() {
            c.release(ops);
        }
    }
}

impl H2DownstreamSink for H2RequestCollector {
    fn on_request_headers(
        &mut self,
        _down: H2ConnKey,
        sid: u32,
        end_stream: bool,
        head: H2RequestHead,
    ) {
        let e = self.pending.entry(sid).or_default();
        e.head = Some(head);
        if end_stream {
            e.end_stream = true;
            self.ready.push(sid);
        }
    }

    fn on_request_data(&mut self, _down: H2ConnKey, sid: u32, end_stream: bool, data: H2BufChain) {
        let e = self.pending.entry(sid).or_default();
        e.body.push(data);
        if end_stream {
            e.end_stream = true;
            if e.head.is_some() {
                self.ready.push(sid);
            }
        }
    }

    fn on_rst_stream(&mut self, _down: H2ConnKey, sid: u32, _code: arc_proto_h2::error::H2Code) {
        if let Some(mut p) = self.pending.remove(&sid) {
            self.dropped.append(&mut p.body);
        }
    }

    fn on_goaway(&mut self, _down: H2ConnKey, _last_sid: u32, _code: arc_proto_h2::error::H2Code) {}

    fn on_conn_error(&mut self, _down: H2ConnKey, _err: arc_proto_h2::error::H2Error) {}
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum H2H1RoundtripError {
    Timeout,
    Io,
    Proto,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RouteSelectError {
    NotFound,
    Ambiguous,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ErrorResponseSource {
    Gateway,
    Upstream,
}

#[derive(Clone)]
struct AccessLogSnapshot {
    trace_id: String,
    span_id: Option<String>,
    request_id: String,
    method: String,
    path: String,
    query: String,
    host: String,
    route: String,
    upstream: String,
    upstream_addr: String,
    client_ip: String,
    client_port: u16,
    tls: bool,
    http_version: String,
    status: u16,
    duration_ms: u64,
    upstream_connect_ms: Option<u64>,
    upstream_response_ms: Option<u64>,
    attempt: u32,
}

#[derive(Clone)]
struct ForwardedIdentity {
    effective_client_ip: String,
    x_forwarded_for: String,
    real_ip_header: Arc<str>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum H2H1TaskState {
    Connecting,
    WritingReq,
    ReadingResp,
}

#[inline]
fn h2_log_timing(_stream_id: u32, _phase_name: &str, _started_ns: u64) {
}

struct H2H1Task {
    down: H2ConnKey,
    sid: u32,
    upstream_id: usize,

    upstream_fd: RawFd,
    upstream_fi: i32,
    upstream_sa: net::SockAddr,

    io_buf: u16,
    io_len: u32,
    io_off: u32,

    req: Vec<u8>,
    req_sent: usize,
    req_keepalive: bool,
    resp_keepalive: bool,
    resp: Vec<u8>,

    status: u16,
    head_end: Option<usize>,
    body_kind: Option<BodyKind>,
    saw_eof: bool,

    state: H2H1TaskState,
    deadline_ns: u64,
    started_ns: u64,
    connect_done_ns: Option<u64>,
    access_log: Option<AccessLogSnapshot>,
    response_header_muts: Arc<[CompiledHeaderMutation]>,
}

enum H2DispatchError {
    RefusedStream(Option<AccessLogSnapshot>),
    Failed(Option<AccessLogSnapshot>),
}

#[derive(Debug, Clone)]
struct RequestIdDecision {
    value: String,
    force_set: bool,
    original: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum UpMtlsTaskState {
    Connecting,
    Writing,
    Reading,
}

struct UpMtlsTask {
    down: H2ConnKey,
    upstream_id: usize,

    upstream_fd: RawFd,
    upstream_fi: i32,
    upstream_sa: net::SockAddr,

    io_buf: u16,
    io_len: u32,
    io_off: u32,

    tls: ClientConnection,
    resp: Vec<u8>,
    head_end: Option<usize>,
    body_kind: Option<BodyKind>,
    saw_eof: bool,

    state: UpMtlsTaskState,
    deadline_ns: u64,
}

struct RawBufWriter {
    ptr: *mut u8,
    cap: usize,
    pos: usize,
}

impl RawBufWriter {
    #[inline]
    fn new(ptr: *mut u8, cap: usize) -> Self {
        Self { ptr, cap, pos: 0 }
    }

    #[inline]
    fn written(&self) -> usize {
        self.pos
    }
}

impl Write for RawBufWriter {
    #[inline]
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        if self.pos >= self.cap {
            return Ok(0);
        }
        let n = src.len().min(self.cap - self.pos);
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.add(self.pos), n);
        }
        self.pos += n;
        Ok(n)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct RawBufReader {
    ptr: *const u8,
    len: usize,
    pos: usize,
}

impl RawBufReader {
    #[inline]
    fn new(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len, pos: 0 }
    }
}

impl Read for RawBufReader {
    #[inline]
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let n = out.len().min(self.len - self.pos);
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(self.pos), out.as_mut_ptr(), n);
        }
        self.pos += n;
        Ok(n)
    }
}

pub struct Worker {
    id: usize,

    swap: Arc<ArcSwap<SharedConfig>>,
    active_cfg: Arc<SharedConfig>,
    active_gen: u64,

    metrics: Arc<WorkerMetrics>,

    listener_fi: i32,

    uring: Uring,
    bufs: FixedBuffers,
    conns: Slab<Conn>,
    files: FixedFiles,
    idle_epfd: RawFd,
    idle_ep_events: Vec<libc::epoll_event>,
    idle_gc: Vec<IdleUpstream>,
    idle_watch_seq: u64,

    upstream_pools: Vec<UpstreamPool>,
    upstream_runtime_addrs: Vec<SocketAddr>,
    upstream_dns_next_refresh_ns: Vec<u64>,
    upstream_open_counts: Vec<AtomicUsize>,
    upstream_leak_warn_growth: u64,
    upstream_leak_warn_window_ns: u64,
    upstream_leak_warn_cooldown_ns: u64,
    upstream_leak_baseline_open: u64,
    upstream_leak_baseline_ns: u64,
    upstream_leak_last_warn_ns: u64,
    upstream_tls: Vec<Option<UpstreamTlsRuntime>>,
    downstream_tls: Option<DownstreamTls>,
    mirror_dispatcher: Option<MirrorDispatcher>,
    mirror_targets_by_route: Arc<[Arc<[Arc<MirrorTargetRuntime>]>]>,
    rr_route_counters: Vec<AtomicUsize>,
    compression_global: GlobalCompressionConfig,
    compression_route_overrides: Arc<[RouteCompressionOverrides]>,
    compression_pools: CompressorPools,
    plugins: Option<arc_plugins::WorkerPlugins>,
    global_limiter: Option<GlobalWorkerLimiter>,
    auto_block_policy: AutoBlockPolicy,
    slowloris_guard: Option<SlowlorisGuard>,
    auto_block_counters: HashMap<u64, AutoBlockCounter>,
    auto_block_last_gc_ns: u64,
    cluster_circuit: Arc<ClusterCircuit>,
    cluster_circuit_hot_enabled: bool,
    shutdown: Arc<AtomicBool>,
    drained_workers: Arc<AtomicUsize>,
    graceful_shutdown_timeout: Duration,
    graceful_shutdown_started_ns: Option<u64>,
    drain_reported: bool,
    accepting: bool,
    should_exit: bool,
    access_log_hot_enabled: bool,
    access_log_hot_next_refresh_ns: u64,

    accept_multishot: bool,
    tick_multishot: bool,

    tick_ts: sys::__kernel_timespec,

    last_sq_dropped: u32,
    last_cq_overflow: u32,

    timeout_wheel: TimeoutWheel,
    h2_timeout_wheel: TimeoutWheel,
    mtls_timeout_wheel: TimeoutWheel,

    h2_tasks: Slab<H2H1Task>,
    h2_tasks_by_down: HashMap<H2ConnKey, Vec<Key>>,
    h2_down_pending: HashMap<H2ConnKey, u32>,
    h2_up_inflight: Vec<u32>,
    up_mtls_tasks: Slab<UpMtlsTask>,
    up_mtls_tasks_by_down: HashMap<H2ConnKey, Vec<Key>>,
}

impl Worker {
    #[inline]
    fn global_rate_key(route_id: u32, client_ip: &str) -> u64 {
        // Stable per-route+client key: isolates abusive clients from healthy clients on the same route.
        let mut h = fnv1a64(0x9E37_79B9_7F4A_7C15, &route_id.to_le_bytes());
        h = fnv1a64(h, client_ip.as_bytes());
        splitmix64(h)
    }

    #[inline]
    fn allow_route_rate_limit(
        global_limiter: Option<&mut GlobalWorkerLimiter>,
        route_id: u32,
        client_ip: &str,
        rate_limit_policy: Option<RateLimitPolicy>,
        local_limiter: Option<&Arc<arc_rate_limit::Limiter>>,
        now_ns: u64,
    ) -> bool {
        if let Some(policy) = rate_limit_policy {
            if let Some(global) = global_limiter {
                let key = Self::global_rate_key(route_id, client_ip);
                return global.try_acquire(
                    key,
                    GlobalRatePolicy::new(policy.rps, policy.burst),
                    now_ns,
                );
            }
        }

        if let Some(local) = local_limiter {
            return local.allow(now_ns);
        }

        true
    }

    fn build_auto_block_policy(raw_json: &str) -> AutoBlockPolicy {
        let sec = parse_security_config_best_effort(raw_json);
        let cfg = sec.xdp.auto_block;
        let mut wl = Vec::new();
        for item in cfg.whitelist.iter() {
            match parse_ip_or_cidr_to_ip_key(item) {
                Some(v) => wl.push(v),
                None => {
                    eprintln!("worker auto-block warn: ignore invalid whitelist entry '{item}'");
                }
            }
        }
        AutoBlockPolicy {
            enabled: sec.xdp.enabled && cfg.enabled,
            threshold: cfg.threshold.max(1),
            window_ns: cfg.window_secs.max(1).saturating_mul(1_000_000_000),
            ttl: Duration::from_secs(cfg.ttl_secs.max(1)),
            reason: parse_block_reason(cfg.reason.as_str()),
            whitelist: Arc::from(wl),
        }
    }

    fn build_slowloris_guard(raw_json: &str) -> Option<SlowlorisGuard> {
        let sec = parse_security_config_best_effort(raw_json);
        if !sec.l7_protection.slowloris.enabled {
            return None;
        }
        Some(SlowlorisGuard::new(&sec.l7_protection))
    }

    #[inline]
    fn slowloris_ip_hash(client_ip: &str) -> u64 {
        match client_ip.parse::<IpAddr>() {
            Ok(ip) => {
                let ip_key = ip_addr_to_ip_key(ip);
                let mut h = fnv1a64(0x3F97_6E2A_B8D1_4C5F, &ip_key.addr);
                h = fnv1a64(h, &[ip_key.prefix_len]);
                splitmix64(h)
            }
            Err(_) => splitmix64(fnv1a64(0x3F97_6E2A_B8D1_4C5F, client_ip.as_bytes())),
        }
    }

    #[inline]
    fn slowloris_start_tracking(
        guard: &SlowlorisGuard,
        conn: &mut Conn,
        now_ns: u64,
    ) -> SlowlorisDecision {
        let ip_hash = if conn.slowloris_ip_hash != 0 {
            conn.slowloris_ip_hash
        } else {
            Self::slowloris_ip_hash(conn.client_ip.as_str())
        };
        conn.slowloris_ip_hash = ip_hash;
        conn.slowloris_state = guard.init_conn_state(now_ns);
        let decision = guard.on_conn_start(ip_hash);
        conn.slowloris_tracking = matches!(decision, SlowlorisDecision::Allow);
        decision
    }

    #[inline]
    fn slowloris_rebind_client_ip(
        guard: Option<&SlowlorisGuard>,
        conn: &mut Conn,
        effective_client_ip: &str,
    ) -> SlowlorisDecision {
        if effective_client_ip.is_empty() || conn.client_ip == effective_client_ip {
            return SlowlorisDecision::Allow;
        }

        let prev_hash = conn.slowloris_ip_hash;
        let prev_tracking = conn.slowloris_tracking;
        let next_hash = Self::slowloris_ip_hash(effective_client_ip);

        if prev_tracking {
            if let Some(guard) = guard {
                if prev_hash != 0 {
                    guard.on_conn_end(prev_hash);
                }
                let decision = guard.on_conn_start(next_hash);
                if !matches!(decision, SlowlorisDecision::Allow) {
                    // Revert counter so this connection keeps the original tracking key.
                    if prev_hash != 0 {
                        let _ = guard.on_conn_start(prev_hash);
                    }
                    return decision;
                }
            }
        }

        conn.client_ip.clear();
        conn.client_ip.push_str(effective_client_ip);
        conn.slowloris_ip_hash = next_hash;
        SlowlorisDecision::Allow
    }

    #[inline]
    fn slowloris_stop_tracking(guard: Option<&SlowlorisGuard>, conn: &mut Conn) {
        if !conn.slowloris_tracking {
            return;
        }
        if let Some(guard) = guard {
            guard.on_conn_end(conn.slowloris_ip_hash);
        }
        conn.slowloris_tracking = false;
    }

    #[inline]
    fn slowloris_on_header_bytes(
        guard: Option<&SlowlorisGuard>,
        conn: &mut Conn,
        now_ns: u64,
        added_bytes: u32,
    ) -> SlowlorisDecision {
        if added_bytes == 0 || !conn.slowloris_tracking {
            return SlowlorisDecision::Allow;
        }
        let Some(guard) = guard else {
            return SlowlorisDecision::Allow;
        };
        guard.on_header_bytes(now_ns, &mut conn.slowloris_state, added_bytes)
    }

    #[inline]
    fn slowloris_deadline_ns(
        guard: Option<&SlowlorisGuard>,
        conn: &Conn,
        fallback_deadline_ns: u64,
    ) -> u64 {
        if !conn.slowloris_tracking {
            return fallback_deadline_ns;
        }
        let Some(guard) = guard else {
            return fallback_deadline_ns;
        };
        if conn.slowloris_state.started_ns == 0 {
            return fallback_deadline_ns;
        }
        let slow_deadline = conn
            .slowloris_state
            .started_ns
            .saturating_add(guard.headers_timeout_ns());
        fallback_deadline_ns.min(slow_deadline)
    }

    #[inline]
    fn auto_block_counter_key(route_id: u32, ip: IpKey) -> u64 {
        let mut h = fnv1a64(0xA9BF_7C13_41D2_55E1, &route_id.to_le_bytes());
        h = fnv1a64(h, &ip.addr);
        h = fnv1a64(h, &[ip.prefix_len]);
        splitmix64(h)
    }

    #[inline]
    fn is_auto_block_whitelisted(&self, ip: IpKey) -> bool {
        self.auto_block_policy
            .whitelist
            .iter()
            .copied()
            .any(|w| ip_key_prefix_match(w, ip))
    }

    fn auto_block_gc(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.auto_block_last_gc_ns) < AUTO_BLOCK_GC_INTERVAL_NS {
            return;
        }
        self.auto_block_last_gc_ns = now_ns;
        let keep_ns = self
            .auto_block_policy
            .window_ns
            .saturating_mul(4)
            .max(AUTO_BLOCK_KEEP_NS_FLOOR);
        self.auto_block_counters.retain(|_, s| {
            let recent = now_ns.saturating_sub(s.window_start_ns) <= keep_ns;
            let still_blocked = now_ns < s.blocked_until_ns;
            recent || still_blocked
        });
    }

    fn on_route_rate_limited(&mut self, route_id: u32, client_ip: &str, now_ns: u64) {
        if !self.auto_block_policy.enabled {
            return;
        }
        self.auto_block_gc(now_ns);
        let Some(ip_addr) = client_ip.parse::<IpAddr>().ok() else {
            return;
        };
        let ip = ip_addr_to_ip_key(ip_addr).as_exact();
        if self.is_auto_block_whitelisted(ip) {
            return;
        }

        let k = Self::auto_block_counter_key(route_id, ip);
        let mut should_block = false;
        {
            let s = self
                .auto_block_counters
                .entry(k)
                .or_insert(AutoBlockCounter {
                    window_start_ns: now_ns,
                    hits: 0,
                    blocked_until_ns: 0,
                });
            if now_ns.saturating_sub(s.window_start_ns) >= self.auto_block_policy.window_ns {
                s.window_start_ns = now_ns;
                s.hits = 0;
            }
            if now_ns < s.blocked_until_ns {
                return;
            }
            s.hits = s.hits.saturating_add(1);
            if s.hits >= self.auto_block_policy.threshold {
                s.hits = 0;
                s.window_start_ns = now_ns;
                should_block = true;
            }
        }

        if !should_block {
            return;
        }

        let Some(xdp) = global_xdp_manager() else {
            return;
        };
        let wl = xdp.whitelist_blocking();
        if wl.contains(ip).unwrap_or(false) {
            return;
        }

        let bl = xdp.blacklist_blocking();
        match bl.add(
            ip,
            self.auto_block_policy.ttl,
            self.auto_block_policy.reason,
        ) {
            Ok(()) => {
                if let Some(s) = self.auto_block_counters.get_mut(&k) {
                    s.blocked_until_ns = now_ns.saturating_add(
                        self.auto_block_policy
                            .ttl
                            .as_nanos()
                            .min(u128::from(u64::MAX)) as u64,
                    );
                }
            }
            Err(e) => {
                // Retry quickly on transient init race (xdp manager/maps not ready yet).
                if let Some(s) = self.auto_block_counters.get_mut(&k) {
                    s.hits = self.auto_block_policy.threshold.saturating_sub(1);
                }
                eprintln!("worker auto-block warn: xdp add failed for {client_ip}: {e}");
            }
        }
    }

    #[inline]
    fn mark_upstream_failure(&self, upstream_id: usize) {
        if !self.cluster_circuit_hot_enabled {
            return;
        }
        if let Some(up) = self.active_cfg.upstreams.get(upstream_id) {
            self.cluster_circuit.record_failure(up.addr);
        }
    }

    #[inline]
    fn mark_upstream_success(&self, upstream_id: usize) {
        if !self.cluster_circuit_hot_enabled {
            return;
        }
        if let Some(up) = self.active_cfg.upstreams.get(upstream_id) {
            self.cluster_circuit.record_success(up.addr);
        }
    }

    #[inline]
    fn upstream_circuit_open(&self, upstream_id: usize) -> bool {
        if !self.cluster_circuit_hot_enabled {
            return false;
        }
        self.active_cfg
            .upstreams
            .get(upstream_id)
            .map(|up| self.cluster_circuit.is_open(up.addr))
            .unwrap_or(false)
    }

    #[inline]
    fn ms_to_ns(ms: u64) -> u64 {
        ms.saturating_mul(1_000_000).max(1)
    }

    fn resolve_route_timeout_http1(
        &self,
        route: &arc_config::CompiledRoute,
        head_block: &[u8],
        now_ns: u64,
    ) -> Option<(RouteTimeoutTierNs, RequestTimeoutState)> {
        let tier = route.timeout_tier.as_ref()?;
        let connect_ns = Self::ms_to_ns(tier.connect_ms);
        let response_header_ns = Self::ms_to_ns(tier.response_header_ms);
        let per_try_ns = Self::ms_to_ns(tier.per_try_ms);
        let mut total_ns = Self::ms_to_ns(tier.total_ms);

        if let Some(dp) = tier.deadline_propagation.as_ref() {
            if let Some(raw) = http1_header_value(head_block, dp.header.as_bytes()) {
                if let Ok(v) = std::str::from_utf8(raw) {
                    if let Some(client_budget) = parse_deadline_budget(v) {
                        total_ns = total_ns.min(dur_to_ns_saturating(client_budget).max(1));
                    }
                }
            }
        }

        let mut state = RequestTimeoutState::start(now_ns, total_ns);
        state.start_try(now_ns, per_try_ns);
        Some((
            RouteTimeoutTierNs {
                connect_ns,
                response_header_ns,
                per_try_ns,
            },
            state,
        ))
    }

    #[inline]
    fn should_respond_504_on_timeout(state: ConnState) -> bool {
        matches!(
            state,
            ConnState::UpConnecting
                | ConnState::UpWriteHeadAndMaybeBody
                | ConnState::UpReadHead
                | ConnState::UpReadBody
                | ConnState::RetryBackoff
        )
    }

    #[inline]
    fn ws_forward_client_to_upstream(&mut self, key: Key, n: u32) -> Result<()> {
        if n == 0 {
            return self.schedule_client_read(key, 0);
        }
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if !conn.ws_tunnel_active || conn.upstream_fi < 0 {
            let _ = conn;
            self.close_conn(key);
            return Ok(());
        }
        conn.buf_off = 0;
        conn.buf_len = n;
        conn.state = ConnState::WsTunnelWriteUpstream;
        let up_fi = conn.upstream_fi;
        let _ = conn;
        self.schedule_write(key, Side::Upstream, up_fi, 0, n)
    }

    #[inline]
    fn ws_forward_upstream_to_client(&mut self, key: Key, n: u32) -> Result<()> {
        if n == 0 {
            return self.schedule_read_upstream(key, 0);
        }
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if !conn.ws_tunnel_active {
            let _ = conn;
            self.close_conn(key);
            return Ok(());
        }
        conn.buf_off = 0;
        conn.buf_len = n;
        conn.state = ConnState::WsTunnelWriteClient;
        let _ = conn;
        self.schedule_client_write(key, n)
    }

    pub fn run(
        id: usize,
        worker_count: usize,
        swap: Arc<ArcSwap<SharedConfig>>,
        metrics: Arc<WorkerMetrics>,
        global_limiter: Option<GlobalWorkerLimiter>,
        cluster_circuit: Arc<ClusterCircuit>,
        shutdown: Arc<AtomicBool>,
        drained_workers: Arc<AtomicUsize>,
        graceful_shutdown_timeout: Duration,
    ) -> Result<()> {
        let cpu_count = cpu::cpu_count().unwrap_or(1).max(1);
        let core = id % cpu_count;

        cpu::set_current_thread_name(&format!("arc-gw-{id}"));
        if let Err(e) = cpu::set_thread_affinity(core) {
            eprintln!("worker[{id}] warn: failed to set cpu affinity to core {core}: {e}");
        }
        if let Err(e) = arc_logging::init_worker(id) {
            return Err(ArcError::config(format!(
                "worker[{id}] init arc-logging worker tls failed: {e}"
            )));
        }

        let cfg = swap.load_full();
        let downstream_tls = DownstreamTls::build(&cfg)?;
        let listener_fd = net::create_listener(&cfg.listen, cfg.listen_backlog, true)
            .map_err(|e| ArcError::io("create_listener", e))?;

        // io_uring init with fallbacks
        let mut io_cfg = cfg.io_uring.clone();
        if cfg
            .downstream_tls
            .as_ref()
            .map(|t| t.enable_h2)
            .unwrap_or(false)
            && io_cfg.entries < 1024
        {
            eprintln!(
                "worker[{id}] warn: io_uring.entries={} too low for h2 workload; auto-raised to 1024",
                io_cfg.entries
            );
            io_cfg.entries = 1024;
        }
        let uring = make_uring(&io_cfg, core as u32).map_err(|e| ArcError::io("make_uring", e))?;

        let idle_epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if idle_epfd < 0 {
            return Err(ArcError::io(
                "epoll_create1(idle upstream)",
                io::Error::last_os_error(),
            ));
        }

        // buffer pool
        let mut buf_count = if cfg.buffers.buf_count == 0 {
            // default: 1 buffer per conn (no duplex), cap to u16::MAX
            let desired = cfg.workers.max(1) * 0; // placeholder (workers not used for per-worker capacity)
            let _ = desired;
            // We don't have conn_capacity in config; use safe default.
            // For simplicity we make buf_count = 65535/4 with 8k -> ~512MB; user should configure.
            // In production, set buf_count explicitly.
            16384usize.min(u16::MAX as usize)
        } else {
            cfg.buffers.buf_count
        };

        // TLS path consumes one fixed buffer for plain bytes and one for cipher bytes.
        // Keep a practical floor so c=128 smoke/bench doesn't collapse into connect errors.
        let tls_enabled = downstream_tls.is_some();
        let h2_enabled = cfg
            .downstream_tls
            .as_ref()
            .map(|t| t.enable_h2)
            .unwrap_or(false);
        let min_conn_per_worker = 128usize;
        let min_conn_floor = cfg.workers.max(1).saturating_mul(min_conn_per_worker);
        let mut min_buf_floor = if tls_enabled {
            min_conn_floor.saturating_mul(3)
        } else {
            min_conn_floor
        };
        if h2_enabled {
            // H2 场景下，每个 stream 的 H2->H1 任务和下游帧缓存都会占用 fixed buffer。
            // floor 太低会在 c32/m10 这类场景出现“跑到 80% 后卡住”的缓冲区饥饿。
            min_buf_floor = min_buf_floor.max(2048);
        }
        if buf_count < min_buf_floor {
            eprintln!(
                "worker[{id}] warn: buffers.buf_count={} too low for current mode (tls={} h2={} workers={}); auto-raised to {}",
                buf_count,
                tls_enabled,
                h2_enabled,
                cfg.workers.max(1),
                min_buf_floor
            );
            buf_count = min_buf_floor.min(u16::MAX as usize);
        }

        let mut bufs = FixedBuffers::new(buf_count, cfg.buffers.buf_size)
            .map_err(|e| ArcError::io("FixedBuffers::new", e))?;

        let mut uring = uring;
        let mut iovecs = bufs.iovecs();
        uring
            .register_buffers(&mut iovecs)
            .map_err(|e| ArcError::io("register_buffers", e))?;

        // fixed files:
        // capacity: listener(1) + (buf_count as proxy for max active conns)*2 + upstream idle
        // 为了避免依赖 “conn_capacity” 配置，这里采用保守上界：buf_count*2 + 1
        let file_cap = 1usize
            .saturating_add(buf_count.saturating_mul(2))
            .min(1_000_000);

        let mut files = FixedFiles::new(file_cap);
        uring
            .register_files(&files.table)
            .map_err(|e| ArcError::io("register_files", e))?;

        // assign listener to slot 0
        files.table[0] = listener_fd;
        uring
            .update_files(0, &[listener_fd])
            .map_err(|e| ArcError::io("update_files(listener)", e))?;

        let listener_fi = 0i32;

        // conns slab: approximate with buf_count capacity (one buffer per conn)
        let conns = Slab::new(buf_count).map_err(|e| ArcError::io("Slab::new", e))?;
        let h2_tasks = Slab::new(buf_count).map_err(|e| ArcError::io("H2TaskSlab::new", e))?;
        let up_mtls_tasks =
            Slab::new(buf_count).map_err(|e| ArcError::io("UpMtlsTaskSlab::new", e))?;

        // upstream pools from config
        let mut upstream_pools: Vec<UpstreamPool> = Vec::with_capacity(cfg.upstreams.len());
        let mut upstream_runtime_addrs: Vec<SocketAddr> = Vec::with_capacity(cfg.upstreams.len());
        let mut upstream_dns_next_refresh_ns: Vec<u64> = Vec::with_capacity(cfg.upstreams.len());
        let mut upstream_open_counts: Vec<AtomicUsize> = Vec::with_capacity(cfg.upstreams.len());
        let now_ns = monotonic_nanos();
        for up in cfg.upstreams.iter() {
            upstream_pools.push(UpstreamPool::new(up.keepalive, up.idle_ttl_ms));
            upstream_runtime_addrs.push(up.addr);
            let refresh_ns = up.dns_refresh_ms.saturating_mul(1_000_000);
            if up.host.is_some() && refresh_ns > 0 {
                upstream_dns_next_refresh_ns.push(now_ns.saturating_add(refresh_ns));
            } else {
                upstream_dns_next_refresh_ns.push(0);
            }
            upstream_open_counts.push(AtomicUsize::new(0));
        }
        let upstream_leak_warn_growth = cfg.limits.upstream_leak_warn_growth as u64;
        let upstream_leak_warn_window_ns =
            cfg.limits.upstream_leak_warn_window_ms.saturating_mul(1_000_000);
        let upstream_leak_warn_cooldown_ns = cfg
            .limits
            .upstream_leak_warn_cooldown_ms
            .saturating_mul(1_000_000);
        let upstream_tls = Self::build_upstream_tls_runtime(cfg.as_ref())?;

        // plugin pools (per worker)
        let plugins = if let Some(catalog) = cfg.plugins.catalog.as_ref() {
            Some(catalog.build_worker()?)
        } else {
            None
        };
        let (mirror_dispatcher, mirror_targets_by_route) =
            Self::build_mirror_runtime(cfg.as_ref(), metrics.clone())?;
        let (compression_global, compression_route_overrides) =
            Self::build_compression_runtime(cfg.as_ref());
        let compression_pools = CompressorPools::new(1)?;
        let timeout_wheel =
            TimeoutWheel::new((cfg.io_uring.tick_ms as u64).max(1) * 1_000_000, 8192);
        let h2_timeout_wheel =
            TimeoutWheel::new((cfg.io_uring.tick_ms as u64).max(1) * 1_000_000, 8192);
        let mtls_timeout_wheel =
            TimeoutWheel::new((cfg.io_uring.tick_ms as u64).max(1) * 1_000_000, 8192);
        let auto_block_policy = Self::build_auto_block_policy(cfg.raw_json.as_ref());
        let slowloris_guard = Self::build_slowloris_guard(cfg.raw_json.as_ref());
        if auto_block_policy.enabled {
            eprintln!(
                "worker[{id}] auto-block enabled: threshold={} window_ms={} ttl_ms={} whitelist={}",
                auto_block_policy.threshold,
                auto_block_policy.window_ns / 1_000_000,
                auto_block_policy.ttl.as_millis(),
                auto_block_policy.whitelist.len()
            );
        }
        if slowloris_guard.is_some() {
            eprintln!("worker[{id}] slowloris guard enabled");
        }

        let mut w = Worker {
            id,
            swap,
            active_cfg: cfg.clone(),
            active_gen: cfg.generation,
            metrics,

            listener_fi,

            uring,
            bufs,
            conns,
            files,
            idle_epfd,
            idle_ep_events: vec![libc::epoll_event { events: 0, u64: 0 }; 256],
            idle_gc: Vec::new(),
            idle_watch_seq: 1,

            upstream_pools,
            upstream_runtime_addrs,
            upstream_dns_next_refresh_ns,
            upstream_open_counts,
            upstream_leak_warn_growth,
            upstream_leak_warn_window_ns,
            upstream_leak_warn_cooldown_ns,
            upstream_leak_baseline_open: 0,
            upstream_leak_baseline_ns: 0,
            upstream_leak_last_warn_ns: 0,
            upstream_tls,
            downstream_tls,
            mirror_dispatcher,
            mirror_targets_by_route,
            rr_route_counters: Self::build_rr_route_counters(cfg.routes.len()),
            compression_global,
            compression_route_overrides,
            compression_pools,
            plugins,
            global_limiter,
            auto_block_policy,
            slowloris_guard,
            auto_block_counters: HashMap::new(),
            auto_block_last_gc_ns: 0,
            cluster_circuit,
            cluster_circuit_hot_enabled: cluster_mode_configured(cfg.as_ref()),
            shutdown,
            drained_workers,
            graceful_shutdown_timeout,
            graceful_shutdown_started_ns: None,
            drain_reported: false,
            accepting: true,
            should_exit: false,
            access_log_hot_enabled: arc_logging::access_log_hot_path_enabled(),
            access_log_hot_next_refresh_ns: now_ns.saturating_add(10_000_000),

            accept_multishot: cfg.io_uring.accept_multishot,
            tick_multishot: false,

            tick_ts: sys::__kernel_timespec {
                tv_sec: (cfg.io_uring.tick_ms as i64) / 1000,
                tv_nsec: ((cfg.io_uring.tick_ms as i64) % 1000) * 1_000_000,
            },

            last_sq_dropped: 0,
            last_cq_overflow: 0,
            timeout_wheel,
            h2_timeout_wheel,
            mtls_timeout_wheel,
            h2_tasks,
            h2_tasks_by_down: HashMap::new(),
            h2_down_pending: HashMap::new(),
            h2_up_inflight: vec![0; cfg.upstreams.len()],
            up_mtls_tasks,
            up_mtls_tasks_by_down: HashMap::new(),
        };

        w.last_sq_dropped = w.uring.sq_dropped();
        w.last_cq_overflow = w.uring.cq_overflow();

        // post accept(s): keep a small accept queue in-flight for non-multishot mode
        if w.accept_multishot {
            w.post_accept()?;
        } else {
            let prepost = w.active_cfg.io_uring.accept_prepost.max(1);
            for _ in 0..prepost {
                w.post_accept()?;
            }
        }
        // post tick
        w.post_tick()?;
        w.refresh_upstream_pool_metrics(monotonic_nanos());

        w.event_loop(worker_count)
    }

    fn post_accept(&mut self) -> Result<()> {
        if !self.accepting {
            return Ok(());
        }
        let a = sqe::accept(
            self.listener_fi,
            true,
            self.accept_multishot,
            op::pack_accept(),
        );
        ring_push_blocking(&mut self.uring, a).map_err(|e| ArcError::io("push accept", e))?;
        Ok(())
    }

    fn post_tick(&mut self) -> Result<()> {
        let t = sqe::timeout(
            &self.tick_ts as *const sys::__kernel_timespec,
            self.tick_multishot,
            op::pack_tick(),
        );
        ring_push_blocking(&mut self.uring, t).map_err(|e| ArcError::io("push tick", e))?;
        Ok(())
    }

    fn begin_graceful_shutdown(&mut self) {
        if self.graceful_shutdown_started_ns.is_some() {
            return;
        }

        self.graceful_shutdown_started_ns = Some(monotonic_nanos());
        self.accepting = false;

        let slot = self.listener_fi as usize;
        if slot < self.files.table.len() {
            let fd = self.files.table[slot];
            eprintln!(
                "worker[{}] graceful shutdown: listener slot={} fd={}",
                self.id, slot, fd
            );
            if fd >= 0 {
                let _ = self.uring.update_files(self.listener_fi as u32, &[-1]);
                self.files.table[slot] = -1;
                close_fd(fd);
            }
        }

        let active = self.metrics.active_current.load(Ordering::Relaxed);
        eprintln!(
            "worker[{}] graceful shutdown: stop accepting new connections, draining {} active connections (timeout={}s)",
            self.id,
            active,
            self.graceful_shutdown_timeout.as_secs()
        );
    }

    fn force_close_all_connections(&mut self) {
        let keys = self.conns.active_keys();
        for key in keys {
            self.close_conn(key);
        }
    }

    fn update_graceful_shutdown_state(&mut self) {
        if self.shutdown.load(Ordering::Relaxed) {
            self.begin_graceful_shutdown();
        }

        let Some(started_ns) = self.graceful_shutdown_started_ns else {
            return;
        };

        let active = self.metrics.active_current.load(Ordering::Relaxed);
        if active == 0 {
            if !self.should_exit {
                eprintln!(
                    "worker[{}] graceful shutdown: no active connections, exiting worker loop",
                    self.id
                );
            }
            self.should_exit = true;
            return;
        }

        let timeout_ns = self
            .graceful_shutdown_timeout
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let now_ns = monotonic_nanos();
        if now_ns.saturating_sub(started_ns) >= timeout_ns {
            eprintln!(
                "worker[{}] graceful shutdown timeout, force closing {} active connections",
                self.id, active
            );
            self.force_close_all_connections();
            self.should_exit = true;
        }
    }

    #[inline]
    fn mark_drained_worker_once(&mut self) {
        if self.drain_reported {
            return;
        }
        self.drain_reported = true;
        self.drained_workers.fetch_add(1, Ordering::Relaxed);
    }

    fn event_loop(&mut self, _worker_count: usize) -> Result<()> {
        loop {
            if self.should_exit {
                self.mark_drained_worker_once();
                return Ok(());
            }
            self.uring
                .submit_and_wait(1)
                .map_err(|e| ArcError::io("submit_and_wait", e))?;

            while let Some(cqe) = self.uring.pop_cqe() {
                self.handle_cqe(cqe)?;
                if self.should_exit {
                    self.mark_drained_worker_once();
                    return Ok(());
                }
            }

            self.observe_ring_health();
            if self.should_exit {
                self.mark_drained_worker_once();
                return Ok(());
            }
        }
    }

    fn observe_ring_health(&mut self) {
        let sq_dropped = self.uring.sq_dropped();
        if sq_dropped != self.last_sq_dropped {
            self.metrics
                .ring_sq_dropped
                .store(sq_dropped as u64, Ordering::Relaxed);
            self.last_sq_dropped = sq_dropped;
        }

        let cq_overflow = self.uring.cq_overflow();
        if cq_overflow != self.last_cq_overflow {
            self.metrics
                .ring_cq_overflow
                .store(cq_overflow as u64, Ordering::Relaxed);
            self.last_cq_overflow = cq_overflow;
        }
    }

    fn handle_cqe(&mut self, cqe: sys::io_uring_cqe) -> Result<()> {
        let (opk, side, idx, gen) = op::unpack(cqe.user_data);

        match opk {
            OpKind::Accept => self.on_accept(cqe.res, cqe.flags),
            OpKind::Tick => self.on_tick(cqe.res),
            OpKind::Connect => {
                if side == Side::None {
                    self.on_h2_task_connect(Key { idx, gen }, cqe.res)
                } else {
                    self.on_connect(Key { idx, gen }, cqe.res)
                }
            }
            OpKind::Read => {
                if side == Side::None {
                    self.on_h2_task_read(Key { idx, gen }, cqe.res)
                } else {
                    self.on_read(Key { idx, gen }, side, cqe.res)
                }
            }
            OpKind::Write => {
                if side == Side::None {
                    self.on_h2_task_write(Key { idx, gen }, cqe.res)
                } else {
                    self.on_write(Key { idx, gen }, side, cqe.res)
                }
            }
            OpKind::Close => Ok(()),
            OpKind::MtlsConnect => self.on_up_mtls_task_connect(Key { idx, gen }, cqe.res),
            OpKind::MtlsRead => self.on_up_mtls_task_read(Key { idx, gen }, cqe.res),
            OpKind::MtlsWrite => self.on_up_mtls_task_write(Key { idx, gen }, cqe.res),
        }
    }

    fn on_tick(&mut self, res: i32) -> Result<()> {
        if res < 0 {
            if res == -libc::EINVAL && self.tick_multishot {
                self.tick_multishot = false;
                eprintln!(
                    "worker[{}] timeout multishot not supported, downgrading",
                    self.id
                );
            }
        }

        if !self.tick_multishot {
            self.post_tick()?;
        }

        // idle upstream liveness is maintained passively by epoll events.
        self.drain_idle_epoll()?;
        let now_ns = monotonic_nanos();
        if now_ns >= self.access_log_hot_next_refresh_ns {
            self.access_log_hot_enabled = arc_logging::access_log_hot_path_enabled();
            self.access_log_hot_next_refresh_ns = now_ns.saturating_add(10_000_000);
        }
        self.refresh_upstream_dns(now_ns);
        self.refresh_upstream_pool_metrics(now_ns);

        // graceful shutdown state machine: stop accept, drain active, timeout force-close.
        self.update_graceful_shutdown_state();

        // 1) adopt config if changed (worker-side safe point)
        if self.graceful_shutdown_started_ns.is_none() {
            let g = self.swap.load();
            if g.generation != self.active_gen {
                // adopt: close idle upstream to avoid mismatch; rebuild pools/plugins
                self.apply_new_config(g.clone())?;
            }
        }

        // 2) timeout scan (batch cursor)
        self.sweep_timeouts();
        self.compression_adaptive_tick(monotonic_nanos());

        // Re-check after timeout sweep because closing logic may have drained all active connections.
        self.update_graceful_shutdown_state();

        Ok(())
    }

    fn apply_new_config(&mut self, new_cfg: Arc<SharedConfig>) -> Result<()> {
        let restart_required = restart_required_changes(self.active_cfg.as_ref(), new_cfg.as_ref());
        if self.id == 0 && !restart_required.is_empty() {
            eprintln!(
                "worker[{}] warn: hot reload contains restart-required params (ignored until restart): {}",
                self.id,
                restart_required.join(", ")
            );
        }
        if new_cfg.cluster_circuit.circuit_open_ms
            != self.active_cfg.cluster_circuit.circuit_open_ms
            || new_cfg.cluster_circuit.half_open_probe_interval_ms
                != self.active_cfg.cluster_circuit.half_open_probe_interval_ms
        {
            self.cluster_circuit.apply_hot_settings(
                new_cfg.cluster_circuit.circuit_open_ms.max(1),
                new_cfg.cluster_circuit.half_open_probe_interval_ms.max(1),
            );
        }
        self.cluster_circuit_hot_enabled = cluster_mode_configured(new_cfg.as_ref());

        // close all idle upstream first (also release fixed-file slots)
        self.idle_gc.clear();
        for p in self.upstream_pools.iter_mut() {
            p.drain_all(&mut self.idle_gc);
        }
        let drained: Vec<IdleUpstream> = self.idle_gc.drain(..).collect();
        for item in drained {
            self.drop_idle_upstream(item);
        }
        self.upstream_pools.clear();
        self.upstream_pools.reserve(new_cfg.upstreams.len());
        self.upstream_runtime_addrs.clear();
        self.upstream_runtime_addrs.reserve(new_cfg.upstreams.len());
        self.upstream_dns_next_refresh_ns.clear();
        self.upstream_dns_next_refresh_ns
            .reserve(new_cfg.upstreams.len());
        self.upstream_open_counts.clear();
        self.upstream_open_counts.reserve(new_cfg.upstreams.len());
        let now_ns = monotonic_nanos();
        for up in new_cfg.upstreams.iter() {
            self.upstream_pools
                .push(UpstreamPool::new(up.keepalive, up.idle_ttl_ms));
            self.upstream_runtime_addrs.push(up.addr);
            let refresh_ns = up.dns_refresh_ms.saturating_mul(1_000_000);
            if up.host.is_some() && refresh_ns > 0 {
                self.upstream_dns_next_refresh_ns
                    .push(now_ns.saturating_add(refresh_ns));
            } else {
                self.upstream_dns_next_refresh_ns.push(0);
            }
            self.upstream_open_counts.push(AtomicUsize::new(0));
        }
        self.upstream_leak_warn_growth = new_cfg.limits.upstream_leak_warn_growth as u64;
        self.upstream_leak_warn_window_ns = new_cfg
            .limits
            .upstream_leak_warn_window_ms
            .saturating_mul(1_000_000);
        self.upstream_leak_warn_cooldown_ns = new_cfg
            .limits
            .upstream_leak_warn_cooldown_ms
            .saturating_mul(1_000_000);
        self.upstream_leak_baseline_open = 0;
        self.upstream_leak_baseline_ns = 0;
        self.upstream_leak_last_warn_ns = 0;
        self.upstream_tls = Self::build_upstream_tls_runtime(new_cfg.as_ref())?;
        self.h2_up_inflight = vec![0; new_cfg.upstreams.len()];

        self.plugins = if let Some(catalog) = new_cfg.plugins.catalog.as_ref() {
            Some(catalog.build_worker()?)
        } else {
            None
        };
        self.downstream_tls = DownstreamTls::build(new_cfg.as_ref())?;
        let (mirror_dispatcher, mirror_targets_by_route) =
            Self::build_mirror_runtime(new_cfg.as_ref(), self.metrics.clone())?;
        self.mirror_dispatcher = mirror_dispatcher;
        self.mirror_targets_by_route = mirror_targets_by_route;
        self.rr_route_counters = Self::build_rr_route_counters(new_cfg.routes.len());
        let (compression_global, compression_route_overrides) =
            Self::build_compression_runtime(new_cfg.as_ref());
        self.compression_global = compression_global;
        self.compression_route_overrides = compression_route_overrides;
        if let Some(h) = arc_logging::global() {
            h.update_runtime_from_raw_json(new_cfg.raw_json.as_ref());
        }
        self.auto_block_policy = Self::build_auto_block_policy(new_cfg.raw_json.as_ref());
        self.slowloris_guard = Self::build_slowloris_guard(new_cfg.raw_json.as_ref());
        self.auto_block_counters.clear();
        self.auto_block_last_gc_ns = 0;
        self.refresh_upstream_pool_metrics(monotonic_nanos());

        self.active_gen = new_cfg.generation;
        self.active_cfg = new_cfg;
        Ok(())
    }

    fn build_upstream_tls_runtime(cfg: &SharedConfig) -> Result<Vec<Option<UpstreamTlsRuntime>>> {
        let mut out = Vec::with_capacity(cfg.upstreams.len());
        for up in cfg.upstreams.iter() {
            if let Some(tls) = up.tls.as_ref() {
                let fallback_sni = up.addr.ip().to_string();
                let rt = build_upstream_client_config(tls.as_ref(), &fallback_sni)?;
                out.push(Some(rt));
            } else {
                out.push(None);
            }
        }
        Ok(out)
    }

    fn build_mirror_runtime(
        cfg: &SharedConfig,
        metrics: Arc<WorkerMetrics>,
    ) -> Result<(
        Option<MirrorDispatcher>,
        Arc<[Arc<[Arc<MirrorTargetRuntime>]>]>,
    )> {
        let mut has_any = false;
        let mut max_queue_bytes = 0usize;
        let mut out: Vec<Arc<[Arc<MirrorTargetRuntime>]>> = Vec::with_capacity(cfg.routes.len());

        for route in cfg.routes.iter() {
            if let Some(policy) = route.mirror_policy.as_ref() {
                max_queue_bytes = max_queue_bytes.max(policy.max_queue_bytes);
            }

            if route.mirror_targets.is_empty() {
                out.push(Arc::from([]));
                continue;
            }

            has_any = true;
            let mut targets: Vec<Arc<MirrorTargetRuntime>> =
                Vec::with_capacity(route.mirror_targets.len());
            for t in route.mirror_targets.iter() {
                let Some(up) = cfg.upstreams.get(t.upstream_id) else {
                    return Err(ArcError::config(format!(
                        "mirror target references unknown upstream id {}",
                        t.upstream_id
                    )));
                };

                let mut headers_set = Vec::with_capacity(t.transform_set_headers.len());
                for (k, v) in t.transform_set_headers.iter() {
                    headers_set.push((k.to_string(), v.to_string()));
                }
                let mut headers_remove = Vec::with_capacity(t.transform_remove_headers.len());
                for h in t.transform_remove_headers.iter() {
                    headers_remove.push(h.to_string());
                }

                let ignore_headers_lower: Vec<String> = t
                    .compare_ignore_headers
                    .iter()
                    .map(|h| h.to_ascii_lowercase())
                    .collect();
                let ignore_body_src: Vec<String> = t
                    .compare_ignore_body_fields
                    .iter()
                    .map(|p| p.to_string())
                    .collect();

                let target = MirrorTargetRuntime {
                    upstream: up.name.clone(),
                    addr: up.addr,
                    sample: t.sample,
                    timeout: Duration::from_millis(t.timeout_ms.max(1)),
                    transform: MirrorTransformRuntime {
                        headers_set,
                        headers_remove,
                        path_template: t.transform_path.as_ref().map(|p| p.to_string()),
                    },
                    compare: MirrorCompareRuntime {
                        enabled: t.compare_enabled,
                        ignore_headers_lower,
                        ignore_body_paths: compile_ignore_body_fields(&ignore_body_src),
                    },
                    metrics: Arc::new(MirrorTargetMetrics::new()),
                };
                targets.push(Arc::new(target));
            }
            out.push(targets.into());
        }

        let out: Arc<[Arc<[Arc<MirrorTargetRuntime>]>]> = out.into();
        if !has_any {
            return Ok((None, out));
        }

        let policy = MirrorPolicyRuntime {
            max_queue_bytes: max_queue_bytes.max(64 * 1024),
        };
        let dispatcher = MirrorDispatcher::new(policy, 1, Some(metrics));
        Ok((Some(dispatcher), out))
    }

    fn build_rr_route_counters(route_count: usize) -> Vec<AtomicUsize> {
        let mut out = Vec::with_capacity(route_count);
        for _ in 0..route_count {
            out.push(AtomicUsize::new(0));
        }
        out
    }

    fn refresh_upstream_pool_metrics(&mut self, now_ns: u64) {
        let mut open_current: u64 = 0;
        for count in self.upstream_open_counts.iter() {
            open_current = open_current.saturating_add(count.load(Ordering::Relaxed) as u64);
        }

        let mut idle_current: u64 = 0;
        let mut keepalive_capacity_current: u64 = 0;
        for pool in self.upstream_pools.iter() {
            idle_current = idle_current.saturating_add(pool.idle.len() as u64);
            keepalive_capacity_current =
                keepalive_capacity_current.saturating_add(pool.keepalive as u64);
        }

        let busy_current = open_current.saturating_sub(idle_current);
        self.metrics
            .upstream_pool_open_current
            .store(open_current, Ordering::Relaxed);
        self.metrics
            .upstream_pool_idle_current
            .store(idle_current, Ordering::Relaxed);
        self.metrics
            .upstream_pool_busy_current
            .store(busy_current, Ordering::Relaxed);
        self.metrics
            .upstream_pool_keepalive_capacity_current
            .store(keepalive_capacity_current, Ordering::Relaxed);

        if self.upstream_leak_warn_growth == 0
            || self.upstream_leak_warn_window_ns == 0
            || self.upstream_leak_warn_cooldown_ns == 0
        {
            return;
        }

        if self.upstream_leak_baseline_ns == 0 {
            self.upstream_leak_baseline_ns = now_ns;
            self.upstream_leak_baseline_open = open_current;
            return;
        }

        if open_current < self.upstream_leak_baseline_open {
            self.upstream_leak_baseline_open = open_current;
            self.upstream_leak_baseline_ns = now_ns;
            return;
        }

        if now_ns.saturating_sub(self.upstream_leak_baseline_ns) < self.upstream_leak_warn_window_ns {
            return;
        }

        let growth = open_current.saturating_sub(self.upstream_leak_baseline_open);
        if growth >= self.upstream_leak_warn_growth {
            let cooldown_ok = now_ns.saturating_sub(self.upstream_leak_last_warn_ns)
                >= self.upstream_leak_warn_cooldown_ns;
            if cooldown_ok {
                eprintln!(
                    "worker[{}] WARNING upstream open connections keep growing: baseline={} current={} growth={} busy={} idle={} window_ms={}",
                    self.id,
                    self.upstream_leak_baseline_open,
                    open_current,
                    growth,
                    busy_current,
                    idle_current,
                    self.upstream_leak_warn_window_ns / 1_000_000
                );
                arc_logging::system_log_fields(
                    LogLevel::Warn,
                    "upstream_connection_growth_warning",
                    vec![
                        (LogStr::new("event"), LogValue::from("upstream_connection_growth_warning")),
                        (LogStr::new("worker_id"), LogValue::from(self.id as u64)),
                        (
                            LogStr::new("baseline_open"),
                            LogValue::from(self.upstream_leak_baseline_open),
                        ),
                        (LogStr::new("current_open"), LogValue::from(open_current)),
                        (LogStr::new("growth"), LogValue::from(growth)),
                        (LogStr::new("busy"), LogValue::from(busy_current)),
                        (LogStr::new("idle"), LogValue::from(idle_current)),
                        (
                            LogStr::new("window_ms"),
                            LogValue::from(self.upstream_leak_warn_window_ns / 1_000_000),
                        ),
                    ],
                );
                self.upstream_leak_last_warn_ns = now_ns;
            }
        }

        self.upstream_leak_baseline_open = open_current;
        self.upstream_leak_baseline_ns = now_ns;
    }

    #[inline]
    fn upstream_runtime_addr(&self, upstream_id: usize) -> Option<SocketAddr> {
        self.upstream_runtime_addrs.get(upstream_id).copied()
    }

    fn refresh_upstream_dns(&mut self, now_ns: u64) {
        for upstream_id in 0..self.active_cfg.upstreams.len() {
            let Some(up) = self.active_cfg.upstreams.get(upstream_id) else {
                continue;
            };
            if up.host.is_none() || up.dns_refresh_ms == 0 {
                continue;
            }
            let Some(next_ns) = self.upstream_dns_next_refresh_ns.get_mut(upstream_id) else {
                continue;
            };
            if *next_ns != 0 && now_ns < *next_ns {
                continue;
            }
            let host = up.host.as_ref().map(|v| v.as_ref()).unwrap_or("");
            let port = up.port;
            if !host.is_empty() {
                if let Ok(mut it) = (host, port).to_socket_addrs() {
                    if let Some(new_addr) = it.next() {
                        if let Some(cur) = self.upstream_runtime_addrs.get_mut(upstream_id) {
                            *cur = new_addr;
                        }
                    }
                }
            }
            *next_ns = now_ns.saturating_add(up.dns_refresh_ms.saturating_mul(1_000_000));
        }
    }

    fn upstream_try_acquire_connection_slot(&self, upstream_id: usize) -> bool {
        let Some(limit) = self
            .active_cfg
            .upstreams
            .get(upstream_id)
            .and_then(|up| up.max_connections)
        else {
            // no hard limit: still track open connection count for metrics
            let Some(counter) = self.upstream_open_counts.get(upstream_id) else {
                return false;
            };
            loop {
                let cur = counter.load(Ordering::Relaxed);
                if counter
                    .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
            }
        };
        let Some(counter) = self.upstream_open_counts.get(upstream_id) else {
            return false;
        };
        loop {
            let cur = counter.load(Ordering::Relaxed);
            if cur >= limit {
                return false;
            }
            if counter
                .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn upstream_release_connection_slot(&self, upstream_id: usize) {
        let Some(counter) = self.upstream_open_counts.get(upstream_id) else {
            return;
        };
        let cur = counter.load(Ordering::Relaxed);
        if cur > 0 {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[inline]
    fn map_cfg_compression_algorithm(a: CfgCompressionAlgorithm) -> Algorithm {
        match a {
            CfgCompressionAlgorithm::Zstd => Algorithm::Zstd,
            CfgCompressionAlgorithm::Br => Algorithm::Br,
            CfgCompressionAlgorithm::Gzip => Algorithm::Gzip,
        }
    }

    fn build_compression_runtime(
        cfg: &SharedConfig,
    ) -> (GlobalCompressionConfig, Arc<[RouteCompressionOverrides]>) {
        let c = &cfg.compression;
        let algorithms = c
            .algorithms
            .iter()
            .copied()
            .map(Self::map_cfg_compression_algorithm)
            .collect::<Vec<_>>();
        let mime = MimeMatcher::new(&c.mime_types.include, &c.mime_types.exclude);
        let adaptive = if c.adaptive.enabled {
            Some(Arc::new(AdaptiveController::new(AdaptiveConfig {
                enabled: true,
                cpu_high_threshold: c.adaptive.cpu_high_threshold,
                cpu_low_threshold: c.adaptive.cpu_low_threshold,
                check_interval: c.adaptive.check_interval,
                cooldown: c.adaptive.cooldown,
            })))
        } else {
            None
        };

        let global = GlobalCompressionConfig {
            enabled: c.enabled,
            min_size: c.min_size,
            algorithms,
            zstd_level: c.zstd_level,
            gzip_level: c.gzip_level,
            br_level: c.brotli_level,
            mime,
            adaptive,
        };

        let overrides = cfg
            .routes
            .iter()
            .map(|r| RouteCompressionOverrides {
                enabled: Some(r.compression.enabled),
                algorithm: r
                    .compression
                    .algorithm
                    .map(Self::map_cfg_compression_algorithm),
                level: r.compression.level,
                min_size: Some(r.compression.min_size),
                flush_per_event: r.compression.flush_per_event,
            })
            .collect::<Vec<_>>()
            .into();
        (global, overrides)
    }

    #[inline]
    fn compression_algo_chain(&self, route: &RouteCompressionOverrides) -> ([Algorithm; 3], usize) {
        let mut out = [Algorithm::Identity; 3];
        let mut n = 0usize;
        if let Some(a) = route.algorithm {
            if !matches!(a, Algorithm::Identity) {
                out[0] = a;
                return (out, 1);
            }
            return (out, 0);
        }

        for &a in &self.compression_global.algorithms {
            if matches!(a, Algorithm::Identity) {
                continue;
            }
            if out[..n].contains(&a) {
                continue;
            }
            if n < out.len() {
                out[n] = a;
                n += 1;
            }
            if n == out.len() {
                break;
            }
        }
        (out, n)
    }

    fn idle_watch_add(&self, fd: RawFd, tag: u64) -> io::Result<()> {
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32,
            u64: tag,
        };
        let rc = unsafe { libc::epoll_ctl(self.idle_epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn idle_watch_del_best_effort(&self, fd: RawFd) {
        let rc = unsafe {
            libc::epoll_ctl(
                self.idle_epfd,
                libc::EPOLL_CTL_DEL,
                fd,
                std::ptr::null_mut::<libc::epoll_event>(),
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(code)
                    if code == libc::ENOENT || code == libc::EBADF || code == libc::EINVAL => {}
                _ => {}
            }
        }
    }

    fn take_idle_by_tag(&mut self, tag: u64) -> Option<IdleUpstream> {
        for p in self.upstream_pools.iter_mut() {
            if let Some(item) = p.take_by_tag(tag) {
                return Some(item);
            }
        }
        None
    }

    fn drop_idle_upstream(&mut self, item: IdleUpstream) {
        self.idle_watch_del_best_effort(item.fd);
        close_fd(item.fd);
        self.upstream_release_connection_slot(item.upstream_id);
        if item.fi >= 0 {
            let slot = item.fi as u32;
            let _ = self.uring.update_files(slot, &[-1]);
            self.files.free_slot(slot);
        }
    }

    fn drain_idle_epoll(&mut self) -> Result<()> {
        loop {
            let n = unsafe {
                libc::epoll_wait(
                    self.idle_epfd,
                    self.idle_ep_events.as_mut_ptr(),
                    self.idle_ep_events.len() as i32,
                    0,
                )
            };
            if n == 0 {
                return Ok(());
            }
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ArcError::io("epoll_wait(idle upstream)", e));
            }

            for i in 0..(n as usize) {
                let tag = self.idle_ep_events[i].u64;
                if let Some(item) = self.take_idle_by_tag(tag) {
                    self.drop_idle_upstream(item);
                }
            }
        }
    }

    fn checkout_idle_upstream(&mut self, up_id: usize, now_ns: u64) -> Option<IdleUpstream> {
        let Some(pool) = self.upstream_pools.get(up_id) else {
            return None;
        };
        if pool.idle.is_empty() {
            return None;
        }
        // Drain pending idle epoll events before checkout to reduce stale-conn reuse window.
        let _ = self.drain_idle_epoll();

        let ttl_ns = self.upstream_pools.get(up_id)?.idle_ttl_ns;
        loop {
            let item = self.upstream_pools.get_mut(up_id)?.checkout()?;
            if now_ns.saturating_sub(item.ts_ns) > ttl_ns {
                self.drop_idle_upstream(item);
                continue;
            }
            self.idle_watch_del_best_effort(item.fd);
            return Some(item);
        }
    }

    fn checkin_idle_upstream(&mut self, up_id: usize, mut item: IdleUpstream) {
        if up_id >= self.upstream_pools.len() {
            self.drop_idle_upstream(item);
            return;
        }

        let fd = item.fd;
        let tag = self.idle_watch_seq;
        self.idle_watch_seq = self.idle_watch_seq.wrapping_add(1).max(1);
        item.watch_tag = tag;
        if let Some(reject) = self.upstream_pools[up_id].checkin(item) {
            self.drop_idle_upstream(reject);
            return;
        }

        if self.idle_watch_add(fd, tag).is_err() {
            if let Some(taken) = self.upstream_pools[up_id].take_by_tag(tag) {
                self.drop_idle_upstream(taken);
            }
        }
    }

    fn sweep_timeouts(&mut self) {
        let now = monotonic_nanos();
        let mut expired = Vec::new();
        self.timeout_wheel.expire(now, |k| expired.push(k));
        for key in expired {
            let (retry_wakeup, phase_idx, conn_state, tier_expired) = {
                let Some(conn) = self.conns.get_mut(key) else {
                    continue;
                };
                if conn.deadline_ns == 0 || conn.deadline_ns > now {
                    continue;
                }
                let tier_expired = conn
                    .timeout_state
                    .as_ref()
                    .map(|state| state.total_expired(now) || state.try_expired(now))
                    .unwrap_or(false);
                let mut retry_wakeup = false;
                let mut phase_idx = None;
                if matches!(conn.state, ConnState::RetryBackoff) {
                    retry_wakeup = now >= conn.retry_wakeup_ns;
                } else {
                    phase_idx = Some(conn.phase.idx());
                }
                (retry_wakeup, phase_idx, conn.state, tier_expired)
            };
            if retry_wakeup {
                if tier_expired {
                    let _ = self.queue_error_response(key, RESP_504);
                } else {
                    let _ = self.start_connect_upstream_new_socket(key);
                }
                continue;
            }
            if let Some(idx) = phase_idx {
                self.metrics.phase_timeouts[idx].fetch_add(1, Ordering::Relaxed);
                if tier_expired || Self::should_respond_504_on_timeout(conn_state) {
                    let _ = self.queue_error_response(key, RESP_504);
                } else {
                    self.close_conn(key);
                }
            }
        }

        let mut h2_expired = Vec::new();
        self.h2_timeout_wheel.expire(now, |k| h2_expired.push(k));
        for key in h2_expired {
            let timed_out = match self.h2_tasks.get_mut(key) {
                Some(task) => task.deadline_ns != 0 && task.deadline_ns <= now,
                None => false,
            };
            if !timed_out {
                continue;
            }
            let _ = self.h2_fail_task(key, 504);
        }

        let mut mtls_expired = Vec::new();
        self.mtls_timeout_wheel
            .expire(now, |k| mtls_expired.push(k));
        for key in mtls_expired {
            let timed_out = match self.up_mtls_tasks.get_mut(key) {
                Some(task) => task.deadline_ns != 0 && task.deadline_ns <= now,
                None => false,
            };
            if !timed_out {
                continue;
            }
            let _ = self.up_mtls_fail_task(key, true);
        }

        self.h2_drop_stale_pending(now);
    }

    fn on_accept(&mut self, res: i32, flags: u32) -> Result<()> {
        // multishot accept: if not MORE, need re-arm
        if (flags & sys::IORING_CQE_F_MORE) == 0 && self.accepting {
            // accept stopped -> rearm
            self.post_accept()?;
        }

        if !self.accepting {
            if res >= 0 {
                self.metrics
                    .accept_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                close_fd(res as RawFd);
            }
            return Ok(());
        }

        if res < 0 {
            // accept transient error
            // if kernel doesn't support multishot accept, EINVAL can happen
            if res == -libc::EINVAL && self.accept_multishot {
                self.accept_multishot = false;
                eprintln!(
                    "worker[{}] accept_multishot not supported, downgrading",
                    self.id
                );
                self.post_accept()?;
            }
            return Ok(());
        }

        let client_fd = res as RawFd;

        // tune client
        let _ = net::set_tcp_nodelay(client_fd);
        let _ = net::set_keepalive(client_fd);
        if self.active_cfg.linger_ms > 0 {
            let _ = net::set_linger(client_fd, self.active_cfg.linger_ms);
        }

        // allocate buffer
        let buf = match self.bufs.alloc() {
            Some(b) => b,
            None => {
                self.metrics
                    .accept_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                close_fd(client_fd);
                return Ok(());
            }
        };
        let (tls_buf, tls_wbuf) = if self.downstream_tls.is_some() {
            let rb = match self.bufs.alloc() {
                Some(b) => b,
                None => {
                    self.bufs.free(buf);
                    self.metrics
                        .accept_rejected_total
                        .fetch_add(1, Ordering::Relaxed);
                    close_fd(client_fd);
                    return Ok(());
                }
            };
            let wb = match self.bufs.alloc() {
                Some(b) => b,
                None => {
                    self.bufs.free(rb);
                    self.bufs.free(buf);
                    self.metrics
                        .accept_rejected_total
                        .fetch_add(1, Ordering::Relaxed);
                    close_fd(client_fd);
                    return Ok(());
                }
            };
            (rb, wb)
        } else {
            (INVALID_BUF, INVALID_BUF)
        };

        // allocate fixed file slot for client
        let cslot = match self.files.alloc() {
            Some(s) => s,
            None => {
                self.bufs.free(buf);
                if tls_buf != INVALID_BUF {
                    self.bufs.free(tls_buf);
                }
                if tls_wbuf != INVALID_BUF {
                    self.bufs.free(tls_wbuf);
                }
                self.metrics
                    .accept_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                close_fd(client_fd);
                return Ok(());
            }
        };

        self.files.table[cslot as usize] = client_fd;
        self.uring
            .update_files(cslot, &[client_fd])
            .map_err(|e| ArcError::io("update_files(client)", e))?;

        // allocate conn slot
        let key = match self.conns.alloc() {
            Some(k) => k,
            None => {
                self.uring
                    .update_files(cslot, &[-1])
                    .map_err(|e| ArcError::io("clear_files(client)", e))?;
                self.files.free_slot(cslot);
                self.bufs.free(buf);
                if tls_buf != INVALID_BUF {
                    self.bufs.free(tls_buf);
                }
                if tls_wbuf != INVALID_BUF {
                    self.bufs.free(tls_wbuf);
                }
                self.metrics
                    .accept_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                close_fd(client_fd);
                return Ok(());
            }
        };

        let now = monotonic_nanos();
        let mut conn = Conn::new(client_fd, cslot as i32, buf, now);
        let (peer_ip, peer_port) = socket_peer_addr(client_fd);
        conn.client_ip = peer_ip;
        conn.client_port = peer_port;
        conn.tls_buf = tls_buf;
        conn.tls_wbuf = tls_wbuf;
        conn.phase = Phase::CliRead;
        conn.phase_started_ns = now;
        conn.deadline_ns = now.saturating_add(
            self.active_cfg
                .timeouts_ms
                .cli_read
                .saturating_mul(1_000_000),
        );
        conn.in_flight = 0;

        if let Some(guard) = self.slowloris_guard.as_ref() {
            let decision = Self::slowloris_start_tracking(guard, &mut conn, now);
            if !matches!(decision, SlowlorisDecision::Allow) {
                self.uring
                    .update_files(cslot, &[-1])
                    .map_err(|e| ArcError::io("clear_files(client)", e))?;
                self.files.free_slot(cslot);
                self.bufs.free(buf);
                if tls_buf != INVALID_BUF {
                    self.bufs.free(tls_buf);
                }
                if tls_wbuf != INVALID_BUF {
                    self.bufs.free(tls_wbuf);
                }
                self.metrics
                    .accept_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                close_fd(client_fd);
                self.conns.cancel_alloc(key);
                eprintln!(
                    "worker[{}] slowloris reject on accept: ip={} reason={decision:?}",
                    self.id, conn.client_ip
                );
                return Ok(());
            }
        }

        if let Some(dtls) = self.downstream_tls.as_ref() {
            match ServerConnection::new(dtls.server_cfg.clone()) {
                Ok(sc) => {
                    conn.tls = Some(sc);
                }
                Err(_) => {
                    self.uring
                        .update_files(cslot, &[-1])
                        .map_err(|e| ArcError::io("clear_files(client)", e))?;
                    self.files.free_slot(cslot);
                    self.bufs.free(buf);
                    if tls_buf != INVALID_BUF {
                        self.bufs.free(tls_buf);
                    }
                    if tls_wbuf != INVALID_BUF {
                        self.bufs.free(tls_wbuf);
                    }
                    self.metrics
                        .accept_rejected_total
                        .fetch_add(1, Ordering::Relaxed);
                    close_fd(client_fd);
                    self.conns.cancel_alloc(key);
                    return Ok(());
                }
            }
        }
        let use_tls = conn.tls.is_some();

        unsafe {
            self.conns.write(key, conn);
        }

        self.metrics.accepted_total.fetch_add(1, Ordering::Relaxed);
        self.metrics.active_current.fetch_add(1, Ordering::Relaxed);

        // schedule initial read
        if use_tls {
            self.schedule_read_client_tls(key)?;
        } else {
            self.schedule_read_client(key, 0)?;
        }

        Ok(())
    }

    #[inline]
    fn schedule_read_client(&mut self, key: Key, off: u32) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if conn.buf == INVALID_BUF {
            return Ok(());
        }

        let cap = self.bufs.buf_size() as u32;
        if off >= cap {
            self.close_conn(key);
            return Ok(());
        }

        let p = self.bufs.ptr_at(conn.buf, off);
        let len = cap - off;

        conn.in_flight = conn.in_flight.saturating_add(1);
        conn.phase = Phase::CliRead;
        let now = monotonic_nanos();
        let fallback_deadline_ns = now.saturating_add(
            self.active_cfg
                .timeouts_ms
                .cli_read
                .saturating_mul(1_000_000),
        );
        conn.deadline_ns =
            Self::slowloris_deadline_ns(self.slowloris_guard.as_ref(), conn, fallback_deadline_ns);
        self.timeout_wheel.push(conn.deadline_ns, key);

        let sq = sqe::read_fixed(
            conn.client_fi,
            true,
            p,
            len,
            conn.buf,
            op::pack(OpKind::Read, Side::Client, key.idx, key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push read(client)", e))?;
        Ok(())
    }

    #[inline]
    fn has_down_tls(&mut self, key: Key) -> bool {
        self.conns
            .get_mut(key)
            .map(|c| c.tls.is_some())
            .unwrap_or(false)
    }

    #[inline]
    fn schedule_read_client_tls(&mut self, key: Key) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if conn.tls_buf == INVALID_BUF {
            self.close_conn(key);
            return Ok(());
        }
        if conn.tls_read_in_flight {
            return Ok(());
        }

        let cap = self.bufs.buf_size() as u32;
        let p = self.bufs.ptr(conn.tls_buf);

        conn.tls_read_in_flight = true;
        conn.in_flight = conn.in_flight.saturating_add(1);
        conn.phase = Phase::CliRead;
        let now = monotonic_nanos();
        let handshaking = conn
            .tls
            .as_ref()
            .map(|t| t.is_handshaking())
            .unwrap_or(false);
        let timeout_ms = if handshaking {
            self.active_cfg.timeouts_ms.cli_handshake
        } else {
            self.active_cfg.timeouts_ms.cli_read
        };
        let fallback_deadline_ns = now.saturating_add(timeout_ms.saturating_mul(1_000_000));
        conn.deadline_ns = if handshaking {
            fallback_deadline_ns
        } else {
            Self::slowloris_deadline_ns(self.slowloris_guard.as_ref(), conn, fallback_deadline_ns)
        };
        self.timeout_wheel.push(conn.deadline_ns, key);

        let sq = sqe::read_fixed(
            conn.client_fi,
            true,
            p,
            cap,
            conn.tls_buf,
            op::pack(OpKind::Read, Side::Client, key.idx, key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push read(client tls)", e))?;
        Ok(())
    }

    #[inline]
    fn schedule_client_read(&mut self, key: Key, off: u32) -> Result<()> {
        let use_tls = self
            .conns
            .get_mut(key)
            .map(|c| c.tls.is_some())
            .unwrap_or(false);
        if use_tls {
            self.schedule_read_client_tls(key)
        } else {
            self.schedule_read_client(key, off)
        }
    }

    #[inline]
    fn ensure_h2_downstream(&mut self, key: Key) {
        let Some(conn) = self.conns.get_mut(key) else {
            return;
        };
        if !conn.alpn_h2 || conn.h2_down.is_some() {
            return;
        }
        let seed = ((self.id as u64) << 32) ^ ((key.idx as u64) << 1) ^ (key.gen as u64);
        let max_concurrent = self.active_cfg.http2.max_concurrent_streams.max(1) as usize;
        conn.h2_down = Some(DownstreamH2::new(
            H2ConnKey::new(key.idx, key.gen),
            max_concurrent,
            seed,
        ));
    }

    fn tls_drain_plain_downstream_h2(&mut self, key: Key) -> Result<Vec<H2RxChunk>> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(Vec::new());
        };
        let Some(tls) = conn.tls.as_mut() else {
            return Ok(Vec::new());
        };
        let cap = self.bufs.buf_size();
        let mut out: Vec<H2RxChunk> = Vec::new();

        loop {
            let Some(buf_id) = self.bufs.alloc() else {
                break;
            };
            let p = self.bufs.ptr(buf_id);
            let dst = unsafe { std::slice::from_raw_parts_mut(p as *mut u8, cap) };

            match tls.reader().read(dst) {
                Ok(0) => {
                    self.bufs.free(buf_id);
                    break;
                }
                Ok(n) => {
                    out.push(H2RxChunk {
                        buf_id,
                        off: 0,
                        len: n as u32,
                    });
                    if n < cap {
                        break;
                    }
                    if out.len() >= 64 {
                        break;
                    }
                }
                Err(e) => {
                    self.bufs.free(buf_id);
                    if e.kind() == io::ErrorKind::WouldBlock {
                        break;
                    }
                    break;
                }
            }
        }

        Ok(out)
    }

    fn pump_h2_downstream(&mut self, key: Key, now_ns: u64, chunks: &[H2RxChunk]) -> Result<()> {
        self.ensure_h2_downstream(key);

        let mut down = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            let Some(mut down) = conn.h2_down.take() else {
                return Ok(());
            };
            for c in chunks {
                down.push_rx(*c);
            }
            down
        };

        let mut collector = H2RequestCollector::default();
        {
            let mut ops = WorkerH2BufOps {
                bufs: &mut self.bufs,
            };
            down.pump(now_ns, &mut ops, &mut collector);
            collector.release_dropped(&mut ops);
        }
        self.h2_process_ready_requests(key, now_ns, &mut down, &mut collector)?;

        if let Some(conn) = self.conns.get_mut(key) {
            conn.h2_down = Some(down);
        } else {
            let mut ops = WorkerH2BufOps {
                bufs: &mut self.bufs,
            };
            down.release_all(&mut ops);
        }

        Ok(())
    }

    fn flush_h2_downstream_tx(&mut self, key: Key) -> Result<()> {
        let mut down = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            let Some(down) = conn.h2_down.take() else {
                return Ok(());
            };
            down
        };

        // Keep each rustls writer drain chunk bounded.
        // Large bursts here can overflow rustls internal write buffer and raise
        // "failed to write whole buffer" under high H2 concurrency.
        let max_plain = self.bufs.buf_size().max(1024).min(16 * 1024);
        let mut credits: Vec<H2Credit> = Vec::new();

        if let Some(conn) = self.conns.get_mut(key) {
            if let Some(tls) = conn.tls.as_mut() {
                let mut ops = WorkerH2BufOps {
                    bufs: &mut self.bufs,
                };
                let mut writer = tls.writer();
                h2_drain_tx_to_writer(
                    down.tx_mut(),
                    &mut ops,
                    &mut writer,
                    |c| credits.push(c),
                    max_plain,
                )
                .map_err(|e| ArcError::io("h2 drain tx(downstream)", e))?;
            }
        }

        for c in credits {
            self.apply_h2_credit(c);
        }

        if let Some(conn) = self.conns.get_mut(key) {
            conn.h2_down = Some(down);
        } else {
            let mut ops = WorkerH2BufOps {
                bufs: &mut self.bufs,
            };
            down.release_all(&mut ops);
        }
        Ok(())
    }

    fn apply_h2_credit(&mut self, credit: H2Credit) {
        match credit {
            H2Credit::ToDownstream { conn, sid, bytes } => {
                let key = Key {
                    idx: conn.idx,
                    gen: conn.gen,
                };
                if let Some(c) = self.conns.get_mut(key) {
                    if let Some(d) = c.h2_down.as_mut() {
                        d.credit_recv_window(sid, bytes);
                    }
                }
            }
            #[cfg(feature = "h2-native-upstream")]
            H2Credit::ToUpstream { .. } => {}
        }
    }

    fn h2_release_body_parts(&mut self, mut body_parts: Vec<H2BufChain>) {
        let mut ops = WorkerH2BufOps {
            bufs: &mut self.bufs,
        };
        for mut part in body_parts.drain(..) {
            part.release(&mut ops);
        }
    }

    fn h2_collect_body_bytes(
        &mut self,
        body_parts: Vec<H2BufChain>,
        max_bytes: usize,
    ) -> std::result::Result<Vec<u8>, H2H1RoundtripError> {
        let mut ops = WorkerH2BufOps {
            bufs: &mut self.bufs,
        };
        let mut out = Vec::new();
        for mut part in body_parts {
            let segs: Vec<_> = part.iter().copied().collect();
            for seg in segs {
                let s = ops.slice(seg.buf_id, seg.off, seg.len);
                if out.len().saturating_add(s.len()) > max_bytes {
                    part.release(&mut ops);
                    return Err(H2H1RoundtripError::Proto);
                }
                out.extend_from_slice(s);
            }
            part.release(&mut ops);
        }
        Ok(out)
    }

    fn h2_build_h1_request_with_policies(
        head: &H2RequestHead,
        body: &[u8],
        upstream_addr: SocketAddr,
        forward: &arc_config::forward_policies::ForwardPolicy,
        traceparent: &str,
        forwarded_identity: Option<&ForwardedIdentity>,
        request_id_header: &str,
        request_id: &str,
        request_id_force_set: bool,
        original_request_id: Option<&str>,
    ) -> Vec<u8> {
        let method = if head.method.is_empty() {
            b"GET".as_slice()
        } else {
            head.method.as_ref()
        };
        let orig_path = head.path.as_ref().map(|v| v.as_ref()).unwrap_or(b"/");

        let path: std::borrow::Cow<'_, [u8]> = match &forward.rewrite {
            None => std::borrow::Cow::Borrowed(orig_path),
            Some(CompiledRewrite::Prefix { from, to }) => {
                if orig_path.starts_with(from.as_ref()) {
                    let mut v =
                        Vec::with_capacity(to.len() + orig_path.len().saturating_sub(from.len()));
                    v.extend_from_slice(to.as_ref());
                    v.extend_from_slice(&orig_path[from.len()..]);
                    std::borrow::Cow::Owned(v)
                } else {
                    std::borrow::Cow::Borrowed(orig_path)
                }
            }
            Some(CompiledRewrite::Regex { re, replace }) => {
                if re.is_match(orig_path) {
                    let replaced = re.replace_all(orig_path, replace.as_ref());
                    std::borrow::Cow::Owned(replaced.into_owned())
                } else {
                    std::borrow::Cow::Borrowed(orig_path)
                }
            }
        };

        let muts = forward.header_muts.as_ref();
        let has_set_host = muts.iter().any(|m| match m {
            CompiledHeaderMutation::Set { name_lower, .. } => {
                name_lower.as_ref().eq_ignore_ascii_case(b"host")
            }
            _ => false,
        });

        let mut host = head.authority.as_ref().map(|v| v.as_ref().to_vec());
        if host.is_none() {
            for h in head.headers.iter() {
                if h.name.eq_ignore_ascii_case(b"host") {
                    host = Some(h.value.as_ref().to_vec());
                    break;
                }
            }
        }
        if host.is_none() {
            host = Some(upstream_addr.to_string().into_bytes());
        }
        let mut has_request_id_header = false;
        let mut out = Vec::with_capacity(1024 + body.len());
        out.extend_from_slice(method);
        out.push(b' ');
        out.extend_from_slice(path.as_ref());
        out.extend_from_slice(b" HTTP/1.1\r\n");

        if !has_set_host {
            out.extend_from_slice(b"host: ");
            out.extend_from_slice(host.as_ref().map(|v| v.as_slice()).unwrap_or(b"localhost"));
            out.extend_from_slice(b"\r\n");
        }

        for h in &head.headers {
            let name = h.name.as_ref();
            if name.is_empty()
                || name[0] == b':'
                || name.eq_ignore_ascii_case(b"host")
                || name.eq_ignore_ascii_case(b"content-length")
                || name.eq_ignore_ascii_case(b"connection")
                || name.eq_ignore_ascii_case(b"keep-alive")
                || name.eq_ignore_ascii_case(b"proxy-connection")
                || name.eq_ignore_ascii_case(b"upgrade")
                || name.eq_ignore_ascii_case(b"transfer-encoding")
                || name.eq_ignore_ascii_case(b"te")
                || name.eq_ignore_ascii_case(b"traceparent")
            {
                continue;
            }

            if muts.iter().any(|m| match m {
                CompiledHeaderMutation::Remove { name_lower } => {
                    name.eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Set { name_lower, .. } => {
                    name.eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Add { .. } => false,
            }) {
                continue;
            }

            if name.eq_ignore_ascii_case(request_id_header.as_bytes()) {
                has_request_id_header = true;
                if request_id_force_set {
                    continue;
                }
            }
            if original_request_id.is_some() && name.eq_ignore_ascii_case(b"x-original-request-id")
            {
                continue;
            }

            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.as_ref());
            out.extend_from_slice(b"\r\n");
        }

        for m in muts {
            if let CompiledHeaderMutation::Set { name, value, .. } = m {
                if name
                    .as_ref()
                    .eq_ignore_ascii_case(request_id_header.as_bytes())
                {
                    has_request_id_header = true;
                    if request_id_force_set {
                        continue;
                    }
                }
                out.extend_from_slice(name.as_ref());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_ref());
                out.extend_from_slice(b"\r\n");
            }
        }
        for m in muts {
            if let CompiledHeaderMutation::Add { name, value, .. } = m {
                if name
                    .as_ref()
                    .eq_ignore_ascii_case(request_id_header.as_bytes())
                {
                    has_request_id_header = true;
                    if request_id_force_set {
                        continue;
                    }
                }
                out.extend_from_slice(name.as_ref());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_ref());
                out.extend_from_slice(b"\r\n");
            }
        }
        out.extend_from_slice(b"traceparent: ");
        out.extend_from_slice(traceparent.as_bytes());
        out.extend_from_slice(b"\r\n");
        if (request_id_force_set || !has_request_id_header) && !request_id.is_empty() {
            out.extend_from_slice(request_id_header.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(request_id.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if let Some(original) = original_request_id {
            out.extend_from_slice(b"x-original-request-id: ");
            out.extend_from_slice(original.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if let Some(identity) = forwarded_identity {
            out.extend_from_slice(b"x-forwarded-for: ");
            out.extend_from_slice(identity.x_forwarded_for.as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(identity.real_ip_header.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(identity.effective_client_ip.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"content-length: ");
        out.extend_from_slice(body.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(b"connection: keep-alive\r\n\r\n");
        out.extend_from_slice(body);
        out
    }

    fn h2_is_hop_header(name: &[u8]) -> bool {
        name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"keep-alive")
            || name.eq_ignore_ascii_case(b"proxy-connection")
            || name.eq_ignore_ascii_case(b"upgrade")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
    }

    fn h2_parse_h1_response_headers(block: &[u8]) -> Vec<H2Header> {
        let mut out = Vec::new();
        let mut first = true;
        for line in block.split(|b| *b == b'\n') {
            let l = line.strip_suffix(b"\r").unwrap_or(line);
            if l.is_empty() {
                break;
            }
            if first {
                first = false;
                continue;
            }
            let Some(pos) = l.iter().position(|b| *b == b':') else {
                continue;
            };
            let mut name = l[..pos].to_vec();
            for b in name.iter_mut() {
                *b = b.to_ascii_lowercase();
            }
            if Self::h2_is_hop_header(&name) || name.eq_ignore_ascii_case(b"content-length") {
                continue;
            }
            let mut value = l[pos + 1..].to_vec();
            while value
                .first()
                .map(|b| b.is_ascii_whitespace())
                .unwrap_or(false)
            {
                value.remove(0);
            }
            out.push(H2Header {
                name: Bytes::from(name),
                value: Bytes::from(value),
            });
        }
        out
    }

    fn apply_h2_response_header_muts(headers: &mut Vec<H2Header>, muts: &[CompiledHeaderMutation]) {
        if muts.is_empty() {
            return;
        }

        headers.retain(|h| {
            !muts.iter().any(|m| match m {
                CompiledHeaderMutation::Remove { name_lower } => {
                    h.name.as_ref().eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Set { name_lower, .. } => {
                    h.name.as_ref().eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Add { .. } => false,
            })
        });

        for m in muts.iter() {
            if let CompiledHeaderMutation::Set {
                name_lower, value, ..
            } = m
            {
                headers.push(H2Header {
                    name: name_lower.clone(),
                    value: value.clone(),
                });
            }
        }
        for m in muts.iter() {
            if let CompiledHeaderMutation::Add {
                name_lower, value, ..
            } = m
            {
                headers.push(H2Header {
                    name: name_lower.clone(),
                    value: value.clone(),
                });
            }
        }
    }

    fn h2_decode_chunked(body: &[u8]) -> std::result::Result<Option<Vec<u8>>, H2H1RoundtripError> {
        let mut out = Vec::new();
        let mut i = 0usize;

        while i < body.len() {
            let mut j = i;
            while j < body.len() && body[j] != b'\n' {
                j += 1;
            }
            if j >= body.len() {
                return Ok(None);
            }
            let line = if j > i && body[j - 1] == b'\r' {
                &body[i..j - 1]
            } else {
                &body[i..j]
            };
            let size_token = match line.iter().position(|b| *b == b';') {
                Some(p) => &line[..p],
                None => line,
            };
            let size_str =
                std::str::from_utf8(size_token).map_err(|_| H2H1RoundtripError::Proto)?;
            let size = usize::from_str_radix(size_str.trim(), 16)
                .map_err(|_| H2H1RoundtripError::Proto)?;
            i = j + 1;

            if size == 0 {
                // consume trailers until empty line
                loop {
                    if i >= body.len() {
                        return Ok(None);
                    }
                    let mut t = i;
                    while t < body.len() && body[t] != b'\n' {
                        t += 1;
                    }
                    if t >= body.len() {
                        return Ok(None);
                    }
                    let trailer = if t > i && body[t - 1] == b'\r' {
                        &body[i..t - 1]
                    } else {
                        &body[i..t]
                    };
                    i = t + 1;
                    if trailer.is_empty() {
                        return Ok(Some(out));
                    }
                }
            }

            if i.saturating_add(size).saturating_add(1) >= body.len() {
                return Ok(None);
            }
            out.extend_from_slice(&body[i..i + size]);
            i += size;
            if body.get(i) == Some(&b'\r') {
                i += 1;
            }
            if body.get(i) != Some(&b'\n') {
                return Err(H2H1RoundtripError::Proto);
            }
            i += 1;
        }

        Ok(None)
    }

    fn try_start_http1_stream_compression_in_place(
        &mut self,
        key: Key,
        status: u16,
        header_end: usize,
        send_len: usize,
    ) -> Result<Option<usize>> {
        let (buf_id, route_id, is_head, response_done_now, accept_encoding, upstream_fd) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(None);
            };
            let ae_len = (conn.req_accept_encoding_len as usize).min(REQ_ACCEPT_ENCODING_CAP);
            let mut ae = Vec::new();
            if ae_len > 0 {
                ae.extend_from_slice(&conn.req_accept_encoding[..ae_len]);
            }
            (
                conn.buf,
                conn.route_id as usize,
                conn.log_method.eq_ignore_ascii_case("HEAD"),
                matches!(conn.resp_body, HttpBodyState::None),
                ae,
                conn.upstream_fd,
            )
        };

        if buf_id == INVALID_BUF || header_end > send_len {
            return Ok(None);
        }

        let cap = self.bufs.buf_size();
        if send_len > cap {
            return Ok(None);
        }

        let raw =
            unsafe { std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, send_len) };
        let head_block = &raw[..header_end];
        let body_wire = &raw[header_end..];

        let transfer_chunked = http1_header_has_token(head_block, b"transfer-encoding", b"chunked");
        if transfer_chunked {
            return Ok(None);
        }
        let body_plain: &[u8] = body_wire;

        let content_type = http1_header_value(head_block, b"content-type");
        let content_encoding = http1_header_value(head_block, b"content-encoding");
        let Some(content_length) =
            http1_header_value(head_block, b"content-length").and_then(parse_u64_header_value)
        else {
            return Ok(None);
        };

        let req_info = CompressionRequestInfo {
            accept_encoding: if accept_encoding.is_empty() {
                None
            } else {
                Some(accept_encoding.as_slice())
            },
            is_head,
        };
        let resp_info = CompressionResponseInfo {
            status,
            content_length: Some(content_length),
            content_type,
            content_encoding,
        };
        let route_overrides = self
            .compression_route_overrides
            .get(route_id)
            .cloned()
            .unwrap_or_default();
        let mut peek_prefix = [0u8; 8];
        let body_prefix: Option<&[u8]> = if body_plain.is_empty() {
            let n = peek_upstream_body_prefix(upstream_fd, &mut peek_prefix);
            if n > 0 {
                Some(&peek_prefix[..n])
            } else {
                None
            }
        } else {
            Some(&body_plain[..body_plain.len().min(8)])
        };
        if body_prefix.is_none() {
            if Self::compression_debug_enabled() {
                eprintln!(
                    "compress debug: skip status={} reason=no_body_prefix_for_magic ae='{}' cl={}",
                    status,
                    String::from_utf8_lossy(accept_encoding.as_slice()),
                    content_length
                );
            }
            return Ok(None);
        }
        let decision = decide_response_compression(
            &self.compression_global,
            &route_overrides,
            req_info,
            resp_info,
            body_prefix,
        );
        if Self::compression_debug_enabled() {
            eprintln!(
                "compress debug: status={} ae='{}' ct='{}' cl={:?} chunked={} body_len={} decision={:?}",
                status,
                String::from_utf8_lossy(accept_encoding.as_slice()),
                content_type
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .unwrap_or_default(),
                Some(content_length),
                transfer_chunked,
                body_plain.len(),
                decision.skipped
            );
        }
        if decision.plan.is_none() {
            return Ok(None);
        }

        let (candidates, candidates_len) = self.compression_algo_chain(&route_overrides);
        let flush_mode = if response_done_now {
            FlushMode::Finish
        } else {
            FlushMode::None
        };

        for alg in candidates.iter().copied().take(candidates_len) {
            let mut route_try = route_overrides.clone();
            route_try.algorithm = Some(alg);
            let attempt = decide_response_compression(
                &self.compression_global,
                &route_try,
                req_info,
                resp_info,
                body_prefix,
            );
            let Some(plan) = attempt.plan else {
                continue;
            };

            let mut compressor = match self.compression_pools.acquire(plan.algorithm, plan.level) {
                Ok(v) => v,
                Err(_) => {
                    if Self::compression_debug_enabled() {
                        eprintln!(
                            "compress debug: fallback acquire failed alg={} level={}",
                            plan.algorithm.as_str(),
                            plan.level
                        );
                    }
                    continue;
                }
            };

            let mut compressed_body =
                Vec::with_capacity(body_plain.len().saturating_div(2).saturating_add(256));
            if compressor
                .compress(body_plain, flush_mode, &mut compressed_body)
                .is_err()
            {
                if Self::compression_debug_enabled() {
                    eprintln!(
                        "compress debug: fallback compress failed alg={} level={}",
                        plan.algorithm.as_str(),
                        plan.level
                    );
                }
                continue;
            }

            let mut rewritten = build_http1_compressed_response_head(
                head_block,
                plan.algorithm.as_str().as_bytes(),
            );
            encode_chunked(compressed_body.as_slice(), &mut rewritten);
            if response_done_now {
                encode_chunked_end(&mut rewritten);
            }
            if rewritten.len() > cap {
                if Self::compression_debug_enabled() {
                    eprintln!(
                        "compress debug: fallback buffer overflow alg={} out={}",
                        plan.algorithm.as_str(),
                        rewritten.len()
                    );
                }
                continue;
            }
            if Self::compression_debug_enabled() {
                eprintln!(
                    "compress debug: applied alg={} level={} in={} out={}",
                    plan.algorithm.as_str(),
                    plan.level,
                    body_plain.len(),
                    rewritten.len()
                );
            }

            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(None);
            };
            if conn.buf == INVALID_BUF {
                return Ok(None);
            }
            let p = self.bufs.ptr(conn.buf);
            unsafe {
                std::ptr::copy_nonoverlapping(rewritten.as_ptr(), p, rewritten.len());
            }
            conn.buf_off = 0;
            conn.buf_len = rewritten.len() as u32;
            conn.resp_compressed = true;
            conn.resp_compress_alg = plan.algorithm;
            conn.resp_compress_level = plan.level;
            if response_done_now {
                conn.resp_compressor = None;
                conn.resp_body = HttpBodyState::None;
            } else {
                conn.resp_compressor = Some(compressor);
            }
            return Ok(Some(rewritten.len()));
        }

        if Self::compression_debug_enabled() {
            eprintln!(
                "compress debug: all fallback candidates failed; passthrough identity status={}",
                status
            );
        }
        Ok(None)
    }

    #[inline]
    fn compression_debug_enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var_os("ARC_DEBUG_COMPRESSION").is_some())
    }

    #[inline]
    fn compression_adaptive_tick(&self, now_ns: u64) {
        let Some(adaptive) = self.compression_global.adaptive.as_ref() else {
            return;
        };
        let cap = self.conns.capacity().max(1) as f64;
        let active = self.metrics.active_current.load(Ordering::Relaxed) as f64;
        let load_proxy = (active / cap).clamp(0.0, 1.0);
        if let Some(adj) = adaptive.maybe_adjust(now_ns, load_proxy) {
            if Self::compression_debug_enabled() {
                eprintln!(
                    "compress debug: adaptive state={:?} dir={:?} proxy={:.3} levels(zstd={},br={},gzip={})",
                    adj.state,
                    adj.direction,
                    load_proxy,
                    adaptive.current_level_for_gauge(Algorithm::Zstd),
                    adaptive.current_level_for_gauge(Algorithm::Br),
                    adaptive.current_level_for_gauge(Algorithm::Gzip)
                );
            }
        }
    }

    #[inline]
    fn map_upstream_io_error(e: &io::Error) -> H2H1RoundtripError {
        if e.kind() == io::ErrorKind::TimedOut {
            H2H1RoundtripError::Timeout
        } else {
            H2H1RoundtripError::Io
        }
    }

    #[inline]
    fn upstream_tls_debug<E: std::fmt::Debug>(stage: &str, err: &E) {
        if Self::upstream_tls_debug_enabled() {
            eprintln!("[arc][upstream_tls] stage={stage} err={err:?}");
        }
    }

    #[inline]
    fn upstream_tls_debug_enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var_os("ARC_DEBUG_UPSTREAM_TLS").is_some())
    }

    fn upstream_read_until_complete<R: Read>(
        &self,
        mut reader: R,
        max_resp: usize,
        connect_done_ns: u64,
    ) -> std::result::Result<(Vec<u8>, bool, Option<u64>), H2H1RoundtripError> {
        let mut resp = Vec::with_capacity(8192);
        let mut buf = [0u8; 8192];
        let mut saw_eof = false;
        let mut response_ms: Option<u64> = None;

        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    if Self::upstream_tls_debug_enabled() {
                        eprintln!("[arc][upstream_tls] stage=read eof=1 bytes={}", resp.len());
                    }
                    saw_eof = true;
                    break;
                }
                Ok(n) => {
                    if Self::upstream_tls_debug_enabled() {
                        eprintln!(
                            "[arc][upstream_tls] stage=read chunk={} total={}",
                            n,
                            resp.len().saturating_add(n)
                        );
                    }
                    if resp.len().saturating_add(n) > max_resp {
                        return Err(H2H1RoundtripError::Proto);
                    }
                    resp.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if Self::upstream_tls_debug_enabled() {
                        eprintln!(
                            "[arc][upstream_tls] stage=read timeout_or_wouldblock kind={:?} bytes={}",
                            e.kind(),
                            resp.len()
                        );
                    }
                    break;
                }
                Err(e) => {
                    Self::upstream_tls_debug("read", &e);
                    return Err(H2H1RoundtripError::Io);
                }
            }

            if let Some(hend) = find_header_end(&resp) {
                if let Ok(head) = parse_response_head(&resp, hend) {
                    if response_ms.is_none() {
                        response_ms = Some(
                            monotonic_nanos()
                                .saturating_sub(connect_done_ns)
                                .saturating_div(1_000_000),
                        );
                    }
                    match head.body {
                        BodyKind::None => {
                            if Self::upstream_tls_debug_enabled() {
                                eprintln!("[arc][upstream_tls] stage=read body=none done=1");
                            }
                            break;
                        }
                        BodyKind::ContentLength { remaining } => {
                            if resp.len().saturating_sub(hend) >= remaining as usize {
                                if Self::upstream_tls_debug_enabled() {
                                    eprintln!(
                                        "[arc][upstream_tls] stage=read body=content_length done=1 need={} have={}",
                                        remaining,
                                        resp.len().saturating_sub(hend)
                                    );
                                }
                                break;
                            }
                        }
                        BodyKind::Chunked(_) => {
                            if Self::h2_decode_chunked(&resp[hend..])?.is_some() {
                                if Self::upstream_tls_debug_enabled() {
                                    eprintln!("[arc][upstream_tls] stage=read body=chunked done=1");
                                }
                                break;
                            }
                        }
                        BodyKind::UntilEof => {}
                    }
                }
            }
        }
        Ok((resp, saw_eof, response_ms))
    }

    fn upstream_roundtrip_raw(
        &self,
        upstream_id: usize,
        upstream_addr: SocketAddr,
        req: &[u8],
    ) -> std::result::Result<(Vec<u8>, bool, u64, Option<u64>), H2H1RoundtripError> {
        if self.active_cfg.upstreams.get(upstream_id).is_none() {
            return Err(H2H1RoundtripError::Proto);
        }

        let t0 = monotonic_nanos();
        let mut s = TcpStream::connect_timeout(
            &upstream_addr,
            Duration::from_millis(self.active_cfg.timeouts_ms.up_conn.max(1)),
        )
        .map_err(|e| {
            Self::upstream_tls_debug("connect", &e);
            Self::map_upstream_io_error(&e)
        })?;
        let connect_done_ns = monotonic_nanos();
        let connect_ms = connect_done_ns.saturating_sub(t0).saturating_div(1_000_000);
        // connect_timeout internally may use nonblocking connect.
        // Force blocking mode so timeout semantics are predictable.
        let _ = s.set_nonblocking(false);
        let _ = s.set_nodelay(true);

        let max_resp = 16 * 1024 * 1024usize;

        if let Some(rt) = self.upstream_tls.get(upstream_id).and_then(|v| v.as_ref()) {
            let hs_timeout = Duration::from_millis(self.active_cfg.timeouts_ms.up_handshake.max(1));
            let _ = s.set_write_timeout(Some(hs_timeout));
            let _ = s.set_read_timeout(Some(hs_timeout));

            let mut tls = ClientConnection::new(rt.config.clone(), rt.server_name.clone())
                .map_err(|e| {
                    Self::upstream_tls_debug("client_config", &e);
                    H2H1RoundtripError::Io
                })?;
            while tls.is_handshaking() {
                tls.complete_io(&mut s).map_err(|e| {
                    Self::upstream_tls_debug("handshake", &e);
                    Self::map_upstream_io_error(&e)
                })?;
            }

            let _ = s.set_write_timeout(Some(Duration::from_millis(
                self.active_cfg.timeouts_ms.up_write.max(1),
            )));
            let _ = s.set_read_timeout(Some(Duration::from_millis(
                self.active_cfg.timeouts_ms.up_read.max(1),
            )));

            let mut stream = rustls::Stream::new(&mut tls, &mut s);
            stream.write_all(req).map_err(|e| {
                Self::upstream_tls_debug("write", &e);
                Self::map_upstream_io_error(&e)
            })?;
            stream.flush().map_err(|e| {
                Self::upstream_tls_debug("flush", &e);
                Self::map_upstream_io_error(&e)
            })?;

            let (resp, saw_eof, response_ms) =
                self.upstream_read_until_complete(stream, max_resp, connect_done_ns)?;
            return Ok((resp, saw_eof, connect_ms, response_ms));
        }

        let _ = s.set_write_timeout(Some(Duration::from_millis(
            self.active_cfg.timeouts_ms.up_write.max(1),
        )));
        let _ = s.set_read_timeout(Some(Duration::from_millis(
            self.active_cfg.timeouts_ms.up_read.max(1),
        )));

        s.write_all(req)
            .map_err(|e| Self::map_upstream_io_error(&e))?;
        let (resp, saw_eof, response_ms) =
            self.upstream_read_until_complete(s, max_resp, connect_done_ns)?;
        Ok((resp, saw_eof, connect_ms, response_ms))
    }

    fn h2_roundtrip_h1(
        &self,
        upstream_id: usize,
        upstream_addr: SocketAddr,
        req: &[u8],
    ) -> std::result::Result<(u16, Vec<H2Header>, Vec<u8>, u64, Option<u64>), H2H1RoundtripError>
    {
        let (resp, saw_eof, connect_ms, response_ms) =
            self.upstream_roundtrip_raw(upstream_id, upstream_addr, req)?;

        let hend = find_header_end(&resp).ok_or(H2H1RoundtripError::Proto)?;
        let head = parse_response_head(&resp, hend).map_err(|_| H2H1RoundtripError::Proto)?;
        let mut headers = Self::h2_parse_h1_response_headers(&resp[..hend]);
        let body_raw = &resp[hend..];

        let body = match head.body {
            BodyKind::None => Vec::new(),
            BodyKind::ContentLength { remaining } => {
                if body_raw.len() < remaining as usize {
                    return Err(H2H1RoundtripError::Timeout);
                }
                body_raw[..remaining as usize].to_vec()
            }
            BodyKind::Chunked(_) => {
                let Some(decoded) = Self::h2_decode_chunked(body_raw)? else {
                    return Err(H2H1RoundtripError::Timeout);
                };
                decoded
            }
            BodyKind::UntilEof => {
                if !saw_eof {
                    return Err(H2H1RoundtripError::Timeout);
                }
                body_raw.to_vec()
            }
        };

        headers.push(H2Header {
            name: Bytes::from_static(b"content-length"),
            value: Bytes::from(body.len().to_string()),
        });

        Ok((head.status, headers, body, connect_ms, response_ms))
    }

    fn h2_body_to_chain(&mut self, body: &[u8]) -> Option<H2BufChain> {
        if body.is_empty() {
            return Some(H2BufChain::new());
        }
        let cap = self.bufs.buf_size().max(1);
        let mut off = 0usize;
        let mut chain = H2BufChain::new();
        while off < body.len() {
            let id = self.bufs.alloc()?;
            let take = (body.len() - off).min(cap);
            let p = self.bufs.ptr(id);
            unsafe {
                std::ptr::copy_nonoverlapping(body[off..off + take].as_ptr(), p, take);
            }
            chain.push_seg(id, 0, take as u32);
            off += take;
        }
        Some(chain)
    }

    #[inline]
    fn h2_down_pending_inc(&mut self, down: H2ConnKey) {
        let v = self.h2_down_pending.entry(down).or_insert(0);
        *v = v.saturating_add(1);
    }

    #[inline]
    fn h2_down_pending_dec(&mut self, down: H2ConnKey) -> u32 {
        h2_down_pending_dec_map(&mut self.h2_down_pending, down)
    }

    fn h2_unlink_task_from_down(&mut self, down: H2ConnKey, task_key: Key) {
        h2_unlink_task_from_down_map(&mut self.h2_tasks_by_down, down, task_key);
    }

    fn h2_release_task_resources(&mut self, task_key: Key) -> Option<(H2ConnKey, usize)> {
        let (down, upstream_id, fd, fi, io_buf, req_keepalive, resp_keepalive) = {
            let task = self.h2_tasks.get_mut(task_key)?;
            (
                task.down,
                task.upstream_id,
                task.upstream_fd,
                task.upstream_fi,
                task.io_buf,
                task.req_keepalive,
                task.resp_keepalive,
            )
        };

        if should_checkin_upstream_keepalive(req_keepalive, resp_keepalive, fd, fi) {
            self.checkin_idle_upstream(
                upstream_id,
                IdleUpstream {
                    fd,
                    fi,
                    upstream_id,
                    ts_ns: monotonic_nanos(),
                    watch_tag: 0,
                },
            );
        } else {
            if fd >= 0 {
                close_fd_graceful(fd, self.active_cfg.linger_ms);
                self.upstream_release_connection_slot(upstream_id);
            }
            if fi >= 0 {
                let slot = fi as u32;
                let _ = self.uring.update_files(slot, &[-1]);
                self.files.free_slot(slot);
            }
        }
        if io_buf != INVALID_BUF {
            self.bufs.free(io_buf);
        }

        self.h2_tasks.free(task_key);
        Some((down, upstream_id))
    }

    fn up_mtls_unlink_task_from_down(&mut self, down: H2ConnKey, task_key: Key) {
        let mut empty = false;
        if let Some(v) = self.up_mtls_tasks_by_down.get_mut(&down) {
            if let Some(pos) = v.iter().position(|k| *k == task_key) {
                v.swap_remove(pos);
            }
            empty = v.is_empty();
        }
        if empty {
            self.up_mtls_tasks_by_down.remove(&down);
        }
    }

    fn up_mtls_release_task_resources(&mut self, task_key: Key) -> Option<H2ConnKey> {
        let (down, upstream_id, fd, fi, io_buf) = {
            let task = self.up_mtls_tasks.get_mut(task_key)?;
            (
                task.down,
                task.upstream_id,
                task.upstream_fd,
                task.upstream_fi,
                task.io_buf,
            )
        };

        if fd >= 0 {
            close_fd_graceful(fd, self.active_cfg.linger_ms);
            self.upstream_release_connection_slot(upstream_id);
        }
        if fi >= 0 {
            let slot = fi as u32;
            let _ = self.uring.update_files(slot, &[-1]);
            self.files.free_slot(slot);
        }
        if io_buf != INVALID_BUF {
            self.bufs.free(io_buf);
        }

        self.up_mtls_tasks.free(task_key);
        Some(down)
    }

    fn up_mtls_cleanup_task(&mut self, task_key: Key) {
        let Some(down) = self.up_mtls_release_task_resources(task_key) else {
            return;
        };
        self.up_mtls_unlink_task_from_down(down, task_key);
    }

    fn up_mtls_fail_task(&mut self, task_key: Key, timeout: bool) -> Result<()> {
        let down = match self.up_mtls_tasks.get_mut(task_key) {
            Some(task) => task.down,
            None => return Ok(()),
        };
        self.up_mtls_cleanup_task(task_key);
        let conn_key = Key {
            idx: down.idx,
            gen: down.gen,
        };
        if timeout {
            self.queue_error_response(conn_key, RESP_504)?;
        } else {
            self.queue_error_response(conn_key, RESP_502)?;
        }
        Ok(())
    }

    fn up_mtls_finish_task(&mut self, task_key: Key, resp: Vec<u8>) -> Result<()> {
        let down = match self.up_mtls_tasks.get_mut(task_key) {
            Some(task) => task.down,
            None => return Ok(()),
        };
        self.up_mtls_cleanup_task(task_key);
        let conn_key = Key {
            idx: down.idx,
            gen: down.gen,
        };
        self.metrics.req_total.fetch_add(1, Ordering::Relaxed);
        self.metrics.resp_total.fetch_add(1, Ordering::Relaxed);
        self.queue_error_response(conn_key, &resp)?;
        Ok(())
    }

    fn up_mtls_abort_tasks_for_down(&mut self, down: H2ConnKey) {
        let keys = self.up_mtls_tasks_by_down.remove(&down).unwrap_or_default();
        for key in keys {
            let _ = self.up_mtls_release_task_resources(key);
        }
    }

    fn up_mtls_prepare_write_chunk(
        &mut self,
        task_key: Key,
    ) -> std::result::Result<bool, H2H1RoundtripError> {
        let io_buf = match self.up_mtls_tasks.get_mut(task_key) {
            Some(task) => task.io_buf,
            None => return Ok(false),
        };
        let cap = self.bufs.buf_size();
        let ptr = self.bufs.ptr(io_buf);

        let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
            return Ok(false);
        };

        if task.io_off < task.io_len {
            return Ok(true);
        }

        if !task.tls.wants_write() {
            task.io_off = 0;
            task.io_len = 0;
            return Ok(false);
        }

        let mut writer = RawBufWriter::new(ptr, cap);
        task.tls.write_tls(&mut writer).map_err(|e| {
            Self::upstream_tls_debug("write", &e);
            H2H1RoundtripError::Io
        })?;
        let wrote = writer.written() as u32;
        task.io_off = 0;
        task.io_len = wrote;
        Ok(wrote > 0)
    }

    fn up_mtls_try_build_response(
        &mut self,
        task_key: Key,
    ) -> std::result::Result<Option<Vec<u8>>, H2H1RoundtripError> {
        let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
            return Ok(None);
        };

        if task.resp.len() > UP_MTLS_MAX_RESP {
            return Err(H2H1RoundtripError::Proto);
        }

        if task.head_end.is_none() {
            let Some(hend) = find_header_end(&task.resp) else {
                return Ok(None);
            };
            let head =
                parse_response_head(&task.resp, hend).map_err(|_| H2H1RoundtripError::Proto)?;
            task.head_end = Some(hend);
            task.body_kind = Some(head.body);
        }

        let hend = task.head_end.ok_or(H2H1RoundtripError::Proto)?;
        let body_kind = task.body_kind.ok_or(H2H1RoundtripError::Proto)?;
        let body = &task.resp[hend..];

        let done = match body_kind {
            BodyKind::None => true,
            BodyKind::ContentLength { remaining } => body.len() >= remaining as usize,
            BodyKind::Chunked(_) => Self::h2_decode_chunked(body)?.is_some(),
            BodyKind::UntilEof => task.saw_eof,
        };

        if !done {
            return Ok(None);
        }

        Ok(Some(std::mem::take(&mut task.resp)))
    }

    fn up_mtls_schedule_task_connect(&mut self, task_key: Key) -> Result<()> {
        let (fi, sa_ptr, sa_len) = {
            let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.state = UpMtlsTaskState::Connecting;
            let now = monotonic_nanos();
            task.deadline_ns = now.saturating_add(
                self.active_cfg
                    .timeouts_ms
                    .up_conn
                    .saturating_mul(1_000_000),
            );
            self.mtls_timeout_wheel.push(task.deadline_ns, task_key);
            (
                task.upstream_fi,
                task.upstream_sa.as_ptr(),
                task.upstream_sa.len() as u32,
            )
        };

        let sq = sqe::connect(
            fi,
            true,
            sa_ptr,
            sa_len,
            op::pack(OpKind::MtlsConnect, Side::None, task_key.idx, task_key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push connect(upstream mtls task)", e))?;
        Ok(())
    }

    fn up_mtls_schedule_task_write(&mut self, task_key: Key, off: u32, len: u32) -> Result<()> {
        let (fi, io_buf, hs) = {
            let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.state = UpMtlsTaskState::Writing;
            (task.upstream_fi, task.io_buf, task.tls.is_handshaking())
        };
        let timeout_ms = if hs {
            self.active_cfg.timeouts_ms.up_handshake
        } else {
            self.active_cfg.timeouts_ms.up_write
        };
        let now = monotonic_nanos();
        if let Some(task) = self.up_mtls_tasks.get_mut(task_key) {
            task.deadline_ns = now.saturating_add(timeout_ms.saturating_mul(1_000_000));
            self.mtls_timeout_wheel.push(task.deadline_ns, task_key);
        }

        let p = self.bufs.ptr_at(io_buf, off);
        let sq = sqe::write_fixed(
            fi,
            true,
            p as *const u8,
            len,
            io_buf,
            op::pack(OpKind::MtlsWrite, Side::None, task_key.idx, task_key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push write(upstream mtls task)", e))?;
        Ok(())
    }

    fn up_mtls_schedule_task_read(&mut self, task_key: Key) -> Result<()> {
        let (fi, io_buf, hs) = {
            let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.state = UpMtlsTaskState::Reading;
            (task.upstream_fi, task.io_buf, task.tls.is_handshaking())
        };
        let timeout_ms = if hs {
            self.active_cfg.timeouts_ms.up_handshake
        } else {
            self.active_cfg.timeouts_ms.up_read
        };
        let now = monotonic_nanos();
        if let Some(task) = self.up_mtls_tasks.get_mut(task_key) {
            task.deadline_ns = now.saturating_add(timeout_ms.saturating_mul(1_000_000));
            self.mtls_timeout_wheel.push(task.deadline_ns, task_key);
        }

        let p = self.bufs.ptr(io_buf);
        let sq = sqe::read_fixed(
            fi,
            true,
            p,
            self.bufs.buf_size() as u32,
            io_buf,
            op::pack(OpKind::MtlsRead, Side::None, task_key.idx, task_key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push read(upstream mtls task)", e))?;
        Ok(())
    }

    fn up_mtls_spawn_task(&mut self, down_key: Key, upstream_id: usize, req: &[u8]) -> Result<()> {
        let Some(_up) = self.active_cfg.upstreams.get(upstream_id) else {
            self.queue_error_response(down_key, RESP_502)?;
            return Ok(());
        };
        let up_addr = match self.upstream_runtime_addr(upstream_id) {
            Some(v) => v,
            None => {
                self.queue_error_response(down_key, RESP_502)?;
                return Ok(());
            }
        };
        let Some(rt) = self.upstream_tls.get(upstream_id).and_then(|v| v.as_ref()) else {
            self.queue_error_response(down_key, RESP_502)?;
            return Ok(());
        };
        if !self.upstream_try_acquire_connection_slot(upstream_id) {
            self.queue_error_response(down_key, RESP_503)?;
            return Ok(());
        }

        let upstream_fd = match net::create_client_socket(&up_addr) {
            Ok(fd) => fd,
            Err(_) => {
                self.upstream_release_connection_slot(upstream_id);
                self.queue_error_response(down_key, RESP_502)?;
                return Ok(());
            }
        };
        if self.active_cfg.linger_ms > 0 {
            let _ = net::set_linger(upstream_fd, self.active_cfg.linger_ms);
        }

        let up_slot = match self.files.alloc() {
            Some(s) => s,
            None => {
                close_fd(upstream_fd);
                self.upstream_release_connection_slot(upstream_id);
                self.queue_error_response(down_key, RESP_502)?;
                return Ok(());
            }
        };
        self.files.table[up_slot as usize] = upstream_fd;
        if self.uring.update_files(up_slot, &[upstream_fd]).is_err() {
            self.files.free_slot(up_slot);
            close_fd(upstream_fd);
            self.upstream_release_connection_slot(upstream_id);
            self.queue_error_response(down_key, RESP_502)?;
            return Ok(());
        }

        let io_buf = match self.bufs.alloc() {
            Some(b) => b,
            None => {
                let _ = self.uring.update_files(up_slot, &[-1]);
                self.files.free_slot(up_slot);
                close_fd(upstream_fd);
                self.upstream_release_connection_slot(upstream_id);
                self.queue_error_response(down_key, RESP_502)?;
                return Ok(());
            }
        };

        let mut tls = match ClientConnection::new(rt.config.clone(), rt.server_name.clone()) {
            Ok(v) => v,
            Err(_) => {
                self.bufs.free(io_buf);
                let _ = self.uring.update_files(up_slot, &[-1]);
                self.files.free_slot(up_slot);
                close_fd(upstream_fd);
                self.upstream_release_connection_slot(upstream_id);
                self.queue_error_response(down_key, RESP_502)?;
                return Ok(());
            }
        };
        if tls.writer().write_all(req).is_err() {
            self.bufs.free(io_buf);
            let _ = self.uring.update_files(up_slot, &[-1]);
            self.files.free_slot(up_slot);
            close_fd(upstream_fd);
            self.upstream_release_connection_slot(upstream_id);
            self.queue_error_response(down_key, RESP_502)?;
            return Ok(());
        }

        let task_key = match self.up_mtls_tasks.alloc() {
            Some(k) => k,
            None => {
                self.bufs.free(io_buf);
                let _ = self.uring.update_files(up_slot, &[-1]);
                self.files.free_slot(up_slot);
                close_fd(upstream_fd);
                self.upstream_release_connection_slot(upstream_id);
                self.queue_error_response(down_key, RESP_503)?;
                return Ok(());
            }
        };

        let task = UpMtlsTask {
            down: H2ConnKey::new(down_key.idx, down_key.gen),
            upstream_id,
            upstream_fd,
            upstream_fi: up_slot as i32,
            upstream_sa: net::SockAddr::from_socket_addr(&up_addr),
            io_buf,
            io_len: 0,
            io_off: 0,
            tls,
            resp: Vec::with_capacity(8192),
            head_end: None,
            body_kind: None,
            saw_eof: false,
            state: UpMtlsTaskState::Connecting,
            deadline_ns: 0,
        };
        unsafe {
            self.up_mtls_tasks.write(task_key, task);
        }
        self.up_mtls_tasks_by_down
            .entry(H2ConnKey::new(down_key.idx, down_key.gen))
            .or_default()
            .push(task_key);

        if self.up_mtls_schedule_task_connect(task_key).is_err() {
            self.up_mtls_cleanup_task(task_key);
            self.queue_error_response(down_key, RESP_502)?;
        }
        Ok(())
    }

    fn on_up_mtls_task_connect(&mut self, task_key: Key, res: i32) -> Result<()> {
        let fd = match self.up_mtls_tasks.get_mut(task_key) {
            Some(task) => task.upstream_fd,
            None => return Ok(()),
        };
        if res < 0 {
            let cqe_err = -res;
            let so_error = socket_so_error(fd).unwrap_or(cqe_err);
            if should_retry_connect(res, so_error) {
                return self.up_mtls_schedule_task_connect(task_key);
            }
            let err = io::Error::from_raw_os_error(so_error);
            Self::upstream_tls_debug("connect", &err);
            return self.up_mtls_fail_task(task_key, false);
        }

        match self.up_mtls_prepare_write_chunk(task_key) {
            Ok(true) => {
                let (off, len) = match self.up_mtls_tasks.get_mut(task_key) {
                    Some(task) => (task.io_off, task.io_len.saturating_sub(task.io_off)),
                    None => return Ok(()),
                };
                if len > 0 {
                    return self.up_mtls_schedule_task_write(task_key, off, len);
                }
            }
            Ok(false) => {}
            Err(_) => return self.up_mtls_fail_task(task_key, false),
        }
        self.up_mtls_schedule_task_read(task_key)
    }

    fn on_up_mtls_task_write(&mut self, task_key: Key, res: i32) -> Result<()> {
        if res < 0 {
            if is_retryable_io_error(Some(-res)) {
                let (off, len) = match self.up_mtls_tasks.get_mut(task_key) {
                    Some(task) => (task.io_off, task.io_len.saturating_sub(task.io_off)),
                    None => return Ok(()),
                };
                if len > 0 {
                    return self.up_mtls_schedule_task_write(task_key, off, len);
                }
            }
            let err = io::Error::from_raw_os_error(-res);
            Self::upstream_tls_debug("write", &err);
            return self.up_mtls_fail_task(task_key, false);
        }
        if res == 0 {
            return self.up_mtls_fail_task(task_key, false);
        }

        let wrote = res as u32;
        let mut next_write: Option<(u32, u32)> = None;
        {
            let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.io_off = task.io_off.saturating_add(wrote);
            if task.io_off < task.io_len {
                next_write = Some((task.io_off, task.io_len.saturating_sub(task.io_off)));
            } else {
                task.io_off = 0;
                task.io_len = 0;
            }
        }

        if let Some((off, len)) = next_write {
            return self.up_mtls_schedule_task_write(task_key, off, len);
        }

        match self.up_mtls_prepare_write_chunk(task_key) {
            Ok(true) => {
                let (off, len) = match self.up_mtls_tasks.get_mut(task_key) {
                    Some(task) => (task.io_off, task.io_len.saturating_sub(task.io_off)),
                    None => return Ok(()),
                };
                if len > 0 {
                    return self.up_mtls_schedule_task_write(task_key, off, len);
                }
            }
            Ok(false) => {}
            Err(_) => return self.up_mtls_fail_task(task_key, false),
        }

        if let Ok(Some(resp)) = self.up_mtls_try_build_response(task_key) {
            return self.up_mtls_finish_task(task_key, resp);
        }
        self.up_mtls_schedule_task_read(task_key)
    }

    fn on_up_mtls_task_read(&mut self, task_key: Key, res: i32) -> Result<()> {
        if res < 0 {
            if is_retryable_io_error(Some(-res)) {
                return self.up_mtls_schedule_task_read(task_key);
            }
            let err = io::Error::from_raw_os_error(-res);
            Self::upstream_tls_debug("read", &err);
            return self.up_mtls_fail_task(task_key, false);
        }

        if res == 0 {
            if let Some(task) = self.up_mtls_tasks.get_mut(task_key) {
                task.saw_eof = true;
            }
        } else {
            let n = res as usize;
            let io_buf = match self.up_mtls_tasks.get_mut(task_key) {
                Some(task) => task.io_buf,
                None => return Ok(()),
            };
            let p = self.bufs.ptr(io_buf) as *const u8;

            {
                let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                    return Ok(());
                };
                let mut rdr = RawBufReader::new(p, n);
                if let Err(e) = task.tls.read_tls(&mut rdr) {
                    Self::upstream_tls_debug("read", &e);
                    return self.up_mtls_fail_task(task_key, false);
                }
                if let Err(e) = task.tls.process_new_packets() {
                    Self::upstream_tls_debug("handshake", &e);
                    return self.up_mtls_fail_task(task_key, false);
                }
            }

            let mut drained = 0usize;
            let mut buf = [0u8; 8192];
            loop {
                if drained >= UP_MTLS_PLAIN_DRAIN_BUDGET {
                    break;
                }
                let read_res = {
                    let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                        return Ok(());
                    };
                    task.tls.reader().read(&mut buf)
                };
                match read_res {
                    Ok(0) => break,
                    Ok(m) => {
                        drained += m;
                        let too_large = {
                            let Some(task) = self.up_mtls_tasks.get_mut(task_key) else {
                                return Ok(());
                            };
                            if task.resp.len().saturating_add(m) > UP_MTLS_MAX_RESP {
                                true
                            } else {
                                task.resp.extend_from_slice(&buf[..m]);
                                false
                            }
                        };
                        if too_large {
                            return self.up_mtls_fail_task(task_key, false);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        Self::upstream_tls_debug("read", &e);
                        return self.up_mtls_fail_task(task_key, false);
                    }
                }
            }
        }

        match self.up_mtls_try_build_response(task_key) {
            Ok(Some(resp)) => return self.up_mtls_finish_task(task_key, resp),
            Ok(None) => {}
            Err(_) => return self.up_mtls_fail_task(task_key, false),
        }

        if res == 0 {
            return self.up_mtls_fail_task(task_key, false);
        }

        match self.up_mtls_prepare_write_chunk(task_key) {
            Ok(true) => {
                let (off, len) = match self.up_mtls_tasks.get_mut(task_key) {
                    Some(task) => (task.io_off, task.io_len.saturating_sub(task.io_off)),
                    None => return Ok(()),
                };
                if len > 0 {
                    return self.up_mtls_schedule_task_write(task_key, off, len);
                }
            }
            Ok(false) => {}
            Err(_) => return self.up_mtls_fail_task(task_key, false),
        }

        self.up_mtls_schedule_task_read(task_key)
    }

    #[inline]
    fn h2_up_limit(&self) -> u32 {
        let cfg_limit = self.active_cfg.http2.max_active_streams.max(1) as u32;
        let cap_limit = self.h2_tasks.capacity().max(1) as u32;
        cfg_limit.min(cap_limit).max(1)
    }

    #[inline]
    fn h2_active_inflight(&self) -> u32 {
        self.h2_up_inflight
            .iter()
            .copied()
            .fold(0u32, |acc, v| acc.saturating_add(v))
    }

    fn h2_drop_stale_pending(&mut self, _now_ns: u64) {}

    fn h2_up_on_task_done(&mut self, upstream_id: usize) {
        if let Some(v) = self.h2_up_inflight.get_mut(upstream_id) {
            *v = v.saturating_sub(1);
        }
    }

    fn h2_spawn_or_queue_h1_task(
        &mut self,
        down: H2ConnKey,
        sid: u32,
        upstream_id: usize,
        req: Vec<u8>,
        started_ns: u64,
        mut access_log: Option<AccessLogSnapshot>,
        response_header_muts: Arc<[CompiledHeaderMutation]>,
    ) -> std::result::Result<(), H2DispatchError> {
        if upstream_id >= self.h2_up_inflight.len() {
            return Err(H2DispatchError::Failed(access_log));
        }
        let limit = self.h2_up_limit();
        if self.h2_active_inflight() >= limit {
            return Err(H2DispatchError::RefusedStream(access_log));
        }

        self.h2_up_inflight[upstream_id] = self.h2_up_inflight[upstream_id].saturating_add(1);
        if self
            .h2_spawn_h1_task(
                down,
                sid,
                upstream_id,
                req,
                started_ns,
                &mut access_log,
                response_header_muts,
            )
            .is_err()
        {
            self.h2_up_inflight[upstream_id] = self.h2_up_inflight[upstream_id].saturating_sub(1);
            return Err(H2DispatchError::Failed(access_log));
        }
        Ok(())
    }

    fn h2_abort_tasks_for_down(&mut self, down: H2ConnKey) {
        let keys = self.h2_tasks_by_down.remove(&down).unwrap_or_default();
        self.h2_down_pending.remove(&down);
        for task_key in keys {
            if let Some((_, upstream_id)) = self.h2_release_task_resources(task_key) {
                self.h2_up_on_task_done(upstream_id);
            }
        }
    }

    fn h2_cleanup_task(&mut self, task_key: Key) {
        let Some((down, upstream_id)) = self.h2_release_task_resources(task_key) else {
            return;
        };
        self.h2_unlink_task_from_down(down, task_key);
        self.h2_up_on_task_done(upstream_id);
        let left = self.h2_down_pending_dec(down);
        if left == 0 {
            let _ = self.h2_maybe_resume_downstream_read(down);
        }
    }

    fn h2_send_status_only(&mut self, down: H2ConnKey, sid: u32, status: u16) {
        let key = Key {
            idx: down.idx,
            gen: down.gen,
        };
        let Some(conn) = self.conns.get_mut(key) else {
            return;
        };
        let Some(d) = conn.h2_down.as_mut() else {
            return;
        };
        let _ = d.send_response_headers(sid, status, vec![], true);
    }

    fn h2_send_full_response(
        &mut self,
        down: H2ConnKey,
        sid: u32,
        status: u16,
        headers: Vec<H2Header>,
        body: Vec<u8>,
    ) {
        let chain = if body.is_empty() {
            None
        } else {
            self.h2_body_to_chain(&body)
        };

        let key = Key {
            idx: down.idx,
            gen: down.gen,
        };
        let Some(conn) = self.conns.get_mut(key) else {
            return;
        };
        let Some(d) = conn.h2_down.as_mut() else {
            if let Some(mut c) = chain {
                let mut ops = WorkerH2BufOps {
                    bufs: &mut self.bufs,
                };
                c.release(&mut ops);
            }
            return;
        };

        if body.is_empty() {
            let _ = d.send_response_headers(sid, status, headers, true);
            return;
        }

        if d.send_response_headers(sid, status, headers, false)
            .is_err()
        {
            if let Some(mut c) = chain {
                let mut ops = WorkerH2BufOps {
                    bufs: &mut self.bufs,
                };
                c.release(&mut ops);
            }
            return;
        }

        let Some(chain) = chain else {
            let _ = d.send_response_headers(sid, 503, vec![], true);
            return;
        };

        let mut ops = WorkerH2BufOps {
            bufs: &mut self.bufs,
        };
        let _ = d.send_response_data(sid, true, chain, None, &mut ops);
    }

    #[inline]
    fn select_route_http1(
        &self,
        method: &[u8],
        full_path: &[u8],
        head_block: &[u8],
        sni: Option<&[u8]>,
        is_tls: bool,
    ) -> std::result::Result<u32, RouteSelectError> {
        select_route_http1_from_cfg(
            self.active_cfg.as_ref(),
            method,
            full_path,
            head_block,
            sni,
            is_tls,
        )
    }

    #[inline]
    fn select_route_h2(
        &self,
        method: &[u8],
        full_path: &[u8],
        authority: Option<&[u8]>,
        headers: &[H2Header],
        sni: Option<&[u8]>,
        is_tls: bool,
    ) -> std::result::Result<u32, RouteSelectError> {
        let path_no_q = strip_query(full_path);
        let host = authority
            .or_else(|| h2_header_value(headers, b"host"))
            .map(trim_ascii_ws)
            .map(host_without_port)
            .map(trim_trailing_dot);

        let mut best_pri: i32 = i32::MIN;
        let mut best_spec: u32 = 0;
        let mut best_id: u32 = 0;
        let mut best_count: u32 = 0;

        self.active_cfg.router.for_each_candidate(path_no_q, |rid| {
            let group = self
                .active_cfg
                .route_candidate_groups
                .get(rid as usize)
                .map(|g| g.as_ref())
                .unwrap_or(&[]);
            let candidates: &[u32] = if group.is_empty() { &[rid] } else { group };

            for &cid in candidates {
                let Some(route) = self.active_cfg.routes.get(cid as usize) else {
                    continue;
                };
                if !route_matches_h2(route, method, full_path, headers, host, sni, is_tls) {
                    continue;
                }

                let pri = route.priority;
                let spec = route.specificity();
                if pri > best_pri || (pri == best_pri && spec > best_spec) {
                    best_pri = pri;
                    best_spec = spec;
                    best_id = cid;
                    best_count = 1;
                } else if pri == best_pri && spec == best_spec {
                    best_count = best_count.saturating_add(1);
                }
            }
        });

        if best_count == 0 {
            return Err(RouteSelectError::NotFound);
        }
        if best_count > 1 {
            return Err(RouteSelectError::Ambiguous);
        }
        Ok(best_id)
    }

    #[inline]
    fn compute_split_hash_http1(
        &self,
        route: &arc_config::CompiledRoute,
        head_block: &[u8],
        req_buf: &[u8],
    ) -> u64 {
        let RouteUpstreams::Split(split) = &route.upstreams else {
            return 0;
        };
        let (_, path) = http1_parse_req_line(req_buf).unwrap_or((b"", b"/"));
        match &split.key {
            CompiledSplitKey::Random => splitmix64(monotonic_nanos()),
            CompiledSplitKey::Path => fnv1a64(0xA1C3_5EED, path),
            CompiledSplitKey::Host => {
                let host = http1_header_value(head_block, b"host")
                    .map(trim_ascii_ws)
                    .unwrap_or(b"");
                fnv1a64(0xBADC_0FFE, host)
            }
            CompiledSplitKey::Header(name_lower) => {
                let v = http1_header_value(head_block, name_lower.as_ref())
                    .map(trim_ascii_ws)
                    .unwrap_or(b"");
                fnv1a64(0xC0FF_EE11, v)
            }
            CompiledSplitKey::Cookie(cookie_name) => {
                let ck = http1_header_value(head_block, b"cookie")
                    .map(trim_ascii_ws)
                    .unwrap_or(b"");
                let v = cookie_get(ck, cookie_name.as_ref()).unwrap_or(b"");
                fnv1a64(0x0D15_EA5E, v)
            }
        }
    }

    #[inline]
    fn select_upstream_for_attempt(
        &self,
        route_id: u32,
        route: &arc_config::CompiledRoute,
        base_hash: u64,
        attempt: u32,
        tried: &[usize],
    ) -> Option<usize> {
        match &route.upstreams {
            RouteUpstreams::None => None,
            RouteUpstreams::Single { upstream_id } => {
                if tried.iter().any(|&u| u == *upstream_id)
                    || self.upstream_circuit_open(*upstream_id)
                {
                    None
                } else {
                    Some(*upstream_id)
                }
            }
            RouteUpstreams::Split(split) => match split.load_balance {
                CompiledLoadBalance::RoundRobin => {
                    let n = split.choices.len();
                    if n == 0 {
                        return None;
                    }
                    let start = self
                        .rr_route_counters
                        .get(route_id as usize)
                        .map(|v| v.fetch_add(1, Ordering::Relaxed) % n)
                        .unwrap_or(0);
                    for i in 0..n {
                        let idx = (start + i) % n;
                        let chosen = split.choices[idx].upstream_id;
                        if tried.iter().any(|&u| u == chosen) || self.upstream_circuit_open(chosen)
                        {
                            continue;
                        }
                        return Some(chosen);
                    }
                    None
                }
                CompiledLoadBalance::HashWeighted => {
                    let n = split.choices.len();
                    if n == 0 || split.total_weight == 0 {
                        return None;
                    }
                    for probe in 0..n {
                        let h = splitmix64(base_hash ^ ((attempt as u64) << 32) ^ (probe as u64));
                        let x = (h % (split.total_weight as u64)) as u32;
                        let mut chosen = split.choices[n - 1].upstream_id;
                        for c in split.choices.iter() {
                            if x < c.cumulative {
                                chosen = c.upstream_id;
                                break;
                            }
                        }
                        if tried.iter().any(|&u| u == chosen) || self.upstream_circuit_open(chosen)
                        {
                            continue;
                        }
                        return Some(chosen);
                    }
                    None
                }
            },
        }
    }

    fn http1_apply_rewrite_and_header_muts(&mut self, key: Key, route_id: u32) -> Result<()> {
        let (is_forward, forward) = match self.active_cfg.routes.get(route_id as usize) {
            Some(route) => (
                matches!(route.action, RouteAction::Forward),
                route.forward.clone(),
            ),
            None => return Ok(()),
        };
        if !is_forward {
            return Ok(());
        }
        if forward.rewrite.is_none() && forward.header_muts.is_empty() {
            return Ok(());
        }

        let (buf_id, req_len, header_end) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            if conn.buf == INVALID_BUF {
                return Ok(());
            }
            (conn.buf, conn.buf_len as usize, conn.header_end as usize)
        };
        if header_end == 0 || header_end > req_len {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        }

        let src =
            unsafe { std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, req_len) };
        let Some((method, path)) = http1_parse_req_line(src) else {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        };

        let mut line_end = None;
        for i in 0..header_end.saturating_sub(1) {
            if src[i] == b'\r' && src[i + 1] == b'\n' {
                line_end = Some(i + 2);
                break;
            }
        }
        let Some(line_end) = line_end else {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        };

        let version = {
            let mut sp = 0usize;
            let mut sp_cnt = 0usize;
            for i in 0..line_end {
                if src[i] == b' ' {
                    sp_cnt += 1;
                    if sp_cnt == 2 {
                        sp = i;
                        break;
                    }
                }
            }
            let ver_start = sp + 1;
            let ver_end = line_end.saturating_sub(2);
            if ver_start >= ver_end {
                b"HTTP/1.1".as_slice()
            } else {
                &src[ver_start..ver_end]
            }
        };

        let new_path: std::borrow::Cow<'_, [u8]> = match &forward.rewrite {
            None => std::borrow::Cow::Borrowed(path),
            Some(CompiledRewrite::Prefix { from, to }) => {
                if path.starts_with(from.as_ref()) {
                    let mut v =
                        Vec::with_capacity(to.len() + path.len().saturating_sub(from.len()));
                    v.extend_from_slice(to.as_ref());
                    v.extend_from_slice(&path[from.len()..]);
                    std::borrow::Cow::Owned(v)
                } else {
                    std::borrow::Cow::Borrowed(path)
                }
            }
            Some(CompiledRewrite::Regex { re, replace }) => {
                if re.is_match(path) {
                    let replaced = re.replace_all(path, replace.as_ref());
                    std::borrow::Cow::Owned(replaced.into_owned())
                } else {
                    std::borrow::Cow::Borrowed(path)
                }
            }
        };

        let muts = forward.header_muts.as_ref();
        let mut out: Vec<u8> = Vec::with_capacity(header_end + 64);
        out.extend_from_slice(method);
        out.push(b' ');
        out.extend_from_slice(new_path.as_ref());
        out.push(b' ');
        out.extend_from_slice(version);
        out.extend_from_slice(b"\r\n");

        let hdr_region = &src[line_end..header_end];
        let mut i = 0usize;
        while i + 1 < hdr_region.len() {
            let mut j = i;
            while j + 1 < hdr_region.len()
                && !(hdr_region[j] == b'\r' && hdr_region[j + 1] == b'\n')
            {
                j += 1;
            }
            if j + 1 >= hdr_region.len() {
                break;
            }
            let line = &hdr_region[i..j];
            i = j + 2;
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                continue;
            };
            let name = &line[..colon];
            if muts.iter().any(|m| match m {
                CompiledHeaderMutation::Remove { name_lower } => {
                    name.eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Set { name_lower, .. } => {
                    name.eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Add { .. } => false,
            }) {
                continue;
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }

        for m in muts.iter() {
            if let CompiledHeaderMutation::Set { name, value, .. } = m {
                out.extend_from_slice(name.as_ref());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_ref());
                out.extend_from_slice(b"\r\n");
            }
        }
        for m in muts.iter() {
            if let CompiledHeaderMutation::Add { name, value, .. } = m {
                out.extend_from_slice(name.as_ref());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_ref());
                out.extend_from_slice(b"\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");

        let new_header_end = out.len();
        out.extend_from_slice(&src[header_end..req_len]);

        if out.len() > self.bufs.buf_size() {
            self.queue_error_response(key, RESP_431)?;
            return Ok(());
        }

        unsafe {
            let dst = self.bufs.ptr(buf_id);
            std::ptr::copy_nonoverlapping(out.as_ptr(), dst, out.len());
        }

        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.buf_len = out.len() as u32;
        conn.header_end = new_header_end as u32;
        Ok(())
    }

    fn http1_apply_response_header_muts(
        &mut self,
        key: Key,
        route_id: u32,
        send_len: usize,
    ) -> Result<Option<usize>> {
        let muts = match self.active_cfg.routes.get(route_id as usize) {
            Some(route) => route.response_header_muts.clone(),
            None => return Ok(Some(send_len)),
        };
        if muts.is_empty() || send_len == 0 {
            return Ok(Some(send_len));
        }

        let (buf_id, cur_len) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(None);
            };
            if conn.buf == INVALID_BUF {
                return Ok(None);
            }
            (conn.buf, conn.buf_len as usize)
        };
        if send_len > cur_len || send_len > self.bufs.buf_size() {
            self.queue_error_response(key, RESP_502)?;
            return Ok(None);
        }

        let src =
            unsafe { std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, send_len) };
        let Some(header_end) = find_header_end(src) else {
            self.queue_error_response(key, RESP_502)?;
            return Ok(None);
        };

        let mut line_end = None;
        for i in 0..header_end.saturating_sub(1) {
            if src[i] == b'\r' && src[i + 1] == b'\n' {
                line_end = Some(i + 2);
                break;
            }
        }
        let Some(line_end) = line_end else {
            self.queue_error_response(key, RESP_502)?;
            return Ok(None);
        };

        let mut out = Vec::with_capacity(send_len.saturating_add(64));
        out.extend_from_slice(&src[..line_end]);

        let hdr_region = &src[line_end..header_end];
        let mut i = 0usize;
        while i + 1 < hdr_region.len() {
            let mut j = i;
            while j + 1 < hdr_region.len()
                && !(hdr_region[j] == b'\r' && hdr_region[j + 1] == b'\n')
            {
                j += 1;
            }
            if j + 1 >= hdr_region.len() {
                break;
            }
            let line = &hdr_region[i..j];
            i = j + 2;
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                continue;
            };
            let name = &line[..colon];
            if muts.iter().any(|m| match m {
                CompiledHeaderMutation::Remove { name_lower } => {
                    name.eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Set { name_lower, .. } => {
                    name.eq_ignore_ascii_case(name_lower.as_ref())
                }
                CompiledHeaderMutation::Add { .. } => false,
            }) {
                continue;
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }

        for m in muts.iter() {
            if let CompiledHeaderMutation::Set { name, value, .. } = m {
                out.extend_from_slice(name.as_ref());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_ref());
                out.extend_from_slice(b"\r\n");
            }
        }
        for m in muts.iter() {
            if let CompiledHeaderMutation::Add { name, value, .. } = m {
                out.extend_from_slice(name.as_ref());
                out.extend_from_slice(b": ");
                out.extend_from_slice(value.as_ref());
                out.extend_from_slice(b"\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&src[header_end..send_len]);

        if out.len() > self.bufs.buf_size() {
            self.queue_error_response(key, RESP_502)?;
            return Ok(None);
        }

        unsafe {
            let dst = self.bufs.ptr(buf_id);
            std::ptr::copy_nonoverlapping(out.as_ptr(), dst, out.len());
        }

        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(None);
        };
        conn.buf_len = out.len() as u32;
        conn.header_end = (out.len() - (send_len - header_end)) as u32;
        Ok(Some(out.len()))
    }

    fn http1_upsert_header(&mut self, key: Key, name: &[u8], value: &[u8]) -> Result<()> {
        if name.is_empty() {
            return Ok(());
        }

        let (buf_id, req_len, header_end) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            if conn.buf == INVALID_BUF {
                return Ok(());
            }
            (conn.buf, conn.buf_len as usize, conn.header_end as usize)
        };
        if header_end == 0 || header_end > req_len {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        }

        let src =
            unsafe { std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, req_len) };
        let mut out = Vec::with_capacity(req_len.saturating_add(name.len() + value.len() + 6));

        let mut line_end = None;
        for i in 0..header_end.saturating_sub(1) {
            if src[i] == b'\r' && src[i + 1] == b'\n' {
                line_end = Some(i + 2);
                break;
            }
        }
        let Some(line_end) = line_end else {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        };

        out.extend_from_slice(&src[..line_end]);

        let hdr_region = &src[line_end..header_end];
        let mut i = 0usize;
        while i + 1 < hdr_region.len() {
            let mut j = i;
            while j + 1 < hdr_region.len()
                && !(hdr_region[j] == b'\r' && hdr_region[j + 1] == b'\n')
            {
                j += 1;
            }
            if j + 1 >= hdr_region.len() {
                break;
            }
            let line = &hdr_region[i..j];
            i = j + 2;
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                continue;
            };
            let n = &line[..colon];
            if n.eq_ignore_ascii_case(name) {
                continue;
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(&src[header_end..req_len]);

        if out.len() > self.bufs.buf_size() {
            self.queue_error_response(key, RESP_431)?;
            return Ok(());
        }

        unsafe {
            let dst = self.bufs.ptr(buf_id);
            std::ptr::copy_nonoverlapping(out.as_ptr(), dst, out.len());
        }

        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.buf_len = out.len() as u32;
        conn.header_end = (out.len() - (req_len - header_end)) as u32;
        Ok(())
    }

    fn http1_sanitize_framing_headers(&mut self, key: Key) -> Result<()> {
        let (buf_id, req_len, header_end) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            if conn.buf == INVALID_BUF {
                return Ok(());
            }
            (conn.buf, conn.buf_len as usize, conn.header_end as usize)
        };
        if header_end == 0 || header_end > req_len {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        }

        let src =
            unsafe { std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, req_len) };
        let mut line_end = None;
        for i in 0..header_end.saturating_sub(1) {
            if src[i] == b'\r' && src[i + 1] == b'\n' {
                line_end = Some(i + 2);
                break;
            }
        }
        let Some(line_end) = line_end else {
            self.queue_error_response(key, RESP_400)?;
            return Ok(());
        };

        let hdr_region = &src[line_end..header_end];
        let mut has_te_chunked = false;
        let mut has_content_length = false;
        let mut i = 0usize;
        while i + 1 < hdr_region.len() {
            let mut j = i;
            while j + 1 < hdr_region.len()
                && !(hdr_region[j] == b'\r' && hdr_region[j + 1] == b'\n')
            {
                j += 1;
            }
            if j + 1 >= hdr_region.len() {
                break;
            }
            let line = &hdr_region[i..j];
            i = j + 2;
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                continue;
            };
            let name = &line[..colon];
            let value = trim_ascii_ws(&line[colon + 1..]);
            if name.eq_ignore_ascii_case(b"transfer-encoding")
                && header_value_contains_token(value, b"chunked")
            {
                has_te_chunked = true;
            } else if name.eq_ignore_ascii_case(b"content-length") {
                has_content_length = true;
            }
        }

        if !(has_te_chunked && has_content_length) {
            return Ok(());
        }

        let mut out = Vec::with_capacity(req_len);
        out.extend_from_slice(&src[..line_end]);

        let mut i = 0usize;
        while i + 1 < hdr_region.len() {
            let mut j = i;
            while j + 1 < hdr_region.len()
                && !(hdr_region[j] == b'\r' && hdr_region[j + 1] == b'\n')
            {
                j += 1;
            }
            if j + 1 >= hdr_region.len() {
                break;
            }
            let line = &hdr_region[i..j];
            i = j + 2;
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                continue;
            };
            let name = &line[..colon];
            if name.eq_ignore_ascii_case(b"content-length") {
                continue;
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&src[header_end..req_len]);

        if out.len() > self.bufs.buf_size() {
            self.queue_error_response(key, RESP_431)?;
            return Ok(());
        }

        unsafe {
            let dst = self.bufs.ptr(buf_id);
            std::ptr::copy_nonoverlapping(out.as_ptr(), dst, out.len());
        }
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.buf_len = out.len() as u32;
        conn.header_end = (out.len() - (req_len - header_end)) as u32;
        Ok(())
    }

    fn start_connect_upstream_new_socket(&mut self, key: Key) -> Result<()> {
        let up_id = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            conn.upstream_id
        };

        let up_addr = match self.upstream_runtime_addr(up_id) {
            Some(v) => v,
            None => return Ok(()),
        };
        if !self.upstream_try_acquire_connection_slot(up_id) {
            self.queue_error_response(key, RESP_503)?;
            return Ok(());
        }

        let up_fd = match net::create_client_socket(&up_addr) {
            Ok(fd) => fd,
            Err(_) => {
                self.upstream_release_connection_slot(up_id);
                return Ok(());
            }
        };
        if self.active_cfg.linger_ms > 0 {
            let _ = net::set_linger(up_fd, self.active_cfg.linger_ms);
        }

        let up_slot = match self.files.alloc() {
            Some(s) => s,
            None => {
                close_fd(up_fd);
                self.upstream_release_connection_slot(up_id);
                return Ok(());
            }
        };
        self.files.table[up_slot as usize] = up_fd;
        if self.uring.update_files(up_slot, &[up_fd]).is_err() {
            self.files.free_slot(up_slot);
            close_fd(up_fd);
            self.upstream_release_connection_slot(up_id);
            return Ok(());
        }

        {
            let Some(conn) = self.conns.get_mut(key) else {
                let _ = self.uring.update_files(up_slot, &[-1]);
                self.files.free_slot(up_slot);
                close_fd(up_fd);
                self.upstream_release_connection_slot(up_id);
                return Ok(());
            };
            conn.upstream_fd = up_fd;
            conn.upstream_fi = up_slot as i32;
            conn.upstream_reused = false;
            conn.state = ConnState::UpConnecting;
            conn.upstream_sa = Some(net::SockAddr::from_socket_addr(&up_addr));
        }
        self.schedule_connect_upstream(key, up_slot as i32)?;
        Ok(())
    }

    fn maybe_retry_http1(&mut self, key: Key) -> Result<bool> {
        let now = monotonic_nanos();
        let (
            route_id,
            split_hash,
            retry_allowed,
            retry_idempotent_only,
            retry_count,
            retry_max,
            retry_backoff_ns,
            replay_len,
            stash_len,
            resp_started,
            cur_up,
            timeout_tier_ns,
            timeout_state,
        ) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(false);
            };
            (
                conn.route_id,
                conn.split_hash,
                conn.retry_allowed,
                conn.retry_idempotent_only,
                conn.retry_count,
                conn.retry_max,
                conn.retry_backoff_ns,
                conn.replay_len,
                conn.stash_len,
                conn.resp_started,
                conn.upstream_id,
                conn.timeout_tier_ns,
                conn.timeout_state,
            )
        };

        if resp_started
            || (!retry_allowed && retry_idempotent_only)
            || retry_max == 0
            || retry_count >= retry_max
        {
            return Ok(false);
        }
        if replay_len == 0
            || replay_len as usize > STASH_CAP
            || replay_len as usize > self.bufs.buf_size()
        {
            return Ok(false);
        }
        if stash_len != 0 {
            return Ok(false);
        }

        let mut next_timeout_state = timeout_state;
        if let (Some(tier), Some(mut state)) = (timeout_tier_ns, next_timeout_state) {
            if state.total_expired(now) {
                self.queue_error_response(key, RESP_504)?;
                return Ok(true);
            }
            state.start_try(now, tier.per_try_ns);
            next_timeout_state = Some(state);
        }

        let Some(route) = self.active_cfg.routes.get(route_id as usize) else {
            return Ok(false);
        };

        let mut tried_local = [0usize; MAX_TRIED_UPSTREAMS];
        let tried_len = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(false);
            };
            let len = (conn.tried_len as usize).min(MAX_TRIED_UPSTREAMS);
            tried_local[..len].copy_from_slice(&conn.tried_upstreams[..len]);
            len
        };

        let attempt = retry_count + 1;
        let Some(next_up) = self.select_upstream_for_attempt(
            route_id,
            route,
            split_hash,
            attempt,
            &tried_local[..tried_len],
        ) else {
            return Ok(false);
        };

        self.mark_upstream_failure(cur_up);

        let mut release_closed_upstream = false;
        {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(false);
            };
            if conn.upstream_fd >= 0 {
                close_fd(conn.upstream_fd);
                release_closed_upstream = true;
            }
            if conn.upstream_fi >= 0 {
                let slot = conn.upstream_fi as u32;
                let _ = self.uring.update_files(slot, &[-1]);
                self.files.free_slot(slot);
            }
            conn.upstream_fd = -1;
            conn.upstream_fi = -1;
            conn.upstream_reused = false;
            conn.upstream_sa = None;

            let dst = self.bufs.ptr(conn.buf);
            unsafe { std::ptr::copy_nonoverlapping(conn.stash.as_ptr(), dst, replay_len as usize) }
            conn.buf_len = replay_len;
            conn.buf_off = 0;
            conn.upstream_id = next_up;
            conn.timeout_state = next_timeout_state;

            if (conn.tried_len as usize) < MAX_TRIED_UPSTREAMS {
                conn.tried_upstreams[conn.tried_len as usize] = next_up;
                conn.tried_len = conn.tried_len.saturating_add(1);
            }
            conn.retry_count = attempt;
            conn.resp_started = false;
        }
        if release_closed_upstream {
            self.upstream_release_connection_slot(cur_up);
        }

        let delay = if retry_backoff_ns == 0 {
            0
        } else {
            let cap = retry_backoff_ns
                .saturating_mul(1u64 << attempt.min(6))
                .min(5_000_000_000u64);
            let r =
                splitmix64(now ^ ((key.idx as u64) << 32) ^ (key.gen as u64) ^ (attempt as u64));
            r % cap.max(1)
        };

        if delay > 0 {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(false);
            };
            conn.state = ConnState::RetryBackoff;
            conn.retry_wakeup_ns = now.saturating_add(delay);
            conn.deadline_ns = if let Some(state) = conn.timeout_state.as_ref() {
                state.deadline_for_io(now, delay.max(1))
            } else {
                conn.retry_wakeup_ns
            };
            self.timeout_wheel.push(conn.deadline_ns, key);
            return Ok(true);
        }

        self.start_connect_upstream_new_socket(key)?;
        Ok(true)
    }

    /// Send a full H2 response directly on an extracted `DownstreamH2`.
    ///
    /// This path is used while `conn.h2_down` is temporarily moved out of `self.conns`.
    fn h2_send_full_response_on_down(
        &mut self,
        down: &mut DownstreamH2,
        sid: u32,
        status: u16,
        headers: Vec<H2Header>,
        body: &[u8],
    ) {
        if body.is_empty() {
            let _ = down.send_response_headers(sid, status, headers, true);
            return;
        }

        let Some(chain) = self.h2_body_to_chain(body) else {
            let _ = down.send_response_headers(sid, 503, vec![], true);
            return;
        };

        if down
            .send_response_headers(sid, status, headers, false)
            .is_err()
        {
            let mut ops = WorkerH2BufOps {
                bufs: &mut self.bufs,
            };
            let mut c = chain;
            c.release(&mut ops);
            return;
        }

        let mut ops = WorkerH2BufOps {
            bufs: &mut self.bufs,
        };
        let _ = down.send_response_data(sid, true, chain, None, &mut ops);
    }

    fn h2_maybe_resume_downstream_read(&mut self, down: H2ConnKey) -> Result<()> {
        let key = Key {
            idx: down.idx,
            gen: down.gen,
        };
        {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            if !conn.alpn_h2 || conn.tls.is_none() || conn.tls_read_in_flight {
                return Ok(());
            }
        }
        self.schedule_read_client_tls(key)?;
        Ok(())
    }

    fn h2_try_flush_downstream(&mut self, down: H2ConnKey) -> Result<()> {
        let key = Key {
            idx: down.idx,
            gen: down.gen,
        };
        let can_flush = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            conn.alpn_h2 && conn.tls.is_some() && !conn.tls_write_in_flight
        };
        if !can_flush {
            return Ok(());
        }

        if self.flush_h2_downstream_tx(key).is_err() {
            self.close_conn(key);
            return Ok(());
        }

        let wants_write = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false)
        };
        if wants_write {
            if self.flush_tls_write(key).is_err() {
                self.close_conn(key);
                return Ok(());
            }
        }

        self.h2_maybe_resume_downstream_read(down)
    }

    fn h2_fail_task(&mut self, task_key: Key, status: u16) -> Result<()> {
        let (down, sid, upstream_id, started_ns, access_log) = match self.h2_tasks.get_mut(task_key)
        {
            Some(task) => (
                task.down,
                task.sid,
                task.upstream_id,
                task.started_ns,
                task.access_log.take(),
            ),
            None => return Ok(()),
        };

        if status >= 500 {
            self.mark_upstream_failure(upstream_id);
        }
        self.h2_send_status_only(down, sid, status);
        Self::h2_emit_access_log_opt(access_log, status, started_ns);
        self.h2_cleanup_task(task_key);
        self.h2_try_flush_downstream(down)?;
        Ok(())
    }

    fn h2_schedule_task_connect(&mut self, task_key: Key) -> Result<()> {
        let (fi, sa_ptr, sa_len) = {
            let Some(task) = self.h2_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.state = H2H1TaskState::Connecting;
            let now = monotonic_nanos();
            task.deadline_ns = now.saturating_add(
                self.active_cfg
                    .timeouts_ms
                    .up_conn
                    .saturating_mul(1_000_000),
            );
            self.h2_timeout_wheel.push(task.deadline_ns, task_key);
            (
                task.upstream_fi,
                task.upstream_sa.as_ptr(),
                task.upstream_sa.len() as u32,
            )
        };

        let sq = sqe::connect(
            fi,
            true,
            sa_ptr,
            sa_len,
            op::pack(OpKind::Connect, Side::None, task_key.idx, task_key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push connect(h2 stream upstream)", e))?;
        Ok(())
    }

    fn h2_schedule_task_write(&mut self, task_key: Key, off: u32, len: u32) -> Result<()> {
        let (fi, io_buf) = {
            let Some(task) = self.h2_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.state = H2H1TaskState::WritingReq;
            let now = monotonic_nanos();
            task.deadline_ns = now.saturating_add(
                self.active_cfg
                    .timeouts_ms
                    .up_write
                    .saturating_mul(1_000_000),
            );
            self.h2_timeout_wheel.push(task.deadline_ns, task_key);
            (task.upstream_fi, task.io_buf)
        };

        let p = self.bufs.ptr_at(io_buf, off);
        let sq = sqe::write_fixed(
            fi,
            true,
            p as *const u8,
            len,
            io_buf,
            op::pack(OpKind::Write, Side::None, task_key.idx, task_key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push write(h2 stream upstream)", e))?;
        Ok(())
    }

    fn h2_schedule_task_read(&mut self, task_key: Key) -> Result<()> {
        let (fi, io_buf) = {
            let Some(task) = self.h2_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.state = H2H1TaskState::ReadingResp;
            // H2->H1 适配层在高并发下更需要快速失败，避免个别挂起回源占满任务槽位。
            let read_timeout_ms = self.active_cfg.timeouts_ms.up_read.min(10_000).max(1);
            let now = monotonic_nanos();
            task.deadline_ns = now.saturating_add(read_timeout_ms.saturating_mul(1_000_000));
            self.h2_timeout_wheel.push(task.deadline_ns, task_key);
            (task.upstream_fi, task.io_buf)
        };

        let p = self.bufs.ptr(io_buf);
        let sq = sqe::read_fixed(
            fi,
            true,
            p,
            self.bufs.buf_size() as u32,
            io_buf,
            op::pack(OpKind::Read, Side::None, task_key.idx, task_key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push read(h2 stream upstream)", e))?;
        Ok(())
    }

    fn h2_task_prepare_next_write_chunk(&mut self, task_key: Key) -> Result<bool> {
        let cap = self.bufs.buf_size();
        let (io_buf, chunk) = {
            let Some(task) = self.h2_tasks.get_mut(task_key) else {
                return Ok(false);
            };
            if task.req_sent >= task.req.len() {
                task.io_len = 0;
                task.io_off = 0;
                return Ok(false);
            }
            let end = (task.req_sent + cap).min(task.req.len());
            (task.io_buf, task.req[task.req_sent..end].to_vec())
        };

        let p = self.bufs.ptr(io_buf);
        unsafe {
            std::ptr::copy_nonoverlapping(chunk.as_ptr(), p, chunk.len());
        }

        let Some(task) = self.h2_tasks.get_mut(task_key) else {
            return Ok(false);
        };
        task.io_len = chunk.len() as u32;
        task.io_off = 0;
        Ok(true)
    }

    fn h2_task_try_build_response(
        &mut self,
        task_key: Key,
    ) -> std::result::Result<Option<(u16, Vec<H2Header>, Vec<u8>)>, H2H1RoundtripError> {
        let max_head = self.bufs.buf_size().saturating_mul(8).max(16 * 1024);
        let Some(task) = self.h2_tasks.get_mut(task_key) else {
            return Ok(None);
        };

        if task.head_end.is_none() {
            let Some(hend) = find_header_end(&task.resp) else {
                if task.resp.len() > max_head {
                    return Err(H2H1RoundtripError::Proto);
                }
                return Ok(None);
            };
            let head =
                parse_response_head(&task.resp, hend).map_err(|_| H2H1RoundtripError::Proto)?;
            task.status = head.status;
            task.resp_keepalive = head.keepalive;
            task.head_end = Some(hend);
            task.body_kind = Some(head.body);
            if let Some(log) = task.access_log.as_mut() {
                if log.upstream_response_ms.is_none() {
                    let base_ns = task.connect_done_ns.unwrap_or(task.started_ns);
                    log.upstream_response_ms = Some(
                        monotonic_nanos()
                            .saturating_sub(base_ns)
                            .saturating_div(1_000_000),
                    );
                }
            }
        }

        let hend = task.head_end.ok_or(H2H1RoundtripError::Proto)?;
        let body_kind = task.body_kind.ok_or(H2H1RoundtripError::Proto)?;
        let mut headers = Self::h2_parse_h1_response_headers(&task.resp[..hend]);
        let body_raw = &task.resp[hend..];

        let body = match body_kind {
            BodyKind::None => Vec::new(),
            BodyKind::ContentLength { remaining } => {
                let need = remaining as usize;
                if body_raw.len() < need {
                    if task.saw_eof {
                        return Err(H2H1RoundtripError::Proto);
                    }
                    return Ok(None);
                }
                body_raw[..need].to_vec()
            }
            BodyKind::Chunked(_) => match Self::h2_decode_chunked(body_raw)? {
                Some(decoded) => decoded,
                None => {
                    if task.saw_eof {
                        return Err(H2H1RoundtripError::Proto);
                    }
                    return Ok(None);
                }
            },
            BodyKind::UntilEof => {
                if !task.saw_eof {
                    return Ok(None);
                }
                body_raw.to_vec()
            }
        };

        headers.push(H2Header {
            name: Bytes::from_static(b"content-length"),
            value: Bytes::from(body.len().to_string()),
        });
        Self::apply_h2_response_header_muts(&mut headers, task.response_header_muts.as_ref());

        Ok(Some((task.status, headers, body)))
    }

    fn h2_spawn_h1_task(
        &mut self,
        down: H2ConnKey,
        sid: u32,
        upstream_id: usize,
        req: Vec<u8>,
        started_ns: u64,
        access_log: &mut Option<AccessLogSnapshot>,
        response_header_muts: Arc<[CompiledHeaderMutation]>,
    ) -> Result<()> {
        h2_log_timing(sid, "upstream_connect_or_reuse_start", started_ns);
        let Some(_up) = self.active_cfg.upstreams.get(upstream_id) else {
            return Err(ArcError::config(
                "invalid upstream id for h2 stream".to_string(),
            ));
        };
        let up_addr = self
            .upstream_runtime_addr(upstream_id)
            .ok_or_else(|| ArcError::config("invalid runtime upstream addr".to_string()))?;
        let now_ns = monotonic_nanos();
        let (reused_idle, upstream_fd, upstream_fi, connect_done_ns) =
            if let Some(idle) = self.checkout_idle_upstream(upstream_id, now_ns) {
                (true, idle.fd, idle.fi, Some(now_ns))
            } else {
                if !self.upstream_try_acquire_connection_slot(upstream_id) {
                    return Err(ArcError::internal("upstream max_connections reached"));
                }

                let upstream_fd = match net::create_client_socket(&up_addr) {
                    Ok(fd) => fd,
                    Err(e) => {
                        self.upstream_release_connection_slot(upstream_id);
                        return Err(ArcError::io("h2 stream socket", e));
                    }
                };
                if self.active_cfg.linger_ms > 0 {
                    let _ = net::set_linger(upstream_fd, self.active_cfg.linger_ms);
                }

                let up_slot = match self.files.alloc() {
                    Some(s) => s,
                    None => {
                        close_fd(upstream_fd);
                        self.upstream_release_connection_slot(upstream_id);
                        return Err(ArcError::internal(
                            "no fixed-file slot for h2 stream upstream",
                        ));
                    }
                };

                self.files.table[up_slot as usize] = upstream_fd;
                if let Err(e) = self.uring.update_files(up_slot, &[upstream_fd]) {
                    self.files.free_slot(up_slot);
                    close_fd(upstream_fd);
                    self.upstream_release_connection_slot(upstream_id);
                    return Err(ArcError::io("update_files(h2 stream upstream)", e));
                }
                (false, upstream_fd, up_slot as i32, None)
            };

        let io_buf = match self.bufs.alloc() {
            Some(b) => b,
            None => {
                if reused_idle {
                    self.drop_idle_upstream(IdleUpstream {
                        fd: upstream_fd,
                        fi: upstream_fi,
                        upstream_id,
                        ts_ns: now_ns,
                        watch_tag: 0,
                    });
                } else {
                    if upstream_fi >= 0 {
                        let slot = upstream_fi as u32;
                        let _ = self.uring.update_files(slot, &[-1]);
                        self.files.free_slot(slot);
                    }
                    if upstream_fd >= 0 {
                        close_fd(upstream_fd);
                        self.upstream_release_connection_slot(upstream_id);
                    }
                }
                return Err(ArcError::internal("no fixed buffer for h2 stream upstream"));
            }
        };

        let task_key = match self.h2_tasks.alloc() {
            Some(k) => k,
            None => {
                self.bufs.free(io_buf);
                if reused_idle {
                    self.drop_idle_upstream(IdleUpstream {
                        fd: upstream_fd,
                        fi: upstream_fi,
                        upstream_id,
                        ts_ns: now_ns,
                        watch_tag: 0,
                    });
                } else {
                    if upstream_fi >= 0 {
                        let slot = upstream_fi as u32;
                        let _ = self.uring.update_files(slot, &[-1]);
                        self.files.free_slot(slot);
                    }
                    if upstream_fd >= 0 {
                        close_fd(upstream_fd);
                        self.upstream_release_connection_slot(upstream_id);
                    }
                }
                return Err(ArcError::internal("h2 stream task slab exhausted"));
            }
        };

        if reused_idle {
            if let Some(log) = access_log.as_mut() {
                log.upstream_connect_ms = Some(0);
            }
        }

        let task = H2H1Task {
            down,
            sid,
            upstream_id,
            upstream_fd,
            upstream_fi,
            upstream_sa: net::SockAddr::from_socket_addr(&up_addr),
            io_buf,
            io_len: 0,
            io_off: 0,
            req,
            req_sent: 0,
            req_keepalive: true,
            resp_keepalive: false,
            resp: Vec::with_capacity(8192),
            status: 502,
            head_end: None,
            body_kind: None,
            saw_eof: false,
            state: if reused_idle {
                H2H1TaskState::WritingReq
            } else {
                H2H1TaskState::Connecting
            },
            deadline_ns: 0,
            started_ns,
            connect_done_ns,
            access_log: access_log.take(),
            response_header_muts,
        };
        unsafe {
            self.h2_tasks.write(task_key, task);
        }

        self.h2_tasks_by_down
            .entry(down)
            .or_default()
            .push(task_key);
        self.h2_down_pending_inc(down);

        if reused_idle {
            h2_log_timing(sid, "upstream_connect_or_reuse_done", started_ns);
            let schedule = if !self.h2_task_prepare_next_write_chunk(task_key)? {
                self.h2_schedule_task_read(task_key)
            } else {
                let len = match self.h2_tasks.get_mut(task_key) {
                    Some(task) => task.io_len,
                    None => return Ok(()),
                };
                self.h2_schedule_task_write(task_key, 0, len)
            };
            if let Err(e) = schedule {
                let _ = self.h2_fail_task(task_key, 503);
                return Err(e);
            }
            return Ok(());
        }

        if let Err(e) = self.h2_schedule_task_connect(task_key) {
            let _ = self.h2_fail_task(task_key, 503);
            return Err(e);
        }

        Ok(())
    }

    fn on_h2_task_connect(&mut self, task_key: Key, res: i32) -> Result<()> {
        let (fd, fi) = match self.h2_tasks.get_mut(task_key) {
            Some(task) => (task.upstream_fd, task.upstream_fi),
            None => return Ok(()),
        };

        if res < 0 {
            let cqe_err = -res;
            let so_error = socket_so_error(fd).unwrap_or(cqe_err);
            if should_retry_connect(res, so_error) {
                return self.h2_schedule_task_connect(task_key);
            }
            return self.h2_fail_task(task_key, 502);
        }

        let now = monotonic_nanos();
        let mut timing_log: Option<(u32, u64)> = None;
        if let Some(task) = self.h2_tasks.get_mut(task_key) {
            task.connect_done_ns = Some(now);
            if let Some(log) = task.access_log.as_mut() {
                log.upstream_connect_ms = Some(
                    now.saturating_sub(task.started_ns)
                        .saturating_div(1_000_000),
                );
            }
            timing_log = Some((task.sid, task.started_ns));
        }
        if let Some((sid, started_ns)) = timing_log {
            h2_log_timing(sid, "upstream_connect_or_reuse_done", started_ns);
        }

        let _ = fi;
        if !self.h2_task_prepare_next_write_chunk(task_key)? {
            return self.h2_schedule_task_read(task_key);
        }

        let len = match self.h2_tasks.get_mut(task_key) {
            Some(task) => task.io_len,
            None => return Ok(()),
        };
        self.h2_schedule_task_write(task_key, 0, len)
    }

    fn on_h2_task_write(&mut self, task_key: Key, res: i32) -> Result<()> {
        if res < 0 {
            let retry = is_retryable_io_error(Some(-res));
            if retry {
                let (off, len) = match self.h2_tasks.get_mut(task_key) {
                    Some(task) => (task.io_off, task.io_len.saturating_sub(task.io_off)),
                    None => return Ok(()),
                };
                if len > 0 {
                    return self.h2_schedule_task_write(task_key, off, len);
                }
            }
            return self.h2_fail_task(task_key, 502);
        }
        if res == 0 {
            return self.h2_fail_task(task_key, 502);
        }

        let wrote = res as u32;
        let mut need_continue_chunk = false;
        let mut need_next_chunk = false;
        let mut finished_req = false;
        let mut finished_req_log: Option<(u32, u64)> = None;
        let mut next_off = 0u32;
        let mut next_len = 0u32;
        {
            let Some(task) = self.h2_tasks.get_mut(task_key) else {
                return Ok(());
            };
            task.io_off = task.io_off.saturating_add(wrote);
            if task.io_off < task.io_len {
                need_continue_chunk = true;
                next_off = task.io_off;
                next_len = task.io_len.saturating_sub(task.io_off);
            } else {
                task.req_sent = task.req_sent.saturating_add(task.io_len as usize);
                task.io_off = 0;
                task.io_len = 0;
                if task.req_sent < task.req.len() {
                    need_next_chunk = true;
                } else {
                    finished_req = true;
                    finished_req_log = Some((task.sid, task.started_ns));
                }
            }
        }

        if need_continue_chunk {
            return self.h2_schedule_task_write(task_key, next_off, next_len);
        }

        if need_next_chunk {
            if !self.h2_task_prepare_next_write_chunk(task_key)? {
                return self.h2_schedule_task_read(task_key);
            }
            let len = match self.h2_tasks.get_mut(task_key) {
                Some(task) => task.io_len,
                None => return Ok(()),
            };
            return self.h2_schedule_task_write(task_key, 0, len);
        }

        if finished_req {
            if let Some((sid, started_ns)) = finished_req_log {
                h2_log_timing(sid, "upstream_request_sent", started_ns);
            }
            return self.h2_schedule_task_read(task_key);
        }

        Ok(())
    }

    fn on_h2_task_read(&mut self, task_key: Key, res: i32) -> Result<()> {
        if res < 0 {
            if is_retryable_io_error(Some(-res)) {
                return self.h2_schedule_task_read(task_key);
            }
            return self.h2_fail_task(task_key, 502);
        }

        if res == 0 {
            if let Some(task) = self.h2_tasks.get_mut(task_key) {
                task.saw_eof = true;
            }
        } else {
            let n = res as u32;
            let (io_buf, data_len) = match self.h2_tasks.get_mut(task_key) {
                Some(task) => (task.io_buf, n),
                None => return Ok(()),
            };
            let chunk = self.bufs.slice(io_buf, 0, data_len).to_vec();
            let too_large = {
                let Some(task) = self.h2_tasks.get_mut(task_key) else {
                    return Ok(());
                };
                if task.resp.len().saturating_add(chunk.len()) > 16 * 1024 * 1024 {
                    true
                } else {
                    task.resp.extend_from_slice(&chunk);
                    false
                }
            };
            if too_large {
                return self.h2_fail_task(task_key, 502);
            }
        }

        match self.h2_task_try_build_response(task_key) {
            Ok(Some((status, headers, body))) => {
                let (down, sid, upstream_id, started_ns, access_log) =
                    match self.h2_tasks.get_mut(task_key) {
                        Some(task) => (
                            task.down,
                            task.sid,
                            task.upstream_id,
                            task.started_ns,
                            task.access_log.take(),
                        ),
                        None => return Ok(()),
                    };
                self.mark_upstream_success(upstream_id);
                h2_log_timing(sid, "upstream_response_ready", started_ns);
                h2_log_timing(sid, "downstream_response_emit", started_ns);
                self.h2_send_full_response(down, sid, status, headers, body);
                Self::h2_emit_access_log_opt(access_log, status, started_ns);
                self.h2_cleanup_task(task_key);
                self.h2_try_flush_downstream(down)?;
                h2_log_timing(sid, "downstream_response_flushed", started_ns);
                Ok(())
            }
            Ok(None) => {
                if res == 0 {
                    self.h2_fail_task(task_key, 502)
                } else {
                    self.h2_schedule_task_read(task_key)
                }
            }
            Err(H2H1RoundtripError::Timeout) => self.h2_fail_task(task_key, 504),
            Err(_) => self.h2_fail_task(task_key, 502),
        }
    }

    fn h2_process_ready_requests(
        &mut self,
        down_key: Key,
        now_ns: u64,
        down: &mut DownstreamH2,
        collector: &mut H2RequestCollector,
    ) -> Result<()> {
        let h2_down_key = H2ConnKey::new(down_key.idx, down_key.gen);
        let (mut sni_tmp, mut sni_len, mut is_tls, mut peer_client_ip) =
            ([0u8; 256], 0usize, true, String::new());
        if let Some(conn) = self.conns.get_mut(down_key) {
            if let Some(h) = conn.sni_host.as_ref() {
                let n = (conn.sni_len as usize).min(256);
                sni_tmp[..n].copy_from_slice(&h[..n]);
                sni_len = n;
            }
            // Keep H2 matcher semantics aligned with real connection mode.
            // This lets h2c (cleartext H2) and TLS H2 share the same route matcher logic.
            is_tls = conn.tls.is_some();
            peer_client_ip = conn.client_ip.clone();
        }
        let sni = if sni_len > 0 {
            Some(&sni_tmp[..sni_len])
        } else {
            None
        };
        let access_log_enabled = self.access_log_hot_enabled;
        for (sid, head, body_parts) in collector.take_ready() {
            let started_ns = monotonic_nanos();
            h2_log_timing(sid, "downstream_request_ready", started_ns);
            let path = head.path.as_ref().map(|p| p.as_ref()).unwrap_or(b"/");
            let method = head.method.as_ref();

            let route_id = match self.select_route_h2(
                method,
                path,
                head.authority.as_ref().map(|v| v.as_ref()),
                &head.headers,
                sni,
                is_tls,
            ) {
                Ok(r) => r,
                Err(RouteSelectError::NotFound) => {
                    self.h2_release_body_parts(body_parts);
                    let _ = down.send_response_headers(sid, 404, vec![], true);
                    continue;
                }
                Err(RouteSelectError::Ambiguous) => {
                    self.h2_release_body_parts(body_parts);
                    let _ = down.send_response_headers(sid, 503, vec![], true);
                    continue;
                }
            };

            let inbound_traceparent = h2_header_value(&head.headers, b"traceparent")
                .and_then(|v| std::str::from_utf8(v).ok())
                .map(str::trim)
                .filter(|v| !v.is_empty());
            let trace_ctx = TraceContext::resolve_from_traceparent(inbound_traceparent);
            let traceparent = trace_ctx.to_traceparent();
            let method_for_log = if method.is_empty() { b"GET" } else { method };
            let host_for_log = head
                .authority
                .as_ref()
                .map(|v| v.as_ref())
                .or_else(|| h2_header_value(&head.headers, b"host"))
                .unwrap_or(b"");
            let route_name =
                String::from_utf8_lossy(self.active_cfg.routes[route_id as usize].path.as_ref())
                    .into_owned();
            let mut access_log = if access_log_enabled {
                Some(self.h2_make_access_log_snapshot(
                    down_key,
                    sid,
                    now_ns,
                    trace_ctx,
                    method_for_log,
                    path,
                    host_for_log,
                    route_name.as_str(),
                    "",
                    "",
                ))
            } else {
                None
            };

            let (
                limiter,
                rate_limit_policy,
                plugin_ids,
                action,
                response_header_muts,
                forwarded_for,
                real_ip_header,
                trusted_proxies,
            ) = {
                let route = &self.active_cfg.routes[route_id as usize];
                (
                    route.limiter.clone(),
                    route.rate_limit_policy,
                    route.plugin_ids.clone(),
                    route.action.clone(),
                    route.response_header_muts.clone(),
                    route.forwarded_for,
                    route.real_ip_header.clone(),
                    route.trusted_proxies.clone(),
                )
            };
            let request_id_cfg = self.active_cfg.request_id.clone();
            let request_id_from_client =
                h2_header_value(&head.headers, request_id_cfg.header.as_bytes())
                    .map(|v| String::from_utf8_lossy(v).trim().to_string())
                    .filter(|v| !v.is_empty());
            let request_id_decision = resolve_request_id_decision(
                peer_client_ip.as_str(),
                request_id_from_client,
                &request_id_cfg,
            );
            if let Some(log) = access_log.as_mut() {
                log.request_id = request_id_decision.value.clone();
            }
            let mut forwarded_identity = None;
            let client_ip_for_rl = if forwarded_for {
                let identity = resolve_forwarded_identity(
                    peer_client_ip.as_str(),
                    h2_header_value(&head.headers, b"x-forwarded-for"),
                    trusted_proxies.as_ref(),
                    real_ip_header.clone(),
                );
                let ip = identity.effective_client_ip.clone();
                forwarded_identity = Some(identity);
                ip
            } else {
                peer_client_ip.clone()
            };

            if !Self::allow_route_rate_limit(
                self.global_limiter.as_mut(),
                route_id,
                client_ip_for_rl.as_str(),
                rate_limit_policy,
                limiter.as_ref(),
                now_ns,
            ) {
                self.on_route_rate_limited(route_id, client_ip_for_rl.as_str(), now_ns);
                self.h2_release_body_parts(body_parts);
                let _ = down.send_response_headers(sid, 429, vec![], true);
                Self::h2_emit_access_log_opt(access_log.take(), 429, started_ns);
                continue;
            }

            if let Some(plugins) = self.plugins.as_mut() {
                let mut denied: Option<u16> = None;
                for pid in plugin_ids.iter().copied() {
                    let verdict =
                        plugins.exec_on_request(pid, arc_plugins::RequestView { method, path });
                    if !verdict.allowed {
                        denied = Some(verdict.deny_status.max(400));
                        break;
                    }
                }
                if let Some(code) = denied {
                    self.h2_release_body_parts(body_parts);
                    let _ = down.send_response_headers(sid, code, vec![], true);
                    Self::h2_emit_access_log_opt(access_log.take(), code, started_ns);
                    continue;
                }
            }

            if let RouteAction::Respond {
                status,
                h2_body,
                h2_headers,
                ..
            } = &action
            {
                self.h2_release_body_parts(body_parts);
                let headers: Vec<H2Header> = h2_headers
                    .iter()
                    .map(|(name, value)| H2Header {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect();
                if h2_body.is_empty() {
                    let _ = down.send_response_headers(sid, *status, headers, true);
                } else {
                    self.h2_send_full_response_on_down(down, sid, *status, headers, h2_body);
                }
                Self::h2_emit_access_log_opt(access_log.take(), *status, started_ns);
                continue;
            }

            let (upstream_id, forward_policy) = {
                let route = &self.active_cfg.routes[route_id as usize];
                let authority = head.authority.as_ref().map(|v| v.as_ref());
                let base_hash: u64 = match &route.upstreams {
                    RouteUpstreams::Split(split) => match &split.key {
                        CompiledSplitKey::Random => splitmix64(now_ns),
                        CompiledSplitKey::Path => fnv1a64(0xA1C3_5EED, path),
                        CompiledSplitKey::Host => fnv1a64(0xBADC_0FFE, authority.unwrap_or(b"")),
                        CompiledSplitKey::Header(name_lower) => {
                            let v =
                                h2_header_value(&head.headers, name_lower.as_ref()).unwrap_or(b"");
                            fnv1a64(0xC0FF_EE11, v)
                        }
                        CompiledSplitKey::Cookie(cookie_name) => {
                            let ck = h2_header_value(&head.headers, b"cookie").unwrap_or(b"");
                            let v = cookie_get(ck, cookie_name.as_ref()).unwrap_or(b"");
                            fnv1a64(0x0D15_EA5E, v)
                        }
                    },
                    _ => 0,
                };
                (
                    self.select_upstream_for_attempt(route_id, route, base_hash, 0, &[]),
                    route.forward.clone(),
                )
            };

            let Some(upstream_id) = upstream_id else {
                self.h2_release_body_parts(body_parts);
                let _ = down.send_response_headers(sid, 503, vec![], true);
                Self::h2_emit_access_log_opt(access_log.take(), 503, started_ns);
                continue;
            };
            let Some(upstream_addr) = self.upstream_runtime_addr(upstream_id) else {
                self.h2_release_body_parts(body_parts);
                let _ = down.send_response_headers(sid, 503, vec![], true);
                Self::h2_emit_access_log_opt(access_log.take(), 503, started_ns);
                continue;
            };

            if let Some(upstream) = self.active_cfg.upstreams.get(upstream_id) {
                if let Some(log) = access_log.as_mut() {
                    log.upstream = upstream.name.as_ref().to_string();
                    log.upstream_addr = upstream_addr.to_string();
                }
            }

            let body = match self.h2_collect_body_bytes(body_parts, 8 * 1024 * 1024) {
                Ok(v) => v,
                Err(_) => {
                    let _ = down.send_response_headers(sid, 413, vec![], true);
                    Self::h2_emit_access_log_opt(access_log.take(), 413, started_ns);
                    continue;
                }
            };

            let req = Self::h2_build_h1_request_with_policies(
                &head,
                &body,
                upstream_addr,
                &forward_policy,
                traceparent.as_str(),
                forwarded_identity.as_ref(),
                request_id_cfg.header.as_ref(),
                request_id_decision.value.as_str(),
                request_id_decision.force_set,
                request_id_decision.original.as_deref(),
            );
            if self
                .upstream_tls
                .get(upstream_id)
                .and_then(|v| v.as_ref())
                .is_some()
            {
                h2_log_timing(sid, "upstream_connect_or_reuse_start", started_ns);
                if !self.upstream_try_acquire_connection_slot(upstream_id) {
                    let _ = down.send_response_headers(sid, 503, vec![], true);
                    Self::h2_emit_access_log_opt(access_log.take(), 503, started_ns);
                    continue;
                }
                let roundtrip = self.h2_roundtrip_h1(upstream_id, upstream_addr, &req);
                self.upstream_release_connection_slot(upstream_id);
                match roundtrip {
                    Ok((status, mut headers, body, connect_ms, response_ms)) => {
                        self.mark_upstream_success(upstream_id);
                        Self::apply_h2_response_header_muts(
                            &mut headers,
                            response_header_muts.as_ref(),
                        );
                        if let Some(log) = access_log.as_mut() {
                            log.upstream_connect_ms = Some(connect_ms);
                            log.upstream_response_ms = response_ms;
                        }
                        h2_log_timing(sid, "upstream_response_ready", started_ns);
                        h2_log_timing(sid, "downstream_response_emit", started_ns);
                        self.h2_send_full_response_on_down(down, sid, status, headers, &body);
                        h2_log_timing(sid, "downstream_response_flushed", started_ns);
                        Self::h2_emit_access_log_opt(access_log.take(), status, started_ns);
                    }
                    Err(H2H1RoundtripError::Timeout) => {
                        self.mark_upstream_failure(upstream_id);
                        let _ = down.send_response_headers(sid, 504, vec![], true);
                        Self::h2_emit_access_log_opt(access_log.take(), 504, started_ns);
                    }
                    Err(_) => {
                        self.mark_upstream_failure(upstream_id);
                        let _ = down.send_response_headers(sid, 502, vec![], true);
                        Self::h2_emit_access_log_opt(access_log.take(), 502, started_ns);
                    }
                }
                continue;
            }
            match self.h2_spawn_or_queue_h1_task(
                h2_down_key,
                sid,
                upstream_id,
                req,
                started_ns,
                access_log,
                response_header_muts,
            ) {
                Ok(()) => {}
                Err(H2DispatchError::RefusedStream(access_log)) => {
                    match self.active_cfg.http2.overflow_action {
                        arc_config::Http2OverflowActionConfig::RstRefused => {
                            let _ = down.send_rst_stream(sid, H2Code::RefusedStream);
                        }
                    }
                    Self::h2_emit_access_log_opt(access_log, 503, started_ns);
                }
                Err(H2DispatchError::Failed(access_log)) => {
                    let _ = down.send_response_headers(sid, 503, vec![], true);
                    Self::h2_emit_access_log_opt(access_log, 503, started_ns);
                }
            }
        }
        Ok(())
    }

    fn tls_drain_plain_downstream(&mut self, key: Key) -> Result<u32> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(0);
        };
        let Some(tls) = conn.tls.as_mut() else {
            return Ok(0);
        };

        let cap = self.bufs.buf_size() as u32;
        let mut total: u32 = 0;
        loop {
            if conn.buf_len >= cap {
                break;
            }
            let dst_len = (cap - conn.buf_len) as usize;
            let p = self.bufs.ptr_at(conn.buf, conn.buf_len);
            let dst = unsafe { std::slice::from_raw_parts_mut(p as *mut u8, dst_len) };
            match tls.reader().read(dst) {
                Ok(0) => break,
                Ok(n) => {
                    conn.buf_len += n as u32;
                    total += n as u32;
                }
                Err(_) => break,
            }
        }
        Ok(total)
    }

    fn flush_tls_write(&mut self, key: Key) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        let Some(tls) = conn.tls.as_mut() else {
            return Ok(());
        };
        if conn.tls_wbuf == INVALID_BUF {
            self.close_conn(key);
            return Ok(());
        }
        if conn.tls_write_in_flight {
            return Ok(());
        }

        let cap = self.bufs.buf_size();
        let p = self.bufs.ptr(conn.tls_wbuf);
        let out = unsafe { std::slice::from_raw_parts_mut(p as *mut u8, cap) };
        let mut cur = std::io::Cursor::new(out);

        let n = tls
            .write_tls(&mut cur)
            .map_err(|_| ArcError::internal("tls write_tls"))?;
        if n == 0 {
            return Ok(());
        }

        conn.tls_out_off = 0;
        conn.tls_out_len = n as u32;
        conn.tls_write_in_flight = true;
        conn.in_flight = conn.in_flight.saturating_add(1);
        conn.phase = Phase::CliWrite;
        let now = monotonic_nanos();
        let timeout_ms = if tls.is_handshaking() {
            self.active_cfg.timeouts_ms.cli_handshake
        } else {
            self.active_cfg.timeouts_ms.cli_write
        };
        conn.deadline_ns = now.saturating_add(timeout_ms.saturating_mul(1_000_000));
        self.timeout_wheel.push(conn.deadline_ns, key);

        let sq = sqe::write_fixed(
            conn.client_fi,
            true,
            p as *const u8,
            conn.tls_out_len,
            conn.tls_wbuf,
            op::pack(OpKind::Write, Side::Client, key.idx, key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push tls write(client)", e))?;
        Ok(())
    }

    fn capture_tls_peer_info(conn: &mut Conn) {
        conn.alpn_h2 = false;
        if let Some(tls) = conn.tls.as_ref() {
            if let Some(alpn) = tls.alpn_protocol() {
                conn.alpn_h2 = alpn == b"h2";
            }
            if let Some(sni) = tls.server_name() {
                let s = sni.trim().trim_end_matches('.').to_ascii_lowercase();
                if !s.is_empty()
                    && s.len() <= 256
                    && !s
                        .as_bytes()
                        .iter()
                        .any(|b| b.is_ascii_whitespace() || *b == b'/')
                {
                    let mut buf = [0u8; 256];
                    buf[..s.len()].copy_from_slice(s.as_bytes());
                    conn.sni_host = Some(buf);
                    conn.sni_len = s.len() as u8;
                }
            }
        }
    }

    #[inline]
    fn schedule_connect_upstream(&mut self, key: Key, up_fi: i32) -> Result<()> {
        let (sa_ptr, sa_len) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            let Some(sa) = conn.upstream_sa.as_ref() else {
                self.queue_error_response(key, RESP_502)?;
                return Ok(());
            };
            conn.in_flight = conn.in_flight.saturating_add(1);
            conn.phase = Phase::UpConn;
            let now = monotonic_nanos();
            conn.deadline_ns = if let (Some(tier), Some(state)) =
                (conn.timeout_tier_ns, conn.timeout_state.as_ref())
            {
                state.deadline_for_connect(now, tier.connect_ns)
            } else {
                now.saturating_add(
                    self.active_cfg
                        .timeouts_ms
                        .up_conn
                        .saturating_mul(1_000_000),
                )
            };
            self.timeout_wheel.push(conn.deadline_ns, key);
            (sa.as_ptr(), sa.len() as u32)
        };

        let sq = sqe::connect(
            up_fi,
            true,
            sa_ptr,
            sa_len,
            op::pack(OpKind::Connect, Side::Upstream, key.idx, key.gen),
        );
        ring_push_blocking(&mut self.uring, sq).map_err(|e| ArcError::io("push connect", e))?;
        Ok(())
    }

    #[inline]
    fn schedule_write(
        &mut self,
        key: Key,
        side: Side,
        fd_fi: i32,
        off: u32,
        len: u32,
    ) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if conn.buf == INVALID_BUF {
            return Ok(());
        }
        conn.in_flight = conn.in_flight.saturating_add(1);

        let now = monotonic_nanos();
        match side {
            Side::Client => {
                conn.phase = Phase::CliWrite;
                conn.deadline_ns = now.saturating_add(
                    self.active_cfg
                        .timeouts_ms
                        .cli_write
                        .saturating_mul(1_000_000),
                );
                self.timeout_wheel.push(conn.deadline_ns, key);
            }
            Side::Upstream => {
                conn.phase = Phase::UpWrite;
                let op_ns = self
                    .active_cfg
                    .timeouts_ms
                    .up_write
                    .saturating_mul(1_000_000);
                conn.deadline_ns = if let (Some(_tier), Some(state)) =
                    (conn.timeout_tier_ns, conn.timeout_state.as_ref())
                {
                    state.deadline_for_io(now, op_ns)
                } else {
                    now.saturating_add(op_ns)
                };
                self.timeout_wheel.push(conn.deadline_ns, key);
            }
            Side::None => {}
        }

        let p = self.bufs.ptr_at(conn.buf, off);
        let sq = sqe::write_fixed(
            fd_fi,
            true,
            p as *const u8,
            len,
            conn.buf,
            op::pack(OpKind::Write, side, key.idx, key.gen),
        );
        ring_push_blocking(&mut self.uring, sq).map_err(|e| ArcError::io("push write", e))?;
        Ok(())
    }

    #[inline]
    fn schedule_client_write(&mut self, key: Key, len: u32) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if conn.buf == INVALID_BUF || conn.client_fi < 0 {
            self.close_conn(key);
            return Ok(());
        }
        if len == 0 {
            return Ok(());
        }

        if conn.tls.is_none() {
            let cli_fi = conn.client_fi;
            let _ = conn;
            return self.schedule_write(key, Side::Client, cli_fi, 0, len);
        }

        let plain = unsafe {
            std::slice::from_raw_parts(self.bufs.ptr(conn.buf) as *const u8, len as usize)
        };
        let Some(tls) = conn.tls.as_mut() else {
            self.close_conn(key);
            return Ok(());
        };
        if tls.writer().write_all(plain).is_err() {
            self.close_conn(key);
            return Ok(());
        }
        let _ = conn;
        self.flush_tls_write(key)
    }

    fn on_connect(&mut self, key: Key, res: i32) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.in_flight = conn.in_flight.saturating_sub(1);

        if res < 0 {
            let up_fd = conn.upstream_fd;
            let up_fi = conn.upstream_fi;
            let up_id = conn.upstream_id;
            let cqe_err = -res;
            let so_error = socket_so_error(up_fd).unwrap_or(cqe_err);

            // Connect is not ready yet: keep waiting by re-issuing connect.
            if should_retry_connect(res, so_error) {
                let _ = conn;
                let Some(up_addr) = self.upstream_runtime_addr(up_id) else {
                    self.queue_error_response(key, RESP_502)?;
                    return Ok(());
                };
                let Some(conn) = self.conns.get_mut(key) else {
                    return Ok(());
                };
                conn.upstream_sa = Some(net::SockAddr::from_socket_addr(&up_addr));
                let _ = conn;
                self.schedule_connect_upstream(key, up_fi)?;
                return Ok(());
            } else {
                let _ = conn;
                if self.maybe_retry_http1(key)? {
                    return Ok(());
                }
                self.mark_upstream_failure(up_id);
                self.queue_error_response(key, RESP_502)?;
                return Ok(());
            }
        }

        // connected: send buffered request bytes (buf_len)
        let now = monotonic_nanos();
        conn.upstream_connect_done_ns = now;
        if conn.request_started_ns > 0 {
            conn.upstream_connect_ms = Some(
                now.saturating_sub(conn.request_started_ns)
                    .saturating_div(1_000_000),
            );
        }
        conn.state = ConnState::UpWriteHeadAndMaybeBody;
        conn.buf_off = 0;
        conn.upstream_sa = None;

        let send_len = conn.buf_len;
        if send_len == 0 {
            self.queue_error_response(key, RESP_502)?;
            return Ok(());
        }

        let up_fi = conn.upstream_fi;
        let _ = conn;

        self.schedule_write(key, Side::Upstream, up_fi, 0, send_len)?;
        Ok(())
    }

    fn on_client_plaintext(
        &mut self,
        key: Key,
        now: u64,
        n: u32,
        already_buffered: bool,
    ) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };

        match conn.state {
            ConnState::CliReadHead => {
                if !already_buffered {
                    conn.buf_len = conn.buf_len.saturating_add(n);
                }

                // must find header end within buffer
                let cap = self.bufs.buf_size();
                if conn.buf_len as usize > cap {
                    self.queue_error_response(key, RESP_400)?;
                    return Ok(());
                }

                match Self::slowloris_on_header_bytes(self.slowloris_guard.as_ref(), conn, now, n) {
                    SlowlorisDecision::Allow => {}
                    decision => {
                        eprintln!(
                            "worker[{}] slowloris drop: ip={} reason={decision:?}",
                            self.id, conn.client_ip
                        );
                        let _ = conn;
                        self.queue_error_response(key, RESP_408)?;
                        return Ok(());
                    }
                }

                // If stash had bytes, they were pre-copied into buffer before read; header parse just uses [0..buf_len]
                let buf_slice = unsafe {
                    std::slice::from_raw_parts(
                        self.bufs.ptr(conn.buf) as *const u8,
                        conn.buf_len as usize,
                    )
                };

                let Some(hend) = find_header_end(buf_slice) else {
                    // need more
                    let cur_len = conn.buf_len;
                    let _ = conn;
                    self.schedule_client_read(key, cur_len)?;
                    return Ok(());
                };

                Self::slowloris_stop_tracking(self.slowloris_guard.as_ref(), conn);

                let head = match parse_request_head(buf_slice, hend) {
                    Ok(h) => h,
                    Err(_) => {
                        self.queue_error_response(key, RESP_400)?;
                        return Ok(());
                    }
                };
                let head_block = &buf_slice[..head.header_end];
                if http1_has_conflicting_cl_te(head_block) {
                    self.queue_error_response(key, RESP_400)?;
                    return Ok(());
                }
                let ws_upgrade_requested = http1_is_websocket_upgrade_request(head_block);
                let host = http1_header_value(head_block, b"host").unwrap_or(b"");
                let accept_encoding =
                    http1_header_value(head_block, b"accept-encoding").unwrap_or(b"");
                let (path_no_query, query) = split_path_query(head.path);
                let inbound_traceparent = http1_header_value(head_block, b"traceparent")
                    .and_then(|v| std::str::from_utf8(v).ok());
                let trace_ctx = TraceContext::resolve_from_traceparent(inbound_traceparent);
                let traceparent = trace_ctx.to_traceparent();

                // Capture SNI/TLS context for multi-dimension route selection.
                let is_tls = conn.tls.is_some();
                let mut sni_tmp = [0u8; 256];
                let mut sni_len = 0usize;
                if let Some(h) = conn.sni_host.as_ref() {
                    let n = (conn.sni_len as usize).min(256);
                    sni_tmp[..n].copy_from_slice(&h[..n]);
                    sni_len = n;
                }
                let sni = if sni_len > 0 {
                    Some(&sni_tmp[..sni_len])
                } else {
                    None
                };

                conn.header_end = head.header_end as u32;
                conn.resp_started = false;
                conn.split_hash = 0;
                conn.route_selected = false;
                conn.route_id = 0;
                conn.request_id =
                    splitmix64(now ^ ((key.idx as u64) << 32) ^ (key.gen as u64) ^ hend as u64);
                conn.request_id_text = generate_request_id(&self.active_cfg.request_id);
                conn.retry_count = 0;
                conn.retry_allowed = false;
                conn.tried_len = 0;
                conn.retry_wakeup_ns = 0;
                conn.retry_max = 0;
                conn.retry_backoff_ns = 0;
                conn.retry_idempotent_only = true;
                conn.error_page_hops = 0;
                conn.timeout_tier_ns = None;
                conn.timeout_state = None;
                conn.request_started_ns = now;
                conn.upstream_status = 0;
                conn.upstream_connect_ms = None;
                conn.upstream_response_ms = None;
                conn.upstream_connect_done_ns = 0;
                conn.log_active = self.access_log_hot_enabled;
                conn.log_trace_id = trace_ctx.trace_id_hex();
                conn.log_span_id = trace_ctx.span_id_hex();
                conn.log_traceparent = traceparent;
                conn.log_method = String::from_utf8_lossy(head.method).into_owned();
                conn.log_path = String::from_utf8_lossy(path_no_query).into_owned();
                conn.log_query = String::from_utf8_lossy(query).into_owned();
                conn.log_host = String::from_utf8_lossy(host).into_owned();
                conn.ws_upgrade_requested = ws_upgrade_requested;
                conn.ws_tunnel_active = false;
                conn.req_accept_encoding_len =
                    accept_encoding.len().min(REQ_ACCEPT_ENCODING_CAP) as u16;
                if conn.req_accept_encoding_len > 0 {
                    let n = conn.req_accept_encoding_len as usize;
                    conn.req_accept_encoding[..n].copy_from_slice(&accept_encoding[..n]);
                }
                if Self::compression_debug_enabled() {
                    let n = conn.req_accept_encoding_len as usize;
                    eprintln!(
                        "compress debug: request ae='{}' path='{}'",
                        String::from_utf8_lossy(&conn.req_accept_encoding[..n]),
                        String::from_utf8_lossy(head.path)
                    );
                }
                let peer_client_ip = conn.client_ip.clone();

                // Drop conn borrow before route/limit/plugin checks.
                let _ = conn;

                let route_id = match self.select_route_http1(
                    head.method,
                    head.path,
                    &buf_slice[..head.header_end],
                    sni,
                    is_tls,
                ) {
                    Ok(r) => r,
                    Err(RouteSelectError::NotFound) => {
                        self.queue_error_response(key, RESP_404)?;
                        return Ok(());
                    }
                    Err(RouteSelectError::Ambiguous) => {
                        self.queue_error_response(key, RESP_503)?;
                        return Ok(());
                    }
                };

                let (
                    limiter,
                    rate_limit_policy,
                    plugin_ids,
                    action,
                    forwarded_for,
                    real_ip_header,
                    trusted_proxies,
                ) = {
                    let route = &self.active_cfg.routes[route_id as usize];
                    (
                        route.limiter.clone(),
                        route.rate_limit_policy,
                        route.plugin_ids.clone(),
                        route.action.clone(),
                        route.forwarded_for,
                        route.real_ip_header.clone(),
                        route.trusted_proxies.clone(),
                    )
                };
                let mut forwarded_identity = None;
                let client_ip_for_rl = if forwarded_for {
                    let identity = resolve_forwarded_identity(
                        peer_client_ip.as_str(),
                        http1_header_value(&buf_slice[..head.header_end], b"x-forwarded-for"),
                        trusted_proxies.as_ref(),
                        real_ip_header.clone(),
                    );
                    let ip = identity.effective_client_ip.clone();
                    forwarded_identity = Some(identity);
                    ip
                } else {
                    peer_client_ip.clone()
                };
                if let Some(conn) = self.conns.get_mut(key) {
                    let decision = Self::slowloris_rebind_client_ip(
                        self.slowloris_guard.as_ref(),
                        conn,
                        client_ip_for_rl.as_str(),
                    );
                    if !matches!(decision, SlowlorisDecision::Allow) {
                        let _ = conn;
                        self.close_conn(key);
                        return Ok(());
                    }
                }

                // rate limit (global if enabled, otherwise fallback to local limiter)
                if !Self::allow_route_rate_limit(
                    self.global_limiter.as_mut(),
                    route_id,
                    client_ip_for_rl.as_str(),
                    rate_limit_policy,
                    limiter.as_ref(),
                    now,
                ) {
                    self.on_route_rate_limited(route_id, client_ip_for_rl.as_str(), now);
                    self.queue_error_response(key, RESP_429)?;
                    return Ok(());
                }

                // plugin chain
                if let Some(plugins) = self.plugins.as_mut() {
                    for pid in plugin_ids.iter().copied() {
                        let verdict = plugins.exec_on_request(
                            pid,
                            arc_plugins::RequestView {
                                method: head.method,
                                path: head.path,
                            },
                        );
                        if !verdict.allowed {
                            let resp = match verdict.deny_status {
                                503 => RESP_503,
                                429 => RESP_429,
                                404 => RESP_404,
                                400 => RESP_400,
                                502 => RESP_502,
                                504 => RESP_504,
                                _ => RESP_503,
                            };
                            self.queue_error_response(key, resp)?;
                            return Ok(());
                        }
                    }
                }

                if let RouteAction::Respond { http1_bytes, .. } = &action {
                    self.queue_error_response(key, http1_bytes.as_ref())?;
                    return Ok(());
                }

                // forward path: apply rewrite/header mutations first.
                self.http1_apply_rewrite_and_header_muts(key, route_id)?;
                let traceparent = {
                    let Some(conn) = self.conns.get_mut(key) else {
                        return Ok(());
                    };
                    conn.log_traceparent.clone()
                };
                if !traceparent.is_empty() {
                    self.http1_upsert_header(key, b"traceparent", traceparent.as_bytes())?;
                }
                if let Some(identity) = forwarded_identity.as_ref() {
                    self.http1_upsert_header(
                        key,
                        b"x-forwarded-for",
                        identity.x_forwarded_for.as_bytes(),
                    )?;
                    self.http1_upsert_header(
                        key,
                        identity.real_ip_header.as_bytes(),
                        identity.effective_client_ip.as_bytes(),
                    )?;
                }
                let request_id_cfg = self.active_cfg.request_id.clone();
                let request_id_from_client = {
                    let Some(conn) = self.conns.get_mut(key) else {
                        return Ok(());
                    };
                    if conn.buf == INVALID_BUF {
                        None
                    } else {
                        let head_block = unsafe {
                            std::slice::from_raw_parts(
                                self.bufs.ptr(conn.buf) as *const u8,
                                conn.header_end as usize,
                            )
                        };
                        http1_header_value(head_block, request_id_cfg.header.as_bytes())
                            .map(|v| String::from_utf8_lossy(v).trim().to_string())
                            .filter(|v| !v.is_empty())
                    }
                };
                let request_id_decision = resolve_request_id_decision(
                    peer_client_ip.as_str(),
                    request_id_from_client,
                    &request_id_cfg,
                );
                {
                    let Some(conn) = self.conns.get_mut(key) else {
                        return Ok(());
                    };
                    conn.request_id_text = request_id_decision.value.clone();
                }
                if request_id_decision.force_set {
                    self.http1_upsert_header(
                        key,
                        request_id_cfg.header.as_bytes(),
                        request_id_decision.value.as_bytes(),
                    )?;
                }
                if let Some(original) = request_id_decision.original.as_ref() {
                    self.http1_upsert_header(key, b"x-original-request-id", original.as_bytes())?;
                }
                self.http1_sanitize_framing_headers(key)?;

                let (split_hash, upstream_id, retry_policy_snapshot, retry_allowed, timeout_ctx) = {
                    let route = &self.active_cfg.routes[route_id as usize];
                    let (buf_id, header_end, buf_len) = {
                        let Some(conn) = self.conns.get_mut(key) else {
                            return Ok(());
                        };
                        (conn.buf, conn.header_end as usize, conn.buf_len as usize)
                    };

                    if buf_id == INVALID_BUF {
                        return Ok(());
                    }

                    let head_block = unsafe {
                        std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, header_end)
                    };
                    let req_buf = unsafe {
                        std::slice::from_raw_parts(self.bufs.ptr(buf_id) as *const u8, buf_len)
                    };

                    let h = self.compute_split_hash_http1(route, head_block, req_buf);
                    let rp = route.forward.retry.clone();
                    let method = http1_parse_req_line(req_buf).map(|(m, _)| m).unwrap_or(b"");
                    let allowed = !rp.idempotent_only || is_idempotent_method(method);
                    let up = self.select_upstream_for_attempt(route_id, route, h, 0, &[]);
                    let timeout_ctx = self.resolve_route_timeout_http1(route, head_block, now);
                    (h, up, rp, allowed, timeout_ctx)
                };

                let Some(upstream_id) = upstream_id else {
                    self.queue_error_response(key, RESP_503)?;
                    return Ok(());
                };
                let up_addr = match self.upstream_runtime_addr(upstream_id) {
                    Some(v) => v,
                    None => {
                        self.queue_error_response(key, RESP_502)?;
                        return Ok(());
                    }
                };

                let Some(conn) = self.conns.get_mut(key) else {
                    return Ok(());
                };

                conn.route_selected = true;
                conn.route_id = route_id;
                conn.request_id =
                    splitmix64(now ^ ((key.idx as u64) << 32) ^ (key.gen as u64) ^ route_id as u64);
                conn.error_page_hops = 0;
                conn.upstream_id = upstream_id;
                conn.req_keepalive = head.keepalive;
                conn.up_write_retries = 0;
                conn.resp_started = false;
                conn.split_hash = split_hash;
                conn.retry_max = retry_policy_snapshot.max_retries;
                conn.retry_backoff_ns = retry_policy_snapshot.backoff_ns;
                conn.retry_idempotent_only = retry_policy_snapshot.idempotent_only;
                conn.retry_count = 0;
                conn.retry_allowed = retry_allowed;
                conn.tried_len = 0;
                conn.retry_wakeup_ns = 0;
                conn.tried_upstreams[0] = upstream_id;
                conn.tried_len = 1;
                conn.request_started_ns = now;
                conn.upstream_status = 0;
                conn.upstream_connect_ms = None;
                conn.upstream_response_ms = None;
                conn.upstream_connect_done_ns = 0;
                if let Some((tier, state)) = timeout_ctx {
                    conn.timeout_tier_ns = Some(tier);
                    conn.timeout_state = Some(state);
                } else {
                    conn.timeout_tier_ns = None;
                    conn.timeout_state = None;
                }
                let req_body_limit =
                    self.active_cfg.routes[route_id as usize].max_request_body_bytes as u64;
                conn.req_body_limit_bytes = req_body_limit;
                conn.req_body_received_bytes = 0;
                if let BodyKind::ContentLength { remaining } = head.body {
                    if remaining > req_body_limit {
                        self.queue_error_response(key, RESP_413)?;
                        return Ok(());
                    }
                }

                // Determine request body state; also compute how many bytes belong to this request within current buffer
                conn.req_body = HttpBodyState::from_kind(head.body);

                // We will forward the entire buffer up to (header + body-framing-consumed); may stash tail.
                let total_in_buf = conn.buf_len as usize;
                let header_end = conn.header_end as usize;
                let cur_buf_slice = unsafe {
                    std::slice::from_raw_parts(self.bufs.ptr(conn.buf) as *const u8, total_in_buf)
                };

                // header bytes always belong to current request
                let mut send_len = total_in_buf;

                if header_end > total_in_buf {
                    self.queue_error_response(key, RESP_400)?;
                    return Ok(());
                }

                let body_bytes = &cur_buf_slice[header_end..total_in_buf];

                // Decide request boundary for this buffer (for pipelining tail)
                let boundary = match &mut conn.req_body {
                    HttpBodyState::None => header_end,
                    HttpBodyState::ContentLength { remaining } => {
                        // remaining already includes all body, but we haven't consumed the bytes in buffer yet.
                        // We need to "consume" the body bytes in this buffer up to remaining.
                        let take = (*remaining as usize).min(body_bytes.len());
                        let new_seen = conn.req_body_received_bytes.saturating_add(take as u64);
                        if new_seen > conn.req_body_limit_bytes {
                            self.queue_error_response(key, RESP_413)?;
                            return Ok(());
                        }
                        conn.req_body_received_bytes = new_seen;
                        *remaining -= take as u64;
                        if *remaining == 0 {
                            conn.req_body = HttpBodyState::None;
                        }
                        header_end + take
                    }
                    HttpBodyState::Chunked(st) => {
                        let r = st.consume(body_bytes);
                        if r.error {
                            self.queue_error_response(key, RESP_400)?;
                            return Ok(());
                        }
                        let new_seen = conn
                            .req_body_received_bytes
                            .saturating_add(r.data_bytes as u64);
                        if new_seen > conn.req_body_limit_bytes {
                            self.queue_error_response(key, RESP_413)?;
                            return Ok(());
                        }
                        conn.req_body_received_bytes = new_seen;
                        if r.done {
                            conn.req_body = HttpBodyState::None;
                        }
                        header_end + r.consumed
                    }
                    HttpBodyState::UntilEof => {
                        // request UntilEof is not valid
                        self.queue_error_response(key, RESP_400)?;
                        return Ok(());
                    }
                };

                if boundary < total_in_buf {
                    // stash tail (pipelining)
                    let tail = total_in_buf - boundary;
                    if tail <= STASH_CAP {
                        conn.stash[..tail].copy_from_slice(&cur_buf_slice[boundary..total_in_buf]);
                        conn.stash_len = tail as u32;
                    } else {
                        // too much pipelining; fail-safe close
                        conn.stash_len = 0;
                    }
                    send_len = boundary;
                    conn.buf_len = send_len as u32;
                }

                conn.replay_len = 0;
                if conn.req_body.is_done()
                    && conn.stash_len == 0
                    && send_len > 0
                    && send_len <= STASH_CAP
                    && send_len <= self.bufs.buf_size()
                {
                    conn.stash[..send_len].copy_from_slice(&cur_buf_slice[..send_len]);
                    conn.replay_len = send_len as u32;
                }

                // upstream mTLS async path
                let up_id = upstream_id;
                if self
                    .upstream_tls
                    .get(up_id)
                    .and_then(|v| v.as_ref())
                    .is_some()
                {
                    if Self::upstream_tls_debug_enabled() {
                        eprintln!(
                            "[arc][upstream_tls] h1_fast_path selected up_id={} send_len={} stash_len={} req_done={}",
                            up_id,
                            send_len,
                            conn.stash_len,
                            conn.req_body.is_done()
                        );
                    }
                    if !conn.req_body.is_done() || conn.stash_len != 0 {
                        self.queue_error_response(key, RESP_502)?;
                        return Ok(());
                    }
                    let req = cur_buf_slice[..send_len].to_vec();
                    let _ = conn;
                    self.up_mtls_spawn_task(key, up_id, &req)?;
                    return Ok(());
                }

                // upstream connect or reuse
                let _ = conn;
                if let Some(idle) = self.checkout_idle_upstream(up_id, now) {
                    let Some(conn) = self.conns.get_mut(key) else {
                        self.drop_idle_upstream(idle);
                        return Ok(());
                    };
                    // reuse
                    conn.upstream_fd = idle.fd;
                    conn.upstream_fi = idle.fi;
                    conn.upstream_reused = true;
                    conn.upstream_connect_done_ns = conn.request_started_ns;
                    conn.upstream_connect_ms = Some(0);
                    conn.upstream_sa = None;
                    conn.state = ConnState::UpWriteHeadAndMaybeBody;
                    conn.phase = Phase::UpWrite;
                    conn.deadline_ns = now.saturating_add(
                        self.active_cfg
                            .timeouts_ms
                            .up_write
                            .saturating_mul(1_000_000),
                    );
                    conn.buf_off = 0;

                    let up_fi = conn.upstream_fi;
                    let _ = conn;

                    self.schedule_write(key, Side::Upstream, up_fi, 0, send_len as u32)?;
                    return Ok(());
                }

                if !self.upstream_try_acquire_connection_slot(upstream_id) {
                    self.queue_error_response(key, RESP_503)?;
                    return Ok(());
                }
                let up_fd = match net::create_client_socket(&up_addr) {
                    Ok(fd) => fd,
                    Err(_) => {
                        self.upstream_release_connection_slot(upstream_id);
                        self.queue_error_response(key, RESP_502)?;
                        return Ok(());
                    }
                };
                if self.active_cfg.linger_ms > 0 {
                    let _ = net::set_linger(up_fd, self.active_cfg.linger_ms);
                }

                let up_slot = match self.files.alloc() {
                    Some(s) => s,
                    None => {
                        close_fd(up_fd);
                        self.upstream_release_connection_slot(upstream_id);
                        self.queue_error_response(key, RESP_502)?;
                        return Ok(());
                    }
                };

                self.files.table[up_slot as usize] = up_fd;
                if let Err(e) = self.uring.update_files(up_slot, &[up_fd]) {
                    self.files.free_slot(up_slot);
                    close_fd(up_fd);
                    self.upstream_release_connection_slot(upstream_id);
                    self.queue_error_response(key, RESP_502)?;
                    eprintln!("worker[{}] update_files(upstream) failed: {e}", self.id);
                    return Ok(());
                }

                let Some(conn) = self.conns.get_mut(key) else {
                    let _ = self.uring.update_files(up_slot, &[-1]);
                    self.files.free_slot(up_slot);
                    close_fd(up_fd);
                    self.upstream_release_connection_slot(upstream_id);
                    return Ok(());
                };
                conn.upstream_fd = up_fd;
                conn.upstream_fi = up_slot as i32;
                conn.upstream_reused = false;
                conn.state = ConnState::UpConnecting;
                conn.upstream_sa = Some(net::SockAddr::from_socket_addr(&up_addr));

                // connect via io_uring
                let up_fi = conn.upstream_fi;
                let _ = conn;

                self.schedule_connect_upstream(key, up_fi)?;
                Ok(())
            }
            ConnState::CliReadBody => {
                conn.replay_len = 0;
                if !already_buffered {
                    conn.buf_len = n;
                }
                conn.buf_off = 0;

                // determine send_len based on remaining body framing
                let buf_slice = unsafe {
                    std::slice::from_raw_parts(
                        self.bufs.ptr(conn.buf) as *const u8,
                        conn.buf_len as usize,
                    )
                };

                let r = conn.req_body.consume(buf_slice);
                if r.error {
                    self.queue_error_response(key, RESP_400)?;
                    return Ok(());
                }
                let new_seen = conn
                    .req_body_received_bytes
                    .saturating_add(r.data_bytes as u64);
                if new_seen > conn.req_body_limit_bytes {
                    self.queue_error_response(key, RESP_413)?;
                    return Ok(());
                }
                conn.req_body_received_bytes = new_seen;

                let send_len = r.consumed;
                if r.done && send_len < buf_slice.len() {
                    // stash tail
                    let tail = buf_slice.len() - send_len;
                    if tail <= STASH_CAP {
                        conn.stash[..tail].copy_from_slice(&buf_slice[send_len..]);
                        conn.stash_len = tail as u32;
                    } else {
                        conn.stash_len = 0;
                    }
                }

                conn.buf_len = send_len as u32;

                // write to upstream
                let up_fi = conn.upstream_fi;
                conn.state = ConnState::UpWriteHeadAndMaybeBody; // reuse as "writing request chunk"
                let _ = conn;

                if send_len > 0 {
                    self.schedule_write(key, Side::Upstream, up_fi, 0, send_len as u32)?;
                } else {
                    // no bytes to send; request body done => start response read
                    self.start_up_read_head(key)?;
                }
                Ok(())
            }
            _ => {
                // unexpected client read
                self.close_conn(key);
                Ok(())
            }
        }
    }

    fn on_read(&mut self, key: Key, side: Side, res: i32) -> Result<()> {
        let now = monotonic_nanos();
        if side == Side::Client && self.has_down_tls(key) {
            return self.on_read_client_tls(key, res);
        }

        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.in_flight = conn.in_flight.saturating_sub(1);

        if res < 0 {
            // IO error
            let err = -res;
            match side {
                Side::Client => {
                    if conn.ws_tunnel_active {
                        let _ = conn;
                        self.close_conn(key);
                        return Ok(());
                    }
                    let _ = conn;
                    if is_retryable_io_error(Some(err)) {
                        self.schedule_read_client(key, 0)?;
                    } else {
                        self.close_conn(key);
                    }
                }
                Side::Upstream => {
                    if conn.ws_tunnel_active {
                        let _ = conn;
                        self.close_conn(key);
                        return Ok(());
                    }
                    let up_id = conn.upstream_id;
                    if is_retryable_io_error(Some(err)) {
                        let off = if matches!(conn.state, ConnState::UpReadHead) {
                            conn.buf_len
                        } else {
                            0
                        };
                        let _ = conn;
                        self.schedule_read_upstream(key, off)?;
                        return Ok(());
                    }
                    let _ = conn;
                    if self.maybe_retry_http1(key)? {
                        return Ok(());
                    }
                    self.mark_upstream_failure(up_id);
                    self.queue_error_response(key, RESP_502)?;
                }
                Side::None => self.close_conn(key),
            }
            return Ok(());
        }

        if res == 0 {
            // EOF
            match side {
                Side::Client => {
                    // client closed
                    self.close_conn(key);
                }
                Side::Upstream => {
                    if conn.ws_tunnel_active {
                        let _ = conn;
                        self.close_conn(key);
                        return Ok(());
                    }
                    let up_id = conn.upstream_id;
                    // upstream EOF: if body is UntilEof, response done, else error
                    if matches!(conn.resp_body, HttpBodyState::UntilEof) {
                        conn.resp_body = HttpBodyState::None;
                        // response complete -> decide keepalive
                        self.finish_response_and_maybe_keepalive(key);
                    } else {
                        let _ = conn;
                        if self.maybe_retry_http1(key)? {
                            return Ok(());
                        }
                        self.mark_upstream_failure(up_id);
                        self.queue_error_response(key, RESP_502)?;
                    }
                }
                Side::None => self.close_conn(key),
            }
            return Ok(());
        }

        let n = res as u32;

        match side {
            Side::Client => {
                self.metrics
                    .bytes_cli_in
                    .fetch_add(n as u64, Ordering::Relaxed);
                if matches!(conn.state, ConnState::WsTunnelReadClient) {
                    let _ = conn;
                    return self.ws_forward_client_to_upstream(key, n);
                }
                let _ = conn;
                self.on_client_plaintext(key, now, n, false)
            }

            Side::Upstream => {
                self.metrics
                    .bytes_up_in
                    .fetch_add(n as u64, Ordering::Relaxed);
                conn.resp_started = true;

                match conn.state {
                    ConnState::WsTunnelReadUpstream => {
                        let _ = conn;
                        self.ws_forward_upstream_to_client(key, n)?;
                        return Ok(());
                    }
                    ConnState::UpReadHead => {
                        conn.buf_len = conn.buf_len.saturating_add(n);

                        let cap = self.bufs.buf_size();
                        if conn.buf_len as usize > cap {
                            self.queue_error_response(key, RESP_502)?;
                            return Ok(());
                        }

                        let buf_slice = unsafe {
                            std::slice::from_raw_parts(
                                self.bufs.ptr(conn.buf) as *const u8,
                                conn.buf_len as usize,
                            )
                        };

                        let Some(hend) = find_header_end(buf_slice) else {
                            // need more upstream header
                            let cur_len = conn.buf_len;
                            let _ = conn;
                            self.schedule_read_upstream(key, cur_len)?;
                            return Ok(());
                        };

                        let head = match parse_response_head(buf_slice, hend) {
                            Ok(h) => h,
                            Err(_) => {
                                self.queue_error_response(key, RESP_502)?;
                                return Ok(());
                            }
                        };

                        let upstream_status = head.status;
                        if conn.upstream_response_ms.is_none() {
                            let base_ns = if conn.upstream_connect_done_ns > 0 {
                                conn.upstream_connect_done_ns
                            } else {
                                conn.request_started_ns
                            };
                            if base_ns > 0 {
                                conn.upstream_response_ms =
                                    Some(now.saturating_sub(base_ns).saturating_div(1_000_000));
                            }
                        }
                        let ws_switching = conn.ws_upgrade_requested
                            && upstream_status == 101
                            && http1_is_websocket_upgrade_response(&buf_slice[..head.header_end]);
                        conn.upstream_status = upstream_status;
                        let _ = conn;
                        if self.apply_error_page_policy(
                            key,
                            upstream_status,
                            ErrorResponseSource::Upstream,
                        )? {
                            return Ok(());
                        }
                        let Some(conn) = self.conns.get_mut(key) else {
                            return Ok(());
                        };

                        if ws_switching {
                            conn.ws_tunnel_active = true;
                            conn.req_keepalive = false;
                            conn.resp_keepalive = false;
                            conn.req_body = HttpBodyState::None;
                            conn.resp_body = HttpBodyState::None;
                            conn.resp_compressed = false;
                            conn.resp_compress_alg = Algorithm::Identity;
                            conn.resp_compress_level = 0;
                            conn.resp_compressor = None;
                            conn.header_end = head.header_end as u32;
                            conn.state = ConnState::WsTunnelWriteClient;
                            conn.buf_off = 0;
                            conn.buf_len = buf_slice.len() as u32;
                            let send_len = conn.buf_len;
                            let _ = conn;
                            self.schedule_client_write(key, send_len)?;
                            return Ok(());
                        }

                        conn.resp_body = HttpBodyState::from_kind(head.body);
                        conn.resp_compressed = false;
                        conn.resp_compress_alg = Algorithm::Identity;
                        conn.resp_compress_level = 0;
                        conn.resp_compressor = None;
                        conn.header_end = head.header_end as u32;

                        // Mirror the old stable logic: bytes after response boundary must not be
                        // blindly forwarded as current response body.
                        let total_in_buf = buf_slice.len();
                        let header_end = head.header_end;
                        if header_end > total_in_buf {
                            self.queue_error_response(key, RESP_502)?;
                            return Ok(());
                        }
                        let body_bytes = &buf_slice[header_end..];
                        let mut send_len = match &mut conn.resp_body {
                            HttpBodyState::None => header_end,
                            HttpBodyState::ContentLength { remaining } => {
                                let take = (*remaining as usize).min(body_bytes.len());
                                *remaining -= take as u64;
                                if *remaining == 0 {
                                    conn.resp_body = HttpBodyState::None;
                                }
                                header_end + take
                            }
                            HttpBodyState::Chunked(st) => {
                                let r = st.consume(body_bytes);
                                if r.error {
                                    self.queue_error_response(key, RESP_502)?;
                                    return Ok(());
                                }
                                if r.done {
                                    conn.resp_body = HttpBodyState::None;
                                }
                                header_end + r.consumed
                            }
                            HttpBodyState::UntilEof => {
                                // close-delimited response; done on upstream EOF.
                                total_in_buf
                            }
                        };

                        if send_len == header_end
                            && conn.req_accept_encoding_len > 0
                            && matches!(
                                &conn.resp_body,
                                HttpBodyState::ContentLength { remaining } if *remaining > 0
                            )
                            && (conn.buf_len as usize) < cap
                        {
                            let cur_len = conn.buf_len;
                            let _ = conn;
                            self.schedule_read_upstream(key, cur_len)?;
                            return Ok(());
                        }

                        let route_id_for_resp = conn.route_id;
                        let _ = conn;
                        let mut compressed_applied = false;
                        if let Some(new_len) = self.try_start_http1_stream_compression_in_place(
                            key,
                            upstream_status,
                            header_end,
                            send_len,
                        )? {
                            send_len = new_len;
                            compressed_applied = true;
                        }
                        let Some(conn) = self.conns.get_mut(key) else {
                            return Ok(());
                        };
                        let _ = conn;
                        let Some(new_len) = self.http1_apply_response_header_muts(
                            key,
                            route_id_for_resp,
                            send_len,
                        )?
                        else {
                            return Ok(());
                        };
                        send_len = new_len;
                        let Some(conn) = self.conns.get_mut(key) else {
                            return Ok(());
                        };
                        let cur_slice = unsafe {
                            std::slice::from_raw_parts(
                                self.bufs.ptr(conn.buf) as *const u8,
                                send_len,
                            )
                        };
                        let Some(header_end_now) = find_header_end(cur_slice) else {
                            self.queue_error_response(key, RESP_502)?;
                            return Ok(());
                        };

                        let mut injected_keepalive = false;
                        if !compressed_applied
                            && conn.req_keepalive
                            && !head.keepalive
                            && !matches!(head.body, BodyKind::UntilEof)
                            && send_len >= header_end_now
                        {
                            let head_block = &cur_slice[..header_end_now];
                            if !has_connection_header(head_block) {
                                const KEEPALIVE_HEADER: &[u8] = b"Connection: keep-alive\r\n";
                                let term_len = header_terminator_len(head_block);
                                if term_len > 0
                                    && send_len.saturating_add(KEEPALIVE_HEADER.len()) <= cap
                                {
                                    let insert_at = header_end_now - (term_len / 2);
                                    let p = self.bufs.ptr(conn.buf);
                                    unsafe {
                                        std::ptr::copy(
                                            p.add(insert_at),
                                            p.add(insert_at + KEEPALIVE_HEADER.len()),
                                            send_len - insert_at,
                                        );
                                        std::ptr::copy_nonoverlapping(
                                            KEEPALIVE_HEADER.as_ptr(),
                                            p.add(insert_at),
                                            KEEPALIVE_HEADER.len(),
                                        );
                                    }
                                    send_len = send_len.saturating_add(KEEPALIVE_HEADER.len());
                                    injected_keepalive = true;
                                }
                            }
                        }

                        // Upstream sent bytes beyond one response boundary in a single read.
                        // Keep serving current response but disable keepalive reuse to avoid desync.
                        if compressed_applied {
                            conn.resp_keepalive = head.keepalive;
                        } else if send_len < total_in_buf {
                            conn.resp_keepalive = false;
                        } else {
                            conn.resp_keepalive = head.keepalive || injected_keepalive;
                        }

                        conn.state = ConnState::CliWriteHeadAndMaybeBody;
                        conn.buf_off = 0;
                        conn.buf_len = send_len as u32;

                        if send_len > 0 {
                            let _ = conn;
                            self.schedule_client_write(key, send_len as u32)?;
                        } else {
                            let _ = conn;
                            self.finish_response_and_maybe_keepalive(key);
                        }
                        return Ok(());
                    }

                    ConnState::UpReadBody => {
                        conn.buf_len = n;
                        conn.buf_off = 0;

                        let buf_slice = unsafe {
                            std::slice::from_raw_parts(
                                self.bufs.ptr(conn.buf) as *const u8,
                                conn.buf_len as usize,
                            )
                        };

                        let r = conn.resp_body.consume(buf_slice);
                        if r.error {
                            self.queue_error_response(key, RESP_502)?;
                            return Ok(());
                        }

                        // For UntilEof: we forward all bytes; done happens on EOF, handled earlier.
                        let send_len_plain = if matches!(conn.resp_body, HttpBodyState::UntilEof) {
                            buf_slice.len()
                        } else {
                            r.consumed
                        };
                        if r.done && send_len_plain < buf_slice.len() {
                            // Defensive: avoid reusing a potentially desynced upstream stream.
                            conn.resp_keepalive = false;
                        }

                        let mut send_len = send_len_plain;
                        if conn.resp_compressed {
                            if matches!(conn.resp_body, HttpBodyState::UntilEof) {
                                let _ = conn;
                                self.queue_error_response(key, RESP_502)?;
                                return Ok(());
                            }

                            let plain = &buf_slice[..send_len_plain];
                            let mut compressed = Vec::with_capacity(
                                plain.len().saturating_div(2).saturating_add(128),
                            );
                            let flush_mode = if r.done {
                                FlushMode::Finish
                            } else {
                                FlushMode::None
                            };
                            let mut compress_ok = false;
                            if let Some(comp) = conn.resp_compressor.as_mut() {
                                compress_ok =
                                    comp.compress(plain, flush_mode, &mut compressed).is_ok();
                            }
                            if !compress_ok {
                                let alg = conn.resp_compress_alg;
                                let lv = conn.resp_compress_level;
                                conn.resp_compressor = None;
                                let mut recovered = match self.compression_pools.acquire(alg, lv) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        let _ = conn;
                                        self.queue_error_response(key, RESP_502)?;
                                        return Ok(());
                                    }
                                };
                                if recovered
                                    .compress(plain, flush_mode, &mut compressed)
                                    .is_err()
                                {
                                    let _ = conn;
                                    self.queue_error_response(key, RESP_502)?;
                                    return Ok(());
                                }
                                conn.resp_compressor = Some(recovered);
                            }

                            let mut out = Vec::with_capacity(compressed.len().saturating_add(32));
                            encode_chunked(compressed.as_slice(), &mut out);
                            if r.done {
                                encode_chunked_end(&mut out);
                                conn.resp_compressor = None;
                                conn.resp_compressed = false;
                                conn.resp_compress_alg = Algorithm::Identity;
                                conn.resp_compress_level = 0;
                            }
                            if out.len() > self.bufs.buf_size() {
                                let _ = conn;
                                self.queue_error_response(key, RESP_502)?;
                                return Ok(());
                            }

                            let p = self.bufs.ptr(conn.buf);
                            unsafe {
                                std::ptr::copy_nonoverlapping(out.as_ptr(), p, out.len());
                            }
                            send_len = out.len();
                        }

                        if send_len == 0 && !r.done {
                            conn.state = ConnState::UpReadBody;
                            let _ = conn;
                            self.schedule_read_upstream(key, 0)?;
                            return Ok(());
                        }

                        conn.buf_len = send_len as u32;
                        conn.state = ConnState::CliWriteBody;

                        if send_len > 0 {
                            let _ = conn;
                            self.schedule_client_write(key, send_len as u32)?;
                        } else {
                            let _ = conn;
                            self.finish_response_and_maybe_keepalive(key);
                        }
                        return Ok(());
                    }

                    _ => {
                        self.queue_error_response(key, RESP_502)?;
                        return Ok(());
                    }
                }
            }

            Side::None => {
                self.close_conn(key);
                Ok(())
            }
        }
    }

    fn on_read_client_tls(&mut self, key: Key, res: i32) -> Result<()> {
        let now = monotonic_nanos();
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.in_flight = conn.in_flight.saturating_sub(1);
        conn.tls_read_in_flight = false;
        if res < 0 {
            let is_h2 = conn.alpn_h2;
            let _ = conn;
            if is_retryable_io_error(Some(-res)) {
                if is_h2 {
                    if self.flush_h2_downstream_tx(key).is_err() {
                        self.close_conn(key);
                        return Ok(());
                    }
                    let wants_write = {
                        let Some(conn) = self.conns.get_mut(key) else {
                            return Ok(());
                        };
                        conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false)
                    };
                    if wants_write {
                        if self.flush_tls_write(key).is_err() {
                            self.close_conn(key);
                            return Ok(());
                        }
                    }
                }
                self.schedule_read_client_tls(key)?;
            } else {
                self.close_conn(key);
            }
            return Ok(());
        }
        if res == 0 {
            self.close_conn(key);
            return Ok(());
        }

        let n_cipher = res as usize;
        self.metrics
            .bytes_cli_in
            .fetch_add(n_cipher as u64, Ordering::Relaxed);
        let tls_buf = unsafe {
            std::slice::from_raw_parts(self.bufs.ptr(conn.tls_buf) as *const u8, n_cipher)
        };
        let processed_ok = match conn.tls.as_mut() {
            Some(tls) => {
                let mut rd = std::io::Cursor::new(tls_buf);
                if tls.read_tls(&mut rd).is_err() {
                    false
                } else {
                    tls.process_new_packets().is_ok()
                }
            }
            None => false,
        };
        if !processed_ok {
            self.close_conn(key);
            return Ok(());
        }

        let (handshaking, wants_write_after_packet) = match conn.tls.as_ref() {
            Some(tls) => (tls.is_handshaking(), tls.wants_write()),
            None => {
                self.close_conn(key);
                return Ok(());
            }
        };
        if !handshaking && conn.sni_len == 0 {
            Self::capture_tls_peer_info(conn);
        }
        if handshaking {
            let _ = conn;
            if wants_write_after_packet {
                if self.flush_tls_write(key).is_err() {
                    self.close_conn(key);
                    return Ok(());
                }
            }
            return self.schedule_read_client_tls(key);
        }

        let is_h2 = conn.alpn_h2;
        if is_h2 {
            Self::slowloris_stop_tracking(self.slowloris_guard.as_ref(), conn);
        }
        if !is_h2 && matches!(conn.state, ConnState::CliReadBody) {
            conn.buf_len = 0;
            conn.buf_off = 0;
        }

        let _ = conn;

        if is_h2 {
            let wants_flush_first = {
                let Some(conn) = self.conns.get_mut(key) else {
                    return Ok(());
                };
                conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false)
            };
            if wants_flush_first {
                if self.flush_tls_write(key).is_err() {
                    self.close_conn(key);
                    return Ok(());
                }
            }

            self.ensure_h2_downstream(key);
            let chunks = self.tls_drain_plain_downstream_h2(key)?;
            if !chunks.is_empty() {
                if self.pump_h2_downstream(key, now, &chunks).is_err() {
                    self.close_conn(key);
                    return Ok(());
                }
            }

            if self.flush_h2_downstream_tx(key).is_err() {
                self.close_conn(key);
                return Ok(());
            }

            let wants_write = {
                let Some(conn) = self.conns.get_mut(key) else {
                    return Ok(());
                };
                conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false)
            };

            if wants_write {
                if self.flush_tls_write(key).is_err() {
                    self.close_conn(key);
                    return Ok(());
                }
            }
            return self.schedule_read_client_tls(key);
        }

        let n_plain = self.tls_drain_plain_downstream(key)?;

        let wants_write = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false)
        };

        let ws_tunnel_client_read = self
            .conns
            .get_mut(key)
            .map(|c| matches!(c.state, ConnState::WsTunnelReadClient))
            .unwrap_or(false);

        if n_plain > 0 {
            if ws_tunnel_client_read {
                return self.ws_forward_client_to_upstream(key, n_plain);
            }
            return self.on_client_plaintext(key, now, n_plain, true);
        }
        if wants_write {
            return self.flush_tls_write(key);
        }
        self.schedule_read_client_tls(key)
    }

    fn on_client_write_complete(&mut self, key: Key) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };

        // finished writing response bytes
        match conn.state {
            ConnState::CliWriteHeadAndMaybeBody => {
                // We forwarded response head+maybe body bytes; now we need to decide next step.
                if conn.resp_body.is_done() {
                    self.metrics.resp_total.fetch_add(1, Ordering::Relaxed);
                    let _ = conn;
                    self.finish_response_and_maybe_keepalive(key);
                    return Ok(());
                }
                // continue reading response body from upstream
                conn.state = ConnState::UpReadBody;
                let _ = conn;
                self.schedule_read_upstream(key, 0)?;
                Ok(())
            }
            ConnState::CliWriteBody => {
                if conn.resp_body.is_done() {
                    self.metrics.resp_total.fetch_add(1, Ordering::Relaxed);
                    let _ = conn;
                    self.finish_response_and_maybe_keepalive(key);
                    return Ok(());
                }
                conn.state = ConnState::UpReadBody;
                let _ = conn;
                self.schedule_read_upstream(key, 0)?;
                Ok(())
            }
            ConnState::WritingErrorThenClose => {
                let _ = conn;
                self.close_conn(key);
                Ok(())
            }
            ConnState::WsTunnelWriteClient => {
                self.metrics.resp_total.fetch_add(1, Ordering::Relaxed);
                conn.state = ConnState::WsTunnelReadClient;
                let _ = conn;
                self.schedule_client_read(key, 0)?;
                Ok(())
            }
            _ => {
                let _ = conn;
                self.close_conn(key);
                Ok(())
            }
        }
    }

    fn on_write(&mut self, key: Key, side: Side, res: i32) -> Result<()> {
        if side == Side::Client && self.has_down_tls(key) {
            return self.on_write_client_tls(key, res);
        }
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.in_flight = conn.in_flight.saturating_sub(1);

        if res < 0 {
            let err = -res;
            if is_retryable_io_error(Some(err)) {
                let off = conn.buf_off;
                let len = conn.buf_len.saturating_sub(conn.buf_off);
                if len > 0 {
                    let fd_fi = match side {
                        Side::Client => conn.client_fi,
                        Side::Upstream => conn.upstream_fi,
                        Side::None => -1,
                    };
                    if fd_fi >= 0 {
                        let _ = conn;
                        self.schedule_write(key, side, fd_fi, off, len)?;
                        return Ok(());
                    }
                }
            }
            match side {
                Side::Client => self.close_conn(key),
                Side::Upstream => {
                    let up_id = conn.upstream_id;
                    let _ = conn;
                    if self.maybe_retry_http1(key)? {
                        return Ok(());
                    }
                    self.mark_upstream_failure(up_id);
                    self.queue_error_response(key, RESP_502)?;
                }
                Side::None => self.close_conn(key),
            }
            return Ok(());
        }
        if res == 0 {
            // write returned 0 => treat as failure
            match side {
                Side::Client => self.close_conn(key),
                Side::Upstream => {
                    let up_id = conn.upstream_id;
                    let _ = conn;
                    if self.maybe_retry_http1(key)? {
                        return Ok(());
                    }
                    self.mark_upstream_failure(up_id);
                    self.queue_error_response(key, RESP_502)?;
                }
                Side::None => self.close_conn(key),
            }
            return Ok(());
        }

        let wrote = res as u32;

        match side {
            Side::Client => {
                self.metrics
                    .bytes_cli_out
                    .fetch_add(wrote as u64, Ordering::Relaxed);
            }
            Side::Upstream => {
                self.metrics
                    .bytes_up_out
                    .fetch_add(wrote as u64, Ordering::Relaxed);
            }
            Side::None => {}
        }

        conn.buf_off = conn.buf_off.saturating_add(wrote);

        if conn.buf_off < conn.buf_len {
            // continue partial write
            let off = conn.buf_off;
            let len = conn.buf_len - conn.buf_off;
            let fd_fi = match side {
                Side::Client => conn.client_fi,
                Side::Upstream => conn.upstream_fi,
                Side::None => conn.client_fi,
            };
            let _ = conn;
            self.schedule_write(key, side, fd_fi, off, len)?;
            return Ok(());
        }

        // write complete for this buffer chunk
        conn.buf_off = 0;
        conn.buf_len = 0;

        match side {
            Side::Upstream => {
                // finished writing request bytes
                match conn.state {
                    ConnState::WsTunnelWriteUpstream => {
                        conn.state = ConnState::WsTunnelReadUpstream;
                        let _ = conn;
                        self.schedule_read_upstream(key, 0)?;
                        return Ok(());
                    }
                    ConnState::UpWriteHeadAndMaybeBody => {
                        // if request body done -> start reading response head
                        if conn.req_body.is_done() {
                            // request done
                            self.metrics.req_total.fetch_add(1, Ordering::Relaxed);
                            let _ = conn;
                            self.start_up_read_head(key)?;
                            return Ok(());
                        }

                        // continue reading request body from client
                        conn.state = ConnState::CliReadBody;

                        // if stash has bytes, process them first (avoid extra syscalls)
                        if conn.stash_len > 0 {
                            let tail = conn.stash_len as usize;
                            let cap = self.bufs.buf_size().min(tail);
                            let p = self.bufs.ptr(conn.buf);
                            unsafe {
                                std::ptr::copy_nonoverlapping(conn.stash.as_ptr(), p, cap);
                            }
                            conn.stash_len = 0;
                            conn.buf_len = cap as u32;
                            conn.buf_off = 0;

                            let buf_slice = unsafe {
                                std::slice::from_raw_parts(
                                    self.bufs.ptr(conn.buf) as *const u8,
                                    cap,
                                )
                            };
                            let r = conn.req_body.consume(buf_slice);
                            if r.error {
                                self.queue_error_response(key, RESP_400)?;
                                return Ok(());
                            }
                            let new_seen = conn
                                .req_body_received_bytes
                                .saturating_add(r.data_bytes as u64);
                            if new_seen > conn.req_body_limit_bytes {
                                self.queue_error_response(key, RESP_413)?;
                                return Ok(());
                            }
                            conn.req_body_received_bytes = new_seen;
                            let send_len = r.consumed;
                            conn.buf_len = send_len as u32;

                            let up_fi = conn.upstream_fi;
                            conn.state = ConnState::UpWriteHeadAndMaybeBody;
                            let _ = conn;

                            if send_len > 0 {
                                self.schedule_write(
                                    key,
                                    Side::Upstream,
                                    up_fi,
                                    0,
                                    send_len as u32,
                                )?;
                            } else {
                                self.start_up_read_head(key)?;
                            }
                            return Ok(());
                        }

                        // schedule next read from client at offset 0
                        let _ = conn;
                        self.schedule_client_read(key, 0)?;
                        return Ok(());
                    }
                    _ => {
                        self.queue_error_response(key, RESP_502)?;
                        return Ok(());
                    }
                }
            }

            Side::Client => {
                let _ = conn;
                self.on_client_write_complete(key)
            }

            Side::None => {
                let _ = conn;
                self.close_conn(key);
                Ok(())
            }
        }
    }

    fn on_write_client_tls(&mut self, key: Key, res: i32) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.in_flight = conn.in_flight.saturating_sub(1);
        conn.tls_write_in_flight = false;
        if res < 0 {
            if is_retryable_io_error(Some(-res)) && conn.tls_out_off < conn.tls_out_len {
                let off = conn.tls_out_off;
                let len = conn.tls_out_len - conn.tls_out_off;
                let p = self.bufs.ptr_at(conn.tls_wbuf, off);
                conn.tls_write_in_flight = true;
                conn.in_flight = conn.in_flight.saturating_add(1);
                let sq = sqe::write_fixed(
                    conn.client_fi,
                    true,
                    p as *const u8,
                    len,
                    conn.tls_wbuf,
                    op::pack(OpKind::Write, Side::Client, key.idx, key.gen),
                );
                ring_push_blocking(&mut self.uring, sq)
                    .map_err(|e| ArcError::io("push write_tls(client,retry)", e))?;
                return Ok(());
            }
            self.close_conn(key);
            return Ok(());
        }
        if res == 0 {
            self.close_conn(key);
            return Ok(());
        }
        let wrote = res as u32;
        self.metrics
            .bytes_cli_out
            .fetch_add(wrote as u64, Ordering::Relaxed);
        conn.tls_out_off = conn.tls_out_off.saturating_add(wrote);
        if conn.tls_out_off < conn.tls_out_len {
            let off = conn.tls_out_off;
            let len = conn.tls_out_len - conn.tls_out_off;
            let p = self.bufs.ptr_at(conn.tls_wbuf, off);
            conn.tls_write_in_flight = true;
            conn.in_flight = conn.in_flight.saturating_add(1);
            let sq = sqe::write_fixed(
                conn.client_fi,
                true,
                p as *const u8,
                len,
                conn.tls_wbuf,
                op::pack(OpKind::Write, Side::Client, key.idx, key.gen),
            );
            ring_push_blocking(&mut self.uring, sq)
                .map_err(|e| ArcError::io("push write_tls(client,partial)", e))?;
            return Ok(());
        }
        conn.tls_out_off = 0;
        conn.tls_out_len = 0;
        let is_h2 = conn.alpn_h2;
        let handshaking = conn
            .tls
            .as_ref()
            .map(|t| t.is_handshaking())
            .unwrap_or(false);
        let wants_more = conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false);
        if wants_more {
            let _ = conn;
            if self.flush_tls_write(key).is_err() {
                self.close_conn(key);
                return Ok(());
            }
            return self.schedule_read_client_tls(key);
        }
        if handshaking {
            let _ = conn;
            return self.schedule_read_client_tls(key);
        }
        if is_h2 {
            let _ = conn;
            if self.flush_h2_downstream_tx(key).is_err() {
                self.close_conn(key);
                return Ok(());
            }
            let wants_write = {
                let Some(conn) = self.conns.get_mut(key) else {
                    return Ok(());
                };
                conn.tls.as_ref().map(|t| t.wants_write()).unwrap_or(false)
            };
            if wants_write {
                if self.flush_tls_write(key).is_err() {
                    self.close_conn(key);
                    return Ok(());
                }
            }
            return self.schedule_read_client_tls(key);
        }
        conn.buf_off = 0;
        conn.buf_len = 0;
        let state = conn.state;
        let _ = conn;
        if matches!(
            state,
            ConnState::CliWriteHeadAndMaybeBody
                | ConnState::CliWriteBody
                | ConnState::WsTunnelWriteClient
                | ConnState::WritingErrorThenClose
        ) {
            return self.on_client_write_complete(key);
        }
        self.schedule_read_client_tls(key)
    }

    fn start_up_read_head(&mut self, key: Key) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        conn.state = ConnState::UpReadHead;
        conn.buf_len = 0;
        conn.buf_off = 0;

        // schedule read upstream
        let _ = conn;
        self.schedule_read_upstream(key, 0)?;
        Ok(())
    }

    #[inline]
    fn schedule_read_upstream(&mut self, key: Key, off: u32) -> Result<()> {
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if conn.buf == INVALID_BUF || conn.upstream_fi < 0 {
            self.queue_error_response(key, RESP_502)?;
            return Ok(());
        }

        let cap = self.bufs.buf_size() as u32;
        if off >= cap {
            self.queue_error_response(key, RESP_502)?;
            return Ok(());
        }

        let p = self.bufs.ptr_at(conn.buf, off);
        let len = cap - off;

        conn.in_flight = conn.in_flight.saturating_add(1);
        conn.phase = Phase::UpRead;
        let now = monotonic_nanos();
        let up_read_ns = self
            .active_cfg
            .timeouts_ms
            .up_read
            .saturating_mul(1_000_000);
        conn.deadline_ns = if let (Some(tier), Some(state)) =
            (conn.timeout_tier_ns, conn.timeout_state.as_ref())
        {
            if matches!(conn.state, ConnState::UpReadHead) {
                state.deadline_for_response_header(now, tier.response_header_ns, conn.resp_started)
            } else {
                state.deadline_for_io(now, up_read_ns)
            }
        } else {
            now.saturating_add(up_read_ns)
        };
        self.timeout_wheel.push(conn.deadline_ns, key);

        let sq = sqe::read_fixed(
            conn.upstream_fi,
            true,
            p,
            len,
            conn.buf,
            op::pack(OpKind::Read, Side::Upstream, key.idx, key.gen),
        );
        ring_push_blocking(&mut self.uring, sq)
            .map_err(|e| ArcError::io("push read(upstream)", e))?;
        Ok(())
    }

    fn emit_access_log_snapshot(s: AccessLogSnapshot) {
        let mut ctx = AccessLogContext::new(
            s.trace_id.as_str(),
            s.request_id.as_str(),
            s.method.as_str(),
            s.path.as_str(),
            s.query.as_str(),
            s.host.as_str(),
            s.route.as_str(),
            s.upstream.as_str(),
            s.upstream_addr.as_str(),
            s.client_ip.as_str(),
            s.client_port,
            s.tls,
            s.http_version.as_str(),
        );
        if let Some(span_id) = s.span_id.as_ref() {
            ctx.span_id = Some(LogStr::new(span_id.as_str()));
        }
        ctx.attempt = s.attempt;
        ctx.upstream_connect_ms = s.upstream_connect_ms;
        ctx.upstream_response_ms = s.upstream_response_ms;
        arc_logging::submit_access_success(ctx, s.status, s.duration_ms);
    }

    fn h2_emit_access_log(mut s: AccessLogSnapshot, status: u16, started_ns: u64) {
        let now_ns = monotonic_nanos();
        s.status = status;
        s.duration_ms = now_ns.saturating_sub(started_ns).saturating_div(1_000_000);
        Self::emit_access_log_snapshot(s);
    }

    #[inline]
    fn h2_emit_access_log_opt(s: Option<AccessLogSnapshot>, status: u16, started_ns: u64) {
        if let Some(s) = s {
            Self::h2_emit_access_log(s, status, started_ns);
        }
    }

    fn h2_make_access_log_snapshot(
        &mut self,
        down_key: Key,
        _sid: u32,
        _now_ns: u64,
        trace_ctx: TraceContext,
        method: &[u8],
        full_path: &[u8],
        host: &[u8],
        route: &str,
        upstream: &str,
        upstream_addr: &str,
    ) -> AccessLogSnapshot {
        let (client_ip, client_port, tls) = match self.conns.get_mut(down_key) {
            Some(conn) => (conn.client_ip.clone(), conn.client_port, conn.tls.is_some()),
            None => ("".to_string(), 0, true),
        };
        let request_id = generate_request_id(&self.active_cfg.request_id);
        let (path_no_query, query) = split_path_query(full_path);

        AccessLogSnapshot {
            trace_id: trace_ctx.trace_id_hex(),
            span_id: Some(trace_ctx.span_id_hex()),
            request_id,
            method: String::from_utf8_lossy(method).into_owned(),
            path: String::from_utf8_lossy(path_no_query).into_owned(),
            query: String::from_utf8_lossy(query).into_owned(),
            host: String::from_utf8_lossy(host).into_owned(),
            route: route.to_string(),
            upstream: upstream.to_string(),
            upstream_addr: upstream_addr.to_string(),
            client_ip,
            client_port,
            tls,
            http_version: "HTTP/2".to_string(),
            status: 0,
            duration_ms: 0,
            upstream_connect_ms: None,
            upstream_response_ms: None,
            attempt: 1,
        }
    }

    fn finish_response_and_maybe_keepalive(&mut self, key: Key) {
        let now_ns = monotonic_nanos();
        let (keep_client, maybe_idle, success_up_id, mirror_job, access_log, released_upstream_id) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return;
            };

            let success_up_id = conn.upstream_id;
            let keep_client = self.graceful_shutdown_started_ns.is_none()
                && should_keepalive(conn.req_keepalive, conn.resp_keepalive);
            let mut maybe_idle: Option<(usize, IdleUpstream)> = None;
            let mirror_job = if conn.route_selected {
                let route_idx = conn.route_id as usize;
                let targets = self
                    .mirror_targets_by_route
                    .get(route_idx)
                    .cloned()
                    .unwrap_or_else(|| Arc::from([]));
                if !targets.is_empty()
                    && conn.replay_len > 0
                    && (conn.replay_len as usize) <= STASH_CAP
                {
                    let raw_req: Arc<[u8]> = conn.stash[..conn.replay_len as usize].to_vec().into();
                    let route_path = self
                        .active_cfg
                        .routes
                        .get(route_idx)
                        .map(|r| String::from_utf8_lossy(r.path.as_ref()).into_owned())
                        .unwrap_or_else(|| "/".to_string());
                    let domain = if let Some(sni) = conn.sni_host.as_ref() {
                        let n = (conn.sni_len as usize).min(sni.len());
                        if n == 0 {
                            None
                        } else {
                            Some(Arc::<str>::from(
                                String::from_utf8_lossy(&sni[..n]).into_owned(),
                            ))
                        }
                    } else {
                        None
                    };
                    let prod_status = if conn.upstream_status == 0 {
                        200
                    } else {
                        conn.upstream_status
                    };
                    let prod_latency = if conn.request_started_ns > 0 {
                        Duration::from_nanos(now_ns.saturating_sub(conn.request_started_ns))
                    } else {
                        Duration::from_nanos(0)
                    };
                    Some((
                        targets,
                        MirrorSubmitContext {
                            domain,
                            route_name: Arc::from(route_path.as_str()),
                            original_path: Arc::from(route_path.as_str()),
                            prod_status,
                            prod_latency,
                            prod_response: None,
                        },
                        raw_req,
                    ))
                } else {
                    None
                }
            } else {
                None
            };
            let status = if conn.upstream_status == 0 {
                200
            } else {
                conn.upstream_status
            };
            let request_id = if conn.request_id_text.is_empty() {
                generate_request_id(&self.active_cfg.request_id)
            } else {
                conn.request_id_text.clone()
            };
            let duration_ms = if conn.request_started_ns > 0 {
                now_ns
                    .saturating_sub(conn.request_started_ns)
                    .saturating_div(1_000_000)
            } else {
                0
            };
            let route = self
                .active_cfg
                .routes
                .get(conn.route_id as usize)
                .map(|r| String::from_utf8_lossy(r.path.as_ref()).into_owned())
                .unwrap_or_else(|| "/".to_string());
            let (upstream, upstream_addr) = self
                .active_cfg
                .upstreams
                .get(conn.upstream_id)
                .map(|u| (u.name.as_ref().to_string(), u.addr.to_string()))
                .unwrap_or_else(|| ("".to_string(), "".to_string()));
            let access_log = if conn.log_active {
                Some(AccessLogSnapshot {
                    trace_id: if conn.log_trace_id.is_empty() {
                        request_id.clone()
                    } else {
                        conn.log_trace_id.clone()
                    },
                    span_id: if conn.log_span_id.is_empty() {
                        None
                    } else {
                        Some(conn.log_span_id.clone())
                    },
                    request_id,
                    method: conn.log_method.clone(),
                    path: conn.log_path.clone(),
                    query: conn.log_query.clone(),
                    host: conn.log_host.clone(),
                    route,
                    upstream,
                    upstream_addr,
                    client_ip: conn.client_ip.clone(),
                    client_port: conn.client_port,
                    tls: conn.tls.is_some(),
                    http_version: "HTTP/1.1".to_string(),
                    status,
                    duration_ms,
                    upstream_connect_ms: conn.upstream_connect_ms,
                    upstream_response_ms: conn.upstream_response_ms,
                    attempt: conn.retry_count.saturating_add(1),
                })
            } else {
                None
            };
            conn.log_active = false;
            let mut released_upstream_id = None;

            if should_checkin_upstream_keepalive(
                conn.req_keepalive,
                conn.resp_keepalive,
                conn.upstream_fd,
                conn.upstream_fi,
            ) {
                let up_id = conn.upstream_id;
                let item = IdleUpstream {
                    fd: conn.upstream_fd,
                    fi: conn.upstream_fi,
                    upstream_id: up_id,
                    ts_ns: monotonic_nanos(),
                    watch_tag: 0,
                };
                conn.upstream_fd = -1;
                conn.upstream_fi = -1;
                conn.upstream_sa = None;
                maybe_idle = Some((up_id, item));
            } else {
                if conn.upstream_fd >= 0 {
                    close_fd_graceful(conn.upstream_fd, self.active_cfg.linger_ms);
                    released_upstream_id = Some(conn.upstream_id);
                    conn.upstream_fd = -1;
                }
                if conn.upstream_fi >= 0 {
                    let slot = conn.upstream_fi as u32;
                    let _ = self.uring.update_files(slot, &[-1]);
                    self.files.free_slot(slot);
                    conn.upstream_fi = -1;
                }
                conn.upstream_sa = None;
            }

            (
                keep_client,
                maybe_idle,
                success_up_id,
                mirror_job,
                access_log,
                released_upstream_id,
            )
        };
        if let Some(up_id) = released_upstream_id {
            self.upstream_release_connection_slot(up_id);
        }

        self.mark_upstream_success(success_up_id);
        if let Some(s) = access_log {
            Self::emit_access_log_snapshot(s);
        }

        if let Some((targets, ctx, raw_req)) = mirror_job {
            if let Some(dispatcher) = self.mirror_dispatcher.as_ref() {
                dispatcher.submit_all(targets.as_ref(), ctx, raw_req);
            }
        }

        if let Some((up_id, item)) = maybe_idle {
            self.checkin_idle_upstream(up_id, item);
        }

        if !keep_client {
            self.close_conn(key);
            return;
        }

        let Some(conn) = self.conns.get_mut(key) else {
            return;
        };

        // reset for next request
        reset_conn_for_next_keepalive_request(conn);

        if let Some(guard) = self.slowloris_guard.as_ref() {
            let now = monotonic_nanos();
            let decision = Self::slowloris_start_tracking(guard, conn, now);
            if !matches!(decision, SlowlorisDecision::Allow) {
                eprintln!(
                    "worker[{}] slowloris reject keepalive request: ip={} reason={decision:?}",
                    self.id, conn.client_ip
                );
                let _ = conn;
                self.close_conn(key);
                return;
            }
        } else {
            conn.slowloris_tracking = false;
        }

        // if stash has pipelined bytes, prime buffer with them and parse without syscall
        if conn.stash_len > 0 {
            let use_tls = conn.tls.is_some();
            let tail = conn.stash_len as usize;
            let cap = self.bufs.buf_size().min(tail);
            let p = self.bufs.ptr(conn.buf);
            unsafe {
                std::ptr::copy_nonoverlapping(conn.stash.as_ptr(), p, cap);
            }
            conn.stash_len = 0;
            conn.buf_len = cap as u32;
            let cur_len = conn.buf_len;
            let _ = conn;
            if use_tls {
                let now = monotonic_nanos();
                let _ = self.on_client_plaintext(key, now, cur_len, true);
            } else {
                let _ = self.schedule_client_read(key, cur_len);
            }
            return;
        }

        let _ = conn;
        let _ = self.schedule_client_read(key, 0);
    }

    fn queue_error_response(&mut self, key: Key, resp: &[u8]) -> Result<()> {
        self.queue_error_response_with_source(key, resp, ErrorResponseSource::Gateway)
    }

    fn queue_error_response_with_source(
        &mut self,
        key: Key,
        resp: &[u8],
        source: ErrorResponseSource,
    ) -> Result<()> {
        if let Some(status) = http1_status_code_from_response_bytes(resp) {
            if self.apply_error_page_policy(key, status, source)? {
                return Ok(());
            }
        }
        self.queue_raw_response_and_close(key, resp)
    }

    fn queue_raw_response_and_close(&mut self, key: Key, resp: &[u8]) -> Result<()> {
        let now_ns = monotonic_nanos();
        let Some(conn) = self.conns.get_mut(key) else {
            return Ok(());
        };
        if conn.buf == INVALID_BUF {
            self.close_conn(key);
            return Ok(());
        }

        // close upstream immediately
        let mut released_upstream_id = None;
        if conn.upstream_fd >= 0 {
            close_fd_graceful(conn.upstream_fd, self.active_cfg.linger_ms);
            released_upstream_id = Some(conn.upstream_id);
            conn.upstream_fd = -1;
        }
        if conn.upstream_fi >= 0 {
            let slot = conn.upstream_fi as u32;
            let _ = self.uring.update_files(slot, &[-1]);
            self.files.free_slot(slot);
            conn.upstream_fi = -1;
        }
        conn.upstream_sa = None;

        // write response into fixed buffer
        let cap = self.bufs.buf_size();
        if resp.len() > cap {
            self.close_conn(key);
            return Ok(());
        }
        let p = self.bufs.ptr(conn.buf);
        unsafe {
            std::ptr::copy_nonoverlapping(resp.as_ptr(), p, resp.len());
        }
        conn.buf_len = resp.len() as u32;
        conn.buf_off = 0;
        conn.state = ConnState::WritingErrorThenClose;
        let status = http1_status_code_from_response_bytes(resp).unwrap_or(500);
        let request_id = if conn.request_id_text.is_empty() {
            generate_request_id(&self.active_cfg.request_id)
        } else {
            conn.request_id_text.clone()
        };
        let duration_ms = if conn.request_started_ns > 0 {
            now_ns
                .saturating_sub(conn.request_started_ns)
                .saturating_div(1_000_000)
        } else {
            0
        };
        let route = self
            .active_cfg
            .routes
            .get(conn.route_id as usize)
            .map(|r| String::from_utf8_lossy(r.path.as_ref()).into_owned())
            .unwrap_or_else(|| "/".to_string());
        let (upstream, upstream_addr) = self
            .active_cfg
            .upstreams
            .get(conn.upstream_id)
            .map(|u| (u.name.as_ref().to_string(), u.addr.to_string()))
            .unwrap_or_else(|| ("".to_string(), "".to_string()));
        let access_log = if conn.log_active {
            Some(AccessLogSnapshot {
                trace_id: if conn.log_trace_id.is_empty() {
                    request_id.clone()
                } else {
                    conn.log_trace_id.clone()
                },
                span_id: if conn.log_span_id.is_empty() {
                    None
                } else {
                    Some(conn.log_span_id.clone())
                },
                request_id,
                method: conn.log_method.clone(),
                path: conn.log_path.clone(),
                query: conn.log_query.clone(),
                host: conn.log_host.clone(),
                route,
                upstream,
                upstream_addr,
                client_ip: conn.client_ip.clone(),
                client_port: conn.client_port,
                tls: conn.tls.is_some(),
                http_version: "HTTP/1.1".to_string(),
                status,
                duration_ms,
                upstream_connect_ms: conn.upstream_connect_ms,
                upstream_response_ms: conn.upstream_response_ms,
                attempt: conn.retry_count.saturating_add(1),
            })
        } else {
            None
        };
        conn.log_active = false;

        let _ = conn;
        if let Some(up_id) = released_upstream_id {
            self.upstream_release_connection_slot(up_id);
        }
        if let Some(s) = access_log {
            Self::emit_access_log_snapshot(s);
        }
        self.schedule_client_write(key, resp.len() as u32)?;
        Ok(())
    }

    fn apply_error_page_policy(
        &mut self,
        key: Key,
        status: u16,
        source: ErrorResponseSource,
    ) -> Result<bool> {
        if status < 400 {
            return Ok(false);
        }

        let (
            route_selected,
            route_id,
            req_id,
            cur_upstream_name,
            error_page_hops,
            route_rules,
            default_rules,
        ) = {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(false);
            };
            let up_name = if conn.route_selected {
                self.active_cfg
                    .upstreams
                    .get(conn.upstream_id)
                    .map(|u| u.name.as_ref().to_string())
            } else {
                None
            };
            let route_rules = if conn.route_selected {
                self.active_cfg
                    .routes
                    .get(conn.route_id as usize)
                    .map(|r| r.error_pages.clone())
                    .unwrap_or_else(|| Arc::from([]))
            } else {
                Arc::from([])
            };
            (
                conn.route_selected,
                conn.route_id,
                conn.request_id,
                up_name,
                conn.error_page_hops,
                route_rules,
                self.active_cfg.default_error_pages.clone(),
            )
        };

        let mut decision: Option<CompiledErrorPageRule> = None;
        if route_selected {
            for rule in route_rules.iter() {
                if !rule.pattern.matches(status) {
                    continue;
                }
                if rule.when == ErrorPageWhen::UpstreamError
                    && source != ErrorResponseSource::Upstream
                {
                    continue;
                }
                if matches!(rule.action, CompiledErrorPageAction::Upstream { .. })
                    && error_page_hops >= 1
                {
                    continue;
                }
                decision = Some(rule.clone());
                break;
            }
        }
        if decision.is_none() {
            for rule in default_rules.iter() {
                if !rule.pattern.matches(status) {
                    continue;
                }
                if rule.when == ErrorPageWhen::UpstreamError
                    && source != ErrorResponseSource::Upstream
                {
                    continue;
                }
                if matches!(rule.action, CompiledErrorPageAction::Upstream { .. })
                    && error_page_hops >= 1
                {
                    continue;
                }
                decision = Some(rule.clone());
                break;
            }
        }

        let Some(rule) = decision else {
            return Ok(false);
        };

        let req_id_val = if req_id != 0 {
            req_id
        } else {
            splitmix64(monotonic_nanos() ^ ((key.idx as u64) << 32) ^ key.gen as u64)
        };
        let req_id_hex = format!("{req_id_val:016x}");
        let source_str = match source {
            ErrorResponseSource::Gateway => "gateway",
            ErrorResponseSource::Upstream => "upstream",
        };
        let upstream_name = cur_upstream_name.unwrap_or_default();

        match rule.action {
            CompiledErrorPageAction::Inline {
                template,
                content_type,
            } => {
                let body = render_error_template(
                    template.as_ref(),
                    req_id_hex.as_str(),
                    upstream_name.as_str(),
                    status,
                    source_str,
                    route_id,
                );
                let headers = vec![(
                    Bytes::from_static(b"Content-Type"),
                    Bytes::copy_from_slice(content_type.as_bytes()),
                )];
                let resp =
                    arc_config::build_http1_response_bytes(status, body.as_slice(), &headers);
                self.queue_raw_response_and_close(key, resp.as_ref())?;
                Ok(true)
            }
            CompiledErrorPageAction::Redirect { location, code } => {
                let body = Vec::new();
                let headers = vec![(
                    Bytes::from_static(b"Location"),
                    Bytes::copy_from_slice(location.as_bytes()),
                )];
                let resp = arc_config::build_http1_response_bytes(code, body.as_slice(), &headers);
                self.queue_raw_response_and_close(key, resp.as_ref())?;
                Ok(true)
            }
            CompiledErrorPageAction::Upstream { upstream_id } => {
                let req = self.build_error_page_upstream_request(
                    upstream_id,
                    status,
                    source_str,
                    req_id_hex.as_str(),
                    upstream_name.as_str(),
                );
                self.start_error_page_upstream_request(key, upstream_id, req.as_slice())?;
                Ok(true)
            }
        }
    }

    fn build_error_page_upstream_request(
        &self,
        upstream_id: usize,
        status: u16,
        source: &str,
        request_id: &str,
        upstream_name: &str,
    ) -> Vec<u8> {
        let host = self
            .active_cfg
            .upstreams
            .get(upstream_id)
            .map(|u| u.addr.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let path = format!("/__arc/error/{status}");
        let mut req = String::new();
        req.push_str("GET ");
        req.push_str(path.as_str());
        req.push_str(" HTTP/1.1\r\n");
        req.push_str("Host: ");
        req.push_str(host.as_str());
        req.push_str("\r\nConnection: close\r\n");
        req.push_str("X-Arc-Error-Status: ");
        req.push_str(status.to_string().as_str());
        req.push_str("\r\nX-Arc-Error-Source: ");
        req.push_str(source);
        req.push_str("\r\nX-Arc-Request-Id: ");
        req.push_str(request_id);
        req.push_str("\r\nX-Arc-Upstream: ");
        req.push_str(upstream_name);
        req.push_str("\r\nContent-Length: 0\r\n\r\n");
        req.into_bytes()
    }

    fn start_error_page_upstream_request(
        &mut self,
        key: Key,
        upstream_id: usize,
        req: &[u8],
    ) -> Result<()> {
        let up_addr = match self.upstream_runtime_addr(upstream_id) {
            Some(v) => v,
            None => {
                self.queue_raw_response_and_close(key, RESP_502)?;
                return Ok(());
            }
        };
        if req.is_empty() || req.len() > self.bufs.buf_size() {
            self.queue_raw_response_and_close(key, RESP_502)?;
            return Ok(());
        }

        let mut released_upstream_id = None;
        {
            let Some(conn) = self.conns.get_mut(key) else {
                return Ok(());
            };
            if conn.buf == INVALID_BUF {
                self.close_conn(key);
                return Ok(());
            }

            if conn.upstream_fd >= 0 {
                close_fd_graceful(conn.upstream_fd, self.active_cfg.linger_ms);
                released_upstream_id = Some(conn.upstream_id);
                conn.upstream_fd = -1;
            }
            if conn.upstream_fi >= 0 {
                let slot = conn.upstream_fi as u32;
                let _ = self.uring.update_files(slot, &[-1]);
                self.files.free_slot(slot);
                conn.upstream_fi = -1;
            }
            conn.upstream_sa = None;

            let dst = self.bufs.ptr(conn.buf);
            unsafe {
                std::ptr::copy_nonoverlapping(req.as_ptr(), dst, req.len());
            }
            conn.buf_len = req.len() as u32;
            conn.buf_off = 0;
            conn.req_body = HttpBodyState::None;
            conn.resp_body = HttpBodyState::None;
            conn.req_keepalive = false;
            conn.resp_keepalive = false;
            conn.upstream_id = upstream_id;
            conn.up_write_retries = 0;
            conn.retry_max = 0;
            conn.retry_count = 0;
            conn.retry_allowed = false;
            conn.tried_len = 1;
            conn.tried_upstreams[0] = upstream_id;
            conn.resp_started = false;
            conn.error_page_hops = conn.error_page_hops.saturating_add(1);
        }
        if let Some(up_id) = released_upstream_id {
            self.upstream_release_connection_slot(up_id);
        }

        let now = monotonic_nanos();
        if let Some(idle) = self.checkout_idle_upstream(upstream_id, now) {
            let Some(conn) = self.conns.get_mut(key) else {
                self.drop_idle_upstream(idle);
                return Ok(());
            };
            conn.upstream_fd = idle.fd;
            conn.upstream_fi = idle.fi;
            conn.upstream_reused = true;
            conn.upstream_connect_done_ns = conn.request_started_ns;
            conn.upstream_connect_ms = Some(0);
            conn.upstream_sa = None;
            conn.state = ConnState::UpWriteHeadAndMaybeBody;
            conn.phase = Phase::UpWrite;
            conn.deadline_ns = now.saturating_add(
                self.active_cfg
                    .timeouts_ms
                    .up_write
                    .saturating_mul(1_000_000),
            );
            conn.buf_off = 0;
            let up_fi = conn.upstream_fi;
            let send_len = conn.buf_len;
            let _ = conn;
            self.schedule_write(key, Side::Upstream, up_fi, 0, send_len)?;
            return Ok(());
        }

        if !self.upstream_try_acquire_connection_slot(upstream_id) {
            self.queue_raw_response_and_close(key, RESP_503)?;
            return Ok(());
        }
        let up_fd = match net::create_client_socket(&up_addr) {
            Ok(fd) => fd,
            Err(_) => {
                self.upstream_release_connection_slot(upstream_id);
                self.queue_raw_response_and_close(key, RESP_502)?;
                return Ok(());
            }
        };
        if self.active_cfg.linger_ms > 0 {
            let _ = net::set_linger(up_fd, self.active_cfg.linger_ms);
        }
        let up_slot = match self.files.alloc() {
            Some(s) => s,
            None => {
                close_fd(up_fd);
                self.upstream_release_connection_slot(upstream_id);
                self.queue_raw_response_and_close(key, RESP_502)?;
                return Ok(());
            }
        };
        self.files.table[up_slot as usize] = up_fd;
        if self.uring.update_files(up_slot, &[up_fd]).is_err() {
            self.files.free_slot(up_slot);
            close_fd(up_fd);
            self.upstream_release_connection_slot(upstream_id);
            self.queue_raw_response_and_close(key, RESP_502)?;
            return Ok(());
        }
        {
            let Some(conn) = self.conns.get_mut(key) else {
                let _ = self.uring.update_files(up_slot, &[-1]);
                self.files.free_slot(up_slot);
                close_fd(up_fd);
                self.upstream_release_connection_slot(upstream_id);
                return Ok(());
            };
            conn.upstream_fd = up_fd;
            conn.upstream_fi = up_slot as i32;
            conn.upstream_reused = false;
            conn.state = ConnState::UpConnecting;
            conn.upstream_sa = Some(net::SockAddr::from_socket_addr(&up_addr));
        }
        self.schedule_connect_upstream(key, up_slot as i32)?;
        Ok(())
    }

    fn close_conn(&mut self, key: Key) {
        let down_key = H2ConnKey::new(key.idx, key.gen);
        self.h2_abort_tasks_for_down(down_key);
        self.up_mtls_abort_tasks_for_down(down_key);

        let Some(conn) = self.conns.get_mut(key) else {
            return;
        };

        // best-effort: ensure no in-flight; if there is, mark closing (in this simplified worker we assume 0/1 ops)
        if conn.in_flight != 0 {
            conn.state = ConnState::Closing;
            // closing fds will cancel in-flight ops, then CQE will arrive and we can finalize later.
        }

        if conn.client_fd >= 0 {
            close_fd_graceful(conn.client_fd, self.active_cfg.linger_ms);
            conn.client_fd = -1;
        }
        if conn.client_fi >= 0 {
            let slot = conn.client_fi as u32;
            let _ = self.uring.update_files(slot, &[-1]);
            self.files.free_slot(slot);
            conn.client_fi = -1;
        }

        let mut released_upstream_id = None;
        if conn.upstream_fd >= 0 {
            close_fd_graceful(conn.upstream_fd, self.active_cfg.linger_ms);
            released_upstream_id = Some(conn.upstream_id);
            conn.upstream_fd = -1;
        }
        if conn.upstream_fi >= 0 {
            let slot = conn.upstream_fi as u32;
            let _ = self.uring.update_files(slot, &[-1]);
            self.files.free_slot(slot);
            conn.upstream_fi = -1;
        }
        conn.upstream_sa = None;

        if let Some(mut down) = conn.h2_down.take() {
            let mut ops = WorkerH2BufOps {
                bufs: &mut self.bufs,
            };
            down.release_all(&mut ops);
        }

        Self::slowloris_stop_tracking(self.slowloris_guard.as_ref(), conn);

        if conn.buf != INVALID_BUF {
            self.bufs.free(conn.buf);
            conn.buf = INVALID_BUF;
        }
        if conn.tls_buf != INVALID_BUF {
            self.bufs.free(conn.tls_buf);
            conn.tls_buf = INVALID_BUF;
        }
        if conn.tls_wbuf != INVALID_BUF {
            self.bufs.free(conn.tls_wbuf);
            conn.tls_wbuf = INVALID_BUF;
        }
        if let Some(up_id) = released_upstream_id {
            self.upstream_release_connection_slot(up_id);
        }

        self.conns.free(key);

        self.metrics.active_current.fetch_sub(1, Ordering::Relaxed);
        self.metrics.closed_total.fetch_add(1, Ordering::Relaxed);
    }
}

fn make_uring(cfg: &arc_config::IoUringConfig, core: u32) -> io::Result<Uring> {
    let attempts = [
        (cfg.sqpoll, cfg.iopoll),
        (cfg.sqpoll, false),
        (false, false),
    ];

    let mut last: Option<io::Error> = None;

    for (want_sqpoll, want_iopoll) in attempts {
        let mut flags = 0u32;

        if want_sqpoll {
            flags |= sys::IORING_SETUP_SQPOLL;
            flags |= sys::IORING_SETUP_SQ_AFF;
        }
        if want_iopoll {
            flags |= sys::IORING_SETUP_IOPOLL;
        }

        match Uring::new(cfg.entries, flags, core, cfg.sqpoll_idle_ms) {
            Ok(r) => return Ok(r),
            Err(e) => last = Some(e),
        }
    }

    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to init io_uring")))
}

fn ring_push_blocking(ring: &mut Uring, sqe: sys::io_uring_sqe) -> io::Result<()> {
    loop {
        match ring.push_sqe(sqe) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                ring.submit_and_wait(0)?;
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

#[inline]
fn socket_peer_addr(fd: RawFd) -> (String, u16) {
    if fd < 0 {
        return ("".to_string(), 0);
    }
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getpeername(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return ("".to_string(), 0);
    }

    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sa: libc::sockaddr_in =
                unsafe { std::ptr::read((&storage as *const libc::sockaddr_storage).cast()) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            (ip.to_string(), u16::from_be(sa.sin_port))
        }
        libc::AF_INET6 => {
            let sa: libc::sockaddr_in6 =
                unsafe { std::ptr::read((&storage as *const libc::sockaddr_storage).cast()) };
            let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
            (ip.to_string(), u16::from_be(sa.sin6_port))
        }
        _ => ("".to_string(), 0),
    }
}

#[inline]
fn socket_so_error(fd: RawFd) -> io::Result<i32> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid fd for SO_ERROR",
        ));
    }
    let mut so_error: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut so_error as *mut i32).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(so_error)
    }
}

#[inline]
fn is_connect_in_progress(code: Option<i32>) -> bool {
    matches!(code, Some(c) if c == libc::EINPROGRESS || c == libc::EALREADY || c == libc::EINTR)
}

#[inline]
fn should_retry_connect(cqe_res: i32, so_error: i32) -> bool {
    if cqe_res >= 0 {
        return false;
    }
    let cqe_err = -cqe_res;
    if is_connect_in_progress(Some(cqe_err)) {
        return true;
    }
    so_error != 0 && is_connect_in_progress(Some(so_error))
}

#[inline]
fn is_retryable_io_error(code: Option<i32>) -> bool {
    matches!(code, Some(c) if c == libc::EAGAIN || c == libc::EWOULDBLOCK || c == libc::EINTR)
}

#[inline]
fn should_keepalive(req_keepalive: bool, resp_keepalive: bool) -> bool {
    req_keepalive && resp_keepalive
}

#[inline]
fn should_checkin_upstream_keepalive(
    req_keepalive: bool,
    resp_keepalive: bool,
    upstream_fd: RawFd,
    upstream_fi: i32,
) -> bool {
    should_keepalive(req_keepalive, resp_keepalive) && upstream_fd >= 0 && upstream_fi >= 0
}

#[inline]
fn reset_conn_for_next_keepalive_request(conn: &mut Conn) {
    conn.state = ConnState::CliReadHead;
    conn.buf_len = 0;
    conn.buf_off = 0;
    conn.header_end = 0;

    conn.req_keepalive = false;
    conn.resp_keepalive = false;
    conn.req_body = HttpBodyState::None;
    conn.req_body_limit_bytes = 0;
    conn.req_body_received_bytes = 0;
    conn.resp_body = HttpBodyState::None;
    conn.upstream_connect_ms = None;
    conn.upstream_response_ms = None;
    conn.upstream_connect_done_ns = 0;
    conn.route_selected = false;
    conn.route_id = 0;
    conn.upstream_reused = false;
    conn.up_write_retries = 0;
    conn.resp_started = false;
    conn.split_hash = 0;
    conn.retry_max = 0;
    conn.retry_backoff_ns = 0;
    conn.retry_idempotent_only = true;
    conn.retry_count = 0;
    conn.retry_allowed = false;
    conn.tried_len = 0;
    conn.retry_wakeup_ns = 0;
    conn.replay_len = 0;
    conn.upstream_sa = None;
    conn.request_id = 0;
    conn.request_id_text.clear();
    conn.error_page_hops = 0;
    conn.log_active = false;
    conn.log_trace_id.clear();
    conn.log_span_id.clear();
    conn.log_traceparent.clear();
    conn.log_method.clear();
    conn.log_path.clear();
    conn.log_query.clear();
    conn.log_host.clear();
    conn.ws_upgrade_requested = false;
    conn.ws_tunnel_active = false;
    conn.resp_compressed = false;
    conn.resp_compress_alg = Algorithm::Identity;
    conn.resp_compress_level = 0;
    conn.resp_compressor = None;
    conn.req_accept_encoding_len = 0;
    conn.timeout_tier_ns = None;
    conn.timeout_state = None;
    conn.request_started_ns = 0;
    conn.upstream_status = 0;
}

#[inline]
fn h2_down_pending_dec_map(map: &mut HashMap<H2ConnKey, u32>, down: H2ConnKey) -> u32 {
    match map.get_mut(&down) {
        Some(v) => {
            if *v <= 1 {
                map.remove(&down);
                0
            } else {
                *v -= 1;
                *v
            }
        }
        None => 0,
    }
}

#[inline]
fn h2_unlink_task_from_down_map(
    tasks_by_down: &mut HashMap<H2ConnKey, Vec<Key>>,
    down: H2ConnKey,
    task_key: Key,
) {
    let mut empty = false;
    if let Some(v) = tasks_by_down.get_mut(&down) {
        if let Some(pos) = v.iter().position(|k| *k == task_key) {
            v.swap_remove(pos);
        }
        empty = v.is_empty();
    }
    if empty {
        tasks_by_down.remove(&down);
    }
}

#[inline]
fn header_terminator_len(head_block: &[u8]) -> usize {
    if head_block.ends_with(b"\r\n\r\n") {
        4
    } else if head_block.ends_with(b"\n\n") {
        2
    } else {
        0
    }
}

#[inline]
fn has_connection_header(head_block: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut first_line = true;

    while pos < head_block.len() {
        let mut end = pos;
        while end < head_block.len() && head_block[end] != b'\n' {
            end += 1;
        }
        let mut line = &head_block[pos..end];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len().saturating_sub(1)];
        }

        if first_line {
            first_line = false;
        } else if line.is_empty() {
            break;
        } else if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = &line[..colon];
            if name.eq_ignore_ascii_case(b"connection") {
                return true;
            }
        }

        pos = if end < head_block.len() { end + 1 } else { end };
    }
    false
}

#[inline]
fn header_value_contains_token(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|b| *b == b',')
        .any(|part| trim_ascii_ws(part).eq_ignore_ascii_case(token))
}

#[inline]
fn http1_header_has_token(head_block: &[u8], name: &[u8], token: &[u8]) -> bool {
    http1_header_value(head_block, name)
        .map(|v| header_value_contains_token(v, token))
        .unwrap_or(false)
}

#[inline]
fn http1_has_conflicting_cl_te(head_block: &[u8]) -> bool {
    http1_header_has_token(head_block, b"transfer-encoding", b"chunked")
        && http1_header_value(head_block, b"content-length").is_some()
}

fn parse_x_forwarded_for_list(raw: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for part in raw.split(|b| *b == b',') {
        let token = trim_ascii_ws(part);
        if token.is_empty() {
            continue;
        }
        if let Ok(v) = std::str::from_utf8(token) {
            if let Ok(ip) = v.parse::<IpAddr>() {
                out.push(ip);
            }
        }
    }
    out
}

#[inline]
fn trusted_proxies_contains_ip(trusted: &[TrustedProxyCidr], ip: IpAddr) -> bool {
    trusted.iter().any(|cidr| cidr.contains_ip(ip))
}

#[inline]
fn generate_request_id_v7() -> String {
    Uuid::now_v7().to_string()
}

#[inline]
fn generate_request_id(cfg: &CompiledRequestIdConfig) -> String {
    match cfg.format {
        RequestIdFormatConfig::UuidV7 => generate_request_id_v7(),
    }
}

fn resolve_request_id_decision(
    peer_client_ip: &str,
    inbound_request_id: Option<String>,
    cfg: &CompiledRequestIdConfig,
) -> RequestIdDecision {
    let peer_ip = peer_client_ip.parse::<IpAddr>().ok();
    let peer_trusted = peer_ip
        .map(|ip| trusted_proxies_contains_ip(cfg.trusted_proxies.as_ref(), ip))
        .unwrap_or(false);

    match inbound_request_id {
        Some(id) if peer_trusted => RequestIdDecision {
            value: id,
            force_set: false,
            original: None,
        },
        Some(id) => match cfg.on_conflict {
            RequestIdConflictConfig::Preserve => RequestIdDecision {
                value: id,
                force_set: false,
                original: None,
            },
            RequestIdConflictConfig::Override => RequestIdDecision {
                value: generate_request_id(cfg),
                force_set: true,
                original: if cfg.preserve_original { Some(id) } else { None },
            },
        },
        None => RequestIdDecision {
            value: generate_request_id(cfg),
            force_set: true,
            original: None,
        },
    }
}

fn resolve_forwarded_identity(
    peer_client_ip: &str,
    inbound_xff: Option<&[u8]>,
    trusted_proxies: &[TrustedProxyCidr],
    real_ip_header: Arc<str>,
) -> ForwardedIdentity {
    let peer_addr = peer_client_ip.parse::<IpAddr>().ok();
    let mut effective_ip = peer_client_ip.to_string();
    let mut xff_out = peer_client_ip.to_string();

    if let Some(peer_addr) = peer_addr {
        let peer_trusted = trusted_proxies_contains_ip(trusted_proxies, peer_addr);
        let parsed_chain = inbound_xff
            .map(parse_x_forwarded_for_list)
            .unwrap_or_default();
        let mut chain_to_forward: Vec<IpAddr> = Vec::new();
        if peer_trusted && !parsed_chain.is_empty() {
            let mut selected = parsed_chain[0];
            for ip in parsed_chain.iter().rev() {
                selected = *ip;
                if !trusted_proxies_contains_ip(trusted_proxies, *ip) {
                    break;
                }
            }
            effective_ip = selected.to_string();
            chain_to_forward = parsed_chain;
        } else {
            effective_ip = peer_addr.to_string();
        }

        if chain_to_forward.is_empty() {
            xff_out = peer_addr.to_string();
        } else {
            xff_out.clear();
            for (idx, ip) in chain_to_forward.iter().enumerate() {
                if idx > 0 {
                    xff_out.push_str(", ");
                }
                xff_out.push_str(&ip.to_string());
            }
            xff_out.push_str(", ");
            xff_out.push_str(&peer_addr.to_string());
        }
    }

    ForwardedIdentity {
        effective_client_ip: effective_ip,
        x_forwarded_for: xff_out,
        real_ip_header,
    }
}

#[inline]
fn http1_is_websocket_upgrade_request(head_block: &[u8]) -> bool {
    http1_header_has_token(head_block, b"connection", b"upgrade")
        && http1_header_has_token(head_block, b"upgrade", b"websocket")
}

#[inline]
fn http1_is_websocket_upgrade_response(head_block: &[u8]) -> bool {
    http1_header_has_token(head_block, b"connection", b"upgrade")
        && http1_header_has_token(head_block, b"upgrade", b"websocket")
}

#[inline]
fn http1_status_code_from_response_bytes(resp: &[u8]) -> Option<u16> {
    if !resp.starts_with(b"HTTP/") {
        return None;
    }
    let first_line_end = resp.iter().position(|b| *b == b'\n').unwrap_or(resp.len());
    let line = &resp[..first_line_end];
    let mut parts = line.split(|b| *b == b' ');
    let _ver = parts.next()?;
    let code = parts.next()?;
    std::str::from_utf8(code).ok()?.trim().parse::<u16>().ok()
}

fn build_http1_compressed_response_head(head_block: &[u8], content_encoding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(head_block.len().saturating_add(128));

    let mut pos = 0usize;
    let mut first_line = true;
    while pos < head_block.len() {
        let mut end = pos;
        while end < head_block.len() && head_block[end] != b'\n' {
            end += 1;
        }
        let mut line = &head_block[pos..end];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len().saturating_sub(1)];
        }

        if first_line {
            first_line = false;
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        } else if line.is_empty() {
            break;
        } else if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = &line[..colon];
            if name.eq_ignore_ascii_case(b"content-length")
                || name.eq_ignore_ascii_case(b"transfer-encoding")
                || name.eq_ignore_ascii_case(b"content-encoding")
            {
                // rewritten below
            } else {
                out.extend_from_slice(line);
                out.extend_from_slice(b"\r\n");
            }
        }
        pos = if end < head_block.len() { end + 1 } else { end };
    }

    out.extend_from_slice(b"Content-Encoding: ");
    out.extend_from_slice(content_encoding);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
    out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    out.extend_from_slice(b"\r\n");
    out
}

#[inline]
fn parse_u64_header_value(v: &[u8]) -> Option<u64> {
    std::str::from_utf8(trim_ascii_ws(v))
        .ok()?
        .parse::<u64>()
        .ok()
}

#[inline]
fn peek_upstream_body_prefix(fd: RawFd, dst: &mut [u8; 8]) -> usize {
    if fd < 0 {
        return 0;
    }
    let n = unsafe {
        libc::recv(
            fd,
            dst.as_mut_ptr() as *mut libc::c_void,
            dst.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n > 0 {
        n as usize
    } else {
        0
    }
}

fn render_error_template(
    tpl: &[u8],
    request_id: &str,
    upstream_name: &str,
    status: u16,
    source: &str,
    route_id: u32,
) -> Vec<u8> {
    let mut s = String::from_utf8_lossy(tpl).into_owned();
    s = s.replace("$request_id", request_id);
    s = s.replace("$upstream.name", upstream_name);
    s = s.replace("$error.status", status.to_string().as_str());
    s = s.replace("$error.source", source);
    s = s.replace("$route.id", route_id.to_string().as_str());
    s.into_bytes()
}

#[inline]
fn close_fd_graceful(fd: RawFd, linger_ms: u32) {
    if fd < 0 {
        return;
    }
    if linger_ms > 0 {
        let _ = net::set_linger(fd, linger_ms);
    }
    unsafe {
        let _ = libc::shutdown(fd, libc::SHUT_WR);
    }
    close_fd(fd);
}

#[inline]
fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

#[inline]
fn strip_query(path: &[u8]) -> &[u8] {
    match path.iter().position(|b| *b == b'?') {
        Some(pos) => &path[..pos],
        None => path,
    }
}

#[inline]
fn split_path_query(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().position(|b| *b == b'?') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (path, b""),
    }
}

#[inline]
fn trim_ascii_ws(mut s: &[u8]) -> &[u8] {
    while let Some(&b) = s.first() {
        if b.is_ascii_whitespace() {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&b) = s.last() {
        if b.is_ascii_whitespace() {
            s = &s[..s.len().saturating_sub(1)];
        } else {
            break;
        }
    }
    s
}

#[inline]
fn trim_trailing_dot(mut s: &[u8]) -> &[u8] {
    while s.last() == Some(&b'.') {
        s = &s[..s.len().saturating_sub(1)];
    }
    s
}

#[inline]
fn host_without_port(host: &[u8]) -> &[u8] {
    let host = trim_ascii_ws(host);
    if host.is_empty() {
        return host;
    }
    if host.first() == Some(&b'[') {
        if let Some(end) = host.iter().position(|b| *b == b']') {
            if end > 1 {
                return &host[1..end];
            }
        }
        return host;
    }
    match host.iter().position(|b| *b == b':') {
        Some(pos) => &host[..pos],
        None => host,
    }
}

#[inline]
fn host_matches_any(host: &[u8], patterns: &[Bytes]) -> bool {
    if host.is_empty() {
        return false;
    }
    let host = trim_trailing_dot(host);
    for p in patterns {
        let pat = trim_trailing_dot(p.as_ref());
        if pat == b"*" {
            return true;
        }
        if pat.len() >= 2 && pat[0] == b'*' && pat[1] == b'.' {
            let suf = &pat[1..];
            if host.len() > suf.len() && host[host.len() - suf.len()..].eq_ignore_ascii_case(suf) {
                return true;
            }
        } else if host.eq_ignore_ascii_case(pat) {
            return true;
        }
    }
    false
}

fn http1_header_value<'a>(head_block: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if name.is_empty() || head_block.is_empty() {
        return None;
    }

    let len = head_block.len();
    let name_len = name.len();

    // Skip request/status line.
    let mut pos = 0usize;
    while pos < len && head_block[pos] != b'\n' {
        pos += 1;
    }
    if pos < len {
        pos += 1;
    } else {
        return None;
    }

    while pos < len {
        // Empty line means end of headers.
        if head_block[pos] == b'\n' {
            break;
        }
        if head_block[pos] == b'\r' && (pos + 1 == len || head_block[pos + 1] == b'\n') {
            break;
        }

        let line_start = pos;
        let mut colon = usize::MAX;
        while pos < len {
            let b = head_block[pos];
            if b == b':' && colon == usize::MAX {
                colon = pos;
            }
            if b == b'\n' {
                break;
            }
            pos += 1;
        }

        let mut line_end = pos;
        if line_end > line_start && head_block[line_end - 1] == b'\r' {
            line_end -= 1;
        }

        if colon != usize::MAX && colon > line_start && colon <= line_end {
            let key = &head_block[line_start..colon];
            if key.len() == name_len
                && {
                    let mut k0 = key[0];
                    let mut n0 = name[0];
                    if k0.is_ascii_uppercase() {
                        k0 += 32;
                    }
                    if n0.is_ascii_uppercase() {
                        n0 += 32;
                    }
                    k0 == n0
                }
                && key.eq_ignore_ascii_case(name)
            {
                let value_start = colon + 1;
                if value_start <= line_end {
                    return Some(trim_ascii_ws(&head_block[value_start..line_end]));
                }
                return Some(&[]);
            }
        }

        if pos < len {
            pos += 1;
        }
    }

    None
}

fn query_param_value<'a>(path: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let q = path.iter().position(|b| *b == b'?')?;
    let mut i = q + 1;
    while i <= path.len() {
        let mut j = i;
        while j < path.len() && path[j] != b'&' {
            j += 1;
        }
        let pair = &path[i..j];
        if let Some(eq) = pair.iter().position(|b| *b == b'=') {
            if &pair[..eq] == key {
                return Some(&pair[eq + 1..]);
            }
        } else if pair == key {
            return Some(&[]);
        }
        if j >= path.len() {
            break;
        }
        i = j + 1;
    }
    None
}

fn h2_header_value<'a>(headers: &'a [H2Header], name: &[u8]) -> Option<&'a [u8]> {
    for h in headers {
        if h.name.as_ref().eq_ignore_ascii_case(name) {
            return Some(h.value.as_ref());
        }
    }
    None
}

#[inline]
fn is_idempotent_method(m: &[u8]) -> bool {
    eq_ascii(m, b"GET")
        || eq_ascii(m, b"HEAD")
        || eq_ascii(m, b"OPTIONS")
        || eq_ascii(m, b"TRACE")
        || eq_ascii(m, b"PUT")
        || eq_ascii(m, b"DELETE")
}

#[inline]
fn eq_ascii(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(&x, &y)| {
            let lx = if x.is_ascii_uppercase() { x + 32 } else { x };
            let ly = if y.is_ascii_uppercase() { y + 32 } else { y };
            lx == ly
        })
}

#[inline]
fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037u64 ^ seed;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211u64);
    }
    h
}

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[inline]
fn parse_block_reason(v: &str) -> BlockReason {
    match v.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "syn_flood" => BlockReason::SynFlood,
        "ack_flood" => BlockReason::AckFlood,
        "rst_invalid" | "rst_flood" => BlockReason::RstInvalid,
        "udp_rate_limit" => BlockReason::UdpRateLimit,
        _ => BlockReason::Manual,
    }
}

#[inline]
fn ip_addr_to_ip_key(ip: IpAddr) -> IpKey {
    match ip {
        IpAddr::V4(v4) => IpKey::from_ipv4_exact(v4.octets()),
        IpAddr::V6(v6) => IpKey::from_ipv6_exact(v6.octets()),
    }
}

fn parse_ip_or_cidr_to_ip_key(s: &str) -> Option<IpKey> {
    let raw = s.trim();
    if raw.is_empty() {
        return None;
    }
    let (ip_part, prefix_part) = match raw.split_once('/') {
        Some((ip, p)) => (ip.trim(), Some(p.trim())),
        None => (raw, None),
    };
    let ip = ip_part.parse::<IpAddr>().ok()?;
    match (ip, prefix_part) {
        (IpAddr::V4(v4), Some(p)) => {
            let plen = p.parse::<u8>().ok()?;
            if plen > 32 {
                return None;
            }
            Some(IpKey::from_ipv4_cidr(v4.octets(), plen))
        }
        (IpAddr::V6(v6), Some(p)) => {
            let plen = p.parse::<u8>().ok()?;
            if plen > 128 {
                return None;
            }
            Some(IpKey::from_ipv6_cidr(v6.octets(), plen))
        }
        (IpAddr::V4(v4), None) => Some(IpKey::from_ipv4_exact(v4.octets())),
        (IpAddr::V6(v6), None) => Some(IpKey::from_ipv6_exact(v6.octets())),
    }
}

#[inline]
fn ip_key_prefix_match(cidr: IpKey, ip: IpKey) -> bool {
    let plen = cidr.prefix_len.min(128) as usize;
    let full_bytes = plen / 8;
    let rem_bits = plen % 8;
    if full_bytes > 0 && cidr.addr[..full_bytes] != ip.addr[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask: u8 = 0xFFu8 << (8 - rem_bits);
    (cidr.addr[full_bytes] & mask) == (ip.addr[full_bytes] & mask)
}

#[inline]
fn http1_parse_req_line(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut sp1 = None;
    for (i, &b) in buf.iter().enumerate() {
        if b == b' ' {
            sp1 = Some(i);
            break;
        }
        if b == b'\r' || b == b'\n' {
            return None;
        }
    }
    let sp1 = sp1?;
    let mut sp2 = None;
    for (i, &b) in buf[sp1 + 1..].iter().enumerate() {
        if b == b' ' {
            sp2 = Some(sp1 + 1 + i);
            break;
        }
        if b == b'\r' || b == b'\n' {
            return None;
        }
    }
    let sp2 = sp2?;
    Some((&buf[..sp1], &buf[sp1 + 1..sp2]))
}

#[inline]
fn cookie_get<'a>(cookie_header: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i < cookie_header.len() {
        while i < cookie_header.len() && (cookie_header[i] == b' ' || cookie_header[i] == b';') {
            i += 1;
        }
        if i >= cookie_header.len() {
            break;
        }
        let key_start = i;
        while i < cookie_header.len() && cookie_header[i] != b'=' && cookie_header[i] != b';' {
            i += 1;
        }
        if i >= cookie_header.len() || cookie_header[i] != b'=' {
            while i < cookie_header.len() && cookie_header[i] != b';' {
                i += 1;
            }
            continue;
        }
        let key_end = i;
        i += 1;
        let val_start = i;
        while i < cookie_header.len() && cookie_header[i] != b';' {
            i += 1;
        }
        let val_end = i;
        let mut ks = key_start;
        let mut ke = key_end;
        while ks < ke && cookie_header[ks] == b' ' {
            ks += 1;
        }
        while ke > ks && cookie_header[ke - 1] == b' ' {
            ke -= 1;
        }
        if cookie_header[ks..ke] == *name {
            return Some(&cookie_header[val_start..val_end]);
        }
    }
    None
}

fn select_route_http1_from_cfg(
    cfg: &SharedConfig,
    method: &[u8],
    full_path: &[u8],
    head_block: &[u8],
    sni: Option<&[u8]>,
    is_tls: bool,
) -> std::result::Result<u32, RouteSelectError> {
    let path_no_q = strip_query(full_path);
    let host = http1_header_value(head_block, b"host")
        .map(trim_ascii_ws)
        .map(host_without_port)
        .map(trim_trailing_dot);

    let mut best_pri: i32 = i32::MIN;
    let mut best_spec: u32 = 0;
    let mut best_id: u32 = 0;
    let mut best_count: u32 = 0;

    cfg.router.for_each_candidate(path_no_q, |rid| {
        let group = cfg
            .route_candidate_groups
            .get(rid as usize)
            .map(|g| g.as_ref())
            .unwrap_or(&[]);
        let candidates: &[u32] = if group.is_empty() { &[rid] } else { group };

        for &cid in candidates {
            let Some(route) = cfg.routes.get(cid as usize) else {
                continue;
            };
            if !route_matches_http1(route, method, full_path, head_block, host, sni, is_tls) {
                continue;
            }

            let pri = route.priority;
            let spec = route.specificity();
            if pri > best_pri || (pri == best_pri && spec > best_spec) {
                best_pri = pri;
                best_spec = spec;
                best_id = cid;
                best_count = 1;
            } else if pri == best_pri && spec == best_spec {
                best_count = best_count.saturating_add(1);
            }
        }
    });

    if best_count == 0 {
        return Err(RouteSelectError::NotFound);
    }
    if best_count > 1 {
        return Err(RouteSelectError::Ambiguous);
    }
    Ok(best_id)
}

fn route_matches_http1(
    route: &arc_config::CompiledRoute,
    method: &[u8],
    full_path: &[u8],
    head_block: &[u8],
    host: Option<&[u8]>,
    sni: Option<&[u8]>,
    is_tls: bool,
) -> bool {
    for m in route.matchers.iter() {
        match m {
            RouteMatcher::Method { methods } => {
                if !methods
                    .iter()
                    .any(|x| x.as_ref().eq_ignore_ascii_case(method))
                {
                    return false;
                }
            }
            RouteMatcher::Host { hosts } => {
                let h = host.or(sni).unwrap_or(&[]);
                if !host_matches_any(h, hosts) {
                    return false;
                }
            }
            RouteMatcher::Sni { hosts } => {
                let s = sni.unwrap_or(&[]);
                if !host_matches_any(s, hosts) {
                    return false;
                }
            }
            RouteMatcher::HeaderPresent { name } => {
                if http1_header_value(head_block, name.as_ref()).is_none() {
                    return false;
                }
            }
            RouteMatcher::HeaderEquals { name, value } => {
                let Some(v) = http1_header_value(head_block, name.as_ref()) else {
                    return false;
                };
                if trim_ascii_ws(v) != value.as_ref() {
                    return false;
                }
            }
            RouteMatcher::QueryEquals { key, value } => {
                let Some(v) = query_param_value(full_path, key.as_ref()) else {
                    return false;
                };
                if v != value.as_ref() {
                    return false;
                }
            }
            RouteMatcher::Tls { enabled } => {
                if *enabled != is_tls {
                    return false;
                }
            }
            RouteMatcher::H2 { enabled } => {
                if *enabled {
                    return false;
                }
            }
        }
    }
    true
}

fn route_matches_h2(
    route: &arc_config::CompiledRoute,
    method: &[u8],
    full_path: &[u8],
    headers: &[H2Header],
    host: Option<&[u8]>,
    sni: Option<&[u8]>,
    is_tls: bool,
) -> bool {
    for m in route.matchers.iter() {
        match m {
            RouteMatcher::Method { methods } => {
                if !methods
                    .iter()
                    .any(|x| x.as_ref().eq_ignore_ascii_case(method))
                {
                    return false;
                }
            }
            RouteMatcher::Host { hosts } => {
                let h = host.or(sni).unwrap_or(&[]);
                if !host_matches_any(h, hosts) {
                    return false;
                }
            }
            RouteMatcher::Sni { hosts } => {
                let s = sni.unwrap_or(&[]);
                if !host_matches_any(s, hosts) {
                    return false;
                }
            }
            RouteMatcher::HeaderPresent { name } => {
                if h2_header_value(headers, name.as_ref()).is_none() {
                    return false;
                }
            }
            RouteMatcher::HeaderEquals { name, value } => {
                let Some(v) = h2_header_value(headers, name.as_ref()) else {
                    return false;
                };
                if trim_ascii_ws(v) != value.as_ref() {
                    return false;
                }
            }
            RouteMatcher::QueryEquals { key, value } => {
                let Some(v) = query_param_value(full_path, key.as_ref()) else {
                    return false;
                };
                if v != value.as_ref() {
                    return false;
                }
            }
            RouteMatcher::Tls { enabled } => {
                if *enabled != is_tls {
                    return false;
                }
            }
            RouteMatcher::H2 { enabled } => {
                if !*enabled {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_config::ConfigManager;
    use arc_xdp_userspace::config::L7ProtectionConfig;
    use std::collections::HashMap;

    #[test]
    fn connect_in_progress_codes_are_recognized() {
        assert!(is_connect_in_progress(Some(libc::EINPROGRESS)));
        assert!(is_connect_in_progress(Some(libc::EALREADY)));
        assert!(is_connect_in_progress(Some(libc::EINTR)));
        assert!(!is_connect_in_progress(Some(libc::ECONNREFUSED)));
        assert!(!is_connect_in_progress(None));
    }

    #[test]
    fn connect_retry_decision_matches_state_machine_expectation() {
        assert!(should_retry_connect(-libc::EINPROGRESS, libc::EINPROGRESS));
        assert!(should_retry_connect(-libc::EALREADY, libc::EALREADY));
        assert!(!should_retry_connect(-libc::ETIMEDOUT, 0));
        assert!(!should_retry_connect(0, 0));
        assert!(!should_retry_connect(
            -libc::ECONNREFUSED,
            libc::ECONNREFUSED
        ));
    }

    #[test]
    fn keepalive_decision_requires_both_sides_and_valid_upstream() {
        assert!(should_keepalive(true, true));
        assert!(!should_keepalive(true, false));
        assert!(!should_keepalive(false, true));
        assert!(!should_keepalive(false, false));

        assert!(should_checkin_upstream_keepalive(true, true, 10, 3));
        assert!(!should_checkin_upstream_keepalive(true, true, -1, 3));
        assert!(!should_checkin_upstream_keepalive(true, true, 10, -1));
        assert!(!should_checkin_upstream_keepalive(true, false, 10, 3));
    }

    #[test]
    fn forwarded_identity_ignores_untrusted_xff_source() {
        let trusted = [TrustedProxyCidr {
            addr: {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&[10, 0, 0, 0]);
                a
            },
            prefix_len: 8,
            is_ipv4: true,
        }];
        let identity = resolve_forwarded_identity(
            "198.51.100.9",
            Some(b"203.0.113.10"),
            &trusted,
            Arc::from("X-Real-IP"),
        );
        assert_eq!(identity.effective_client_ip, "198.51.100.9");
        assert_eq!(identity.x_forwarded_for, "198.51.100.9");
    }

    #[test]
    fn forwarded_identity_uses_rightmost_untrusted_hop() {
        let trusted = [TrustedProxyCidr {
            addr: {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&[10, 0, 0, 0]);
                a
            },
            prefix_len: 8,
            is_ipv4: true,
        }];
        let identity = resolve_forwarded_identity(
            "10.2.3.4",
            Some(b"203.0.113.7, 10.9.8.7"),
            &trusted,
            Arc::from("X-Real-IP"),
        );
        assert_eq!(identity.effective_client_ip, "203.0.113.7");
        assert_eq!(identity.x_forwarded_for, "203.0.113.7, 10.9.8.7, 10.2.3.4");
    }

    #[test]
    fn cl_te_conflict_detection_works() {
        let conflicted =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let plain = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
        assert!(http1_has_conflicting_cl_te(conflicted));
        assert!(!http1_has_conflicting_cl_te(plain));
    }

    #[test]
    fn fixed_file_slots_allocate_and_recycle_without_touching_listener_slot() {
        let mut ff = FixedFiles::new(4);
        assert_eq!(ff.alloc(), Some(1));
        assert_eq!(ff.alloc(), Some(2));
        assert_eq!(ff.alloc(), Some(3));
        assert_eq!(ff.alloc(), None);

        ff.table[2] = 123;
        ff.free_slot(2);
        assert_eq!(ff.table[2], -1);
        assert_eq!(ff.alloc(), Some(2));

        // slot 0 is reserved for listener and must remain non-allocatable.
        ff.table[0] = 777;
        ff.free_slot(0);
        assert_eq!(ff.table[0], 777);
    }

    #[test]
    fn conn_slot_recycles_after_close_like_free_paths() {
        let mut slab = Slab::<Conn>::new(8).expect("slab");
        let k1 = slab.alloc().expect("alloc 1");
        // SAFETY: key was just allocated from this slab, so slot is initialized exactly once.
        unsafe {
            slab.write(k1, Conn::new(10, 1, INVALID_BUF, 100));
        }
        slab.free(k1);

        let k2 = slab.alloc().expect("alloc 2");
        assert_eq!(k1.idx, k2.idx);
        assert_ne!(k1.gen, k2.gen);

        // error-path-like cleanup also returns slot to free list
        // SAFETY: key was allocated from this slab and not currently initialized.
        unsafe {
            slab.write(k2, Conn::new(11, 2, INVALID_BUF, 200));
        }
        slab.free(k2);
        let k3 = slab.alloc().expect("alloc 3");
        assert_eq!(k2.idx, k3.idx);
    }

    fn make_slowloris_guard(
        headers_timeout_secs: u64,
        min_recv_rate_bps: u64,
        max_incomplete_conns_per_ip: u32,
    ) -> SlowlorisGuard {
        let mut cfg = L7ProtectionConfig::default();
        cfg.slowloris.enabled = true;
        cfg.slowloris.headers_timeout_secs = headers_timeout_secs;
        cfg.slowloris.min_recv_rate_bps = min_recv_rate_bps;
        cfg.slowloris.max_incomplete_conns_per_ip = max_incomplete_conns_per_ip;
        SlowlorisGuard::new(&cfg)
    }

    #[test]
    fn slowloris_tracking_enforces_incomplete_cap_and_releases_on_stop() {
        let guard = make_slowloris_guard(10, 1, 1);

        let mut c1 = Conn::new(10, 1, INVALID_BUF, 1_000);
        c1.client_ip = "198.51.100.10".to_string();
        let mut c2 = Conn::new(11, 2, INVALID_BUF, 1_000);
        c2.client_ip = "198.51.100.10".to_string();

        let d1 = Worker::slowloris_start_tracking(&guard, &mut c1, 1_000);
        assert_eq!(d1, SlowlorisDecision::Allow);
        assert!(c1.slowloris_tracking);
        assert_ne!(c1.slowloris_ip_hash, 0);

        let d2 = Worker::slowloris_start_tracking(&guard, &mut c2, 1_000);
        assert_eq!(d2, SlowlorisDecision::DropTooManyIncomplete);
        assert!(!c2.slowloris_tracking);

        Worker::slowloris_stop_tracking(Some(&guard), &mut c1);
        assert!(!c1.slowloris_tracking);

        // After releasing one incomplete slot, same IP should pass again.
        let d3 = Worker::slowloris_start_tracking(&guard, &mut c2, 2_000);
        assert_eq!(d3, SlowlorisDecision::Allow);
        assert!(c2.slowloris_tracking);
    }

    #[test]
    fn slowloris_header_and_deadline_logic_is_applied() {
        let guard_rate = make_slowloris_guard(10, 100, 8);
        let mut c = Conn::new(12, 3, INVALID_BUF, 1_000_000_000);
        c.client_ip = "203.0.113.8".to_string();
        assert_eq!(
            Worker::slowloris_start_tracking(&guard_rate, &mut c, 1_000_000_000),
            SlowlorisDecision::Allow
        );

        // 10 bytes in 2 seconds => 5 B/s, below configured 100 B/s.
        let min_rate =
            Worker::slowloris_on_header_bytes(Some(&guard_rate), &mut c, 3_000_000_000, 10);
        assert_eq!(min_rate, SlowlorisDecision::DropMinRate);

        let fallback_deadline = 30_000_000_000u64;
        let got_deadline = Worker::slowloris_deadline_ns(Some(&guard_rate), &c, fallback_deadline);
        assert_eq!(got_deadline, 11_000_000_000);

        let guard_timeout = make_slowloris_guard(1, 1, 8);
        let mut c2 = Conn::new(13, 4, INVALID_BUF, 0);
        c2.client_ip = "203.0.113.9".to_string();
        assert_eq!(
            Worker::slowloris_start_tracking(&guard_timeout, &mut c2, 0),
            SlowlorisDecision::Allow
        );
        let timed_out =
            Worker::slowloris_on_header_bytes(Some(&guard_timeout), &mut c2, 1_500_000_000, 1024);
        assert_eq!(timed_out, SlowlorisDecision::DropTimeout);
    }

    #[test]
    fn slowloris_rebind_moves_incomplete_counter_from_peer_to_real_ip() {
        let guard = make_slowloris_guard(10, 1, 1);

        let mut tracked = Conn::new(100, 10, INVALID_BUF, 1_000);
        tracked.client_ip = "10.0.0.1".to_string();
        assert_eq!(
            Worker::slowloris_start_tracking(&guard, &mut tracked, 1_000),
            SlowlorisDecision::Allow
        );
        assert!(tracked.slowloris_tracking);

        let mut blocked_on_peer = Conn::new(101, 11, INVALID_BUF, 1_000);
        blocked_on_peer.client_ip = "10.0.0.1".to_string();
        assert_eq!(
            Worker::slowloris_start_tracking(&guard, &mut blocked_on_peer, 1_000),
            SlowlorisDecision::DropTooManyIncomplete
        );

        assert_eq!(
            Worker::slowloris_rebind_client_ip(Some(&guard), &mut tracked, "198.51.100.7"),
            SlowlorisDecision::Allow
        );
        assert_eq!(tracked.client_ip, "198.51.100.7");

        let mut now_peer_allows = Conn::new(102, 12, INVALID_BUF, 1_000);
        now_peer_allows.client_ip = "10.0.0.1".to_string();
        assert_eq!(
            Worker::slowloris_start_tracking(&guard, &mut now_peer_allows, 1_000),
            SlowlorisDecision::Allow
        );

        let mut real_ip_now_limited = Conn::new(103, 13, INVALID_BUF, 1_000);
        real_ip_now_limited.client_ip = "198.51.100.7".to_string();
        assert_eq!(
            Worker::slowloris_start_tracking(&guard, &mut real_ip_now_limited, 1_000),
            SlowlorisDecision::DropTooManyIncomplete
        );
    }

    #[test]
    fn keepalive_reset_clears_request_state_and_keeps_connection_identity() {
        let mut c = Conn::new(33, 7, INVALID_BUF, 1_000);
        c.client_ip = "198.51.100.88".to_string();
        c.client_port = 44321;
        c.req_keepalive = true;
        c.resp_keepalive = true;
        c.req_body = HttpBodyState::ContentLength { remaining: 12 };
        c.resp_body = HttpBodyState::UntilEof;
        c.route_selected = true;
        c.route_id = 42;
        c.upstream_reused = true;
        c.retry_count = 3;
        c.retry_allowed = true;
        c.request_id = 1234;
        c.request_id_text = "req-1".to_string();
        c.error_page_hops = 1;
        c.replay_len = 32;
        c.log_active = true;
        c.log_trace_id = "t".to_string();
        c.log_span_id = "s".to_string();
        c.log_traceparent = "tp".to_string();
        c.log_method = "GET".to_string();
        c.log_path = "/x".to_string();
        c.log_query = "a=1".to_string();
        c.log_host = "example.com".to_string();
        c.timeout_tier_ns = Some(RouteTimeoutTierNs {
            connect_ns: 1,
            response_header_ns: 2,
            per_try_ns: 3,
        });
        c.timeout_state = Some(RequestTimeoutState::start(1, 10));
        c.request_started_ns = 9;
        c.upstream_status = 503;

        reset_conn_for_next_keepalive_request(&mut c);

        assert_eq!(c.state, ConnState::CliReadHead);
        assert_eq!(c.buf_len, 0);
        assert_eq!(c.buf_off, 0);
        assert_eq!(c.header_end, 0);
        assert!(!c.req_keepalive);
        assert!(!c.resp_keepalive);
        assert!(matches!(c.req_body, HttpBodyState::None));
        assert!(matches!(c.resp_body, HttpBodyState::None));
        assert!(!c.route_selected);
        assert_eq!(c.route_id, 0);
        assert_eq!(c.retry_count, 0);
        assert!(!c.retry_allowed);
        assert_eq!(c.request_id, 0);
        assert!(c.request_id_text.is_empty());
        assert_eq!(c.error_page_hops, 0);
        assert_eq!(c.replay_len, 0);
        assert!(!c.log_active);
        assert!(c.log_trace_id.is_empty());
        assert!(c.log_span_id.is_empty());
        assert!(c.log_traceparent.is_empty());
        assert!(c.log_method.is_empty());
        assert!(c.log_path.is_empty());
        assert!(c.log_query.is_empty());
        assert!(c.log_host.is_empty());
        assert!(c.timeout_tier_ns.is_none());
        assert!(c.timeout_state.is_none());
        assert_eq!(c.request_started_ns, 0);
        assert_eq!(c.upstream_status, 0);

        // keepalive should preserve connection identity
        assert_eq!(c.client_ip, "198.51.100.88");
        assert_eq!(c.client_port, 44321);
    }

    #[test]
    fn h2_pending_counter_is_independent_per_downstream() {
        let d1 = H2ConnKey::new(1, 1);
        let d2 = H2ConnKey::new(2, 1);
        let mut map = HashMap::new();
        map.insert(d1, 2);
        map.insert(d2, 1);

        let left_d1 = h2_down_pending_dec_map(&mut map, d1);
        assert_eq!(left_d1, 1);
        assert_eq!(map.get(&d1).copied(), Some(1));
        assert_eq!(map.get(&d2).copied(), Some(1));

        let left_d2 = h2_down_pending_dec_map(&mut map, d2);
        assert_eq!(left_d2, 0);
        assert!(!map.contains_key(&d2));
        assert_eq!(map.get(&d1).copied(), Some(1));
    }

    #[test]
    fn h2_unlink_releases_only_target_stream_state() {
        let d1 = H2ConnKey::new(10, 1);
        let d2 = H2ConnKey::new(11, 1);
        let k1 = Key { idx: 101, gen: 1 };
        let k2 = Key { idx: 102, gen: 1 };
        let k3 = Key { idx: 201, gen: 1 };
        let mut tasks_by_down = HashMap::<H2ConnKey, Vec<Key>>::new();
        tasks_by_down.insert(d1, vec![k1, k2]);
        tasks_by_down.insert(d2, vec![k3]);

        h2_unlink_task_from_down_map(&mut tasks_by_down, d1, k1);
        let remain_d1 = tasks_by_down.get(&d1).cloned().unwrap_or_default();
        assert_eq!(remain_d1.len(), 1);
        assert_eq!(remain_d1[0], k2);
        assert_eq!(
            tasks_by_down.get(&d2).cloned().unwrap_or_default(),
            vec![k3]
        );

        h2_unlink_task_from_down_map(&mut tasks_by_down, d1, k2);
        assert!(!tasks_by_down.contains_key(&d1));
        assert_eq!(
            tasks_by_down.get(&d2).cloned().unwrap_or_default(),
            vec![k3]
        );
    }

    #[test]
    fn h2_build_h1_request_injects_request_id_when_missing() {
        let head = H2RequestHead {
            method: Bytes::from_static(b"GET"),
            authority: Some(Bytes::from_static(b"example.com")),
            path: Some(Bytes::from_static(b"/")),
            headers: vec![],
        };
        let req = Worker::h2_build_h1_request_with_policies(
            &head,
            &[],
            "127.0.0.1:18080"
                .parse::<SocketAddr>()
                .expect("socket addr"),
            &arc_config::forward_policies::ForwardPolicy::default(),
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            None,
            "X-Request-Id",
            "generated-id",
            true,
            None,
        );
        let text = String::from_utf8_lossy(req.as_slice());
        assert!(text.contains("\r\nX-Request-Id: generated-id\r\n"));
    }

    #[test]
    fn h2_build_h1_request_keeps_client_request_id() {
        let head = H2RequestHead {
            method: Bytes::from_static(b"GET"),
            authority: Some(Bytes::from_static(b"example.com")),
            path: Some(Bytes::from_static(b"/")),
            headers: vec![H2Header {
                name: Bytes::from_static(b"x-request-id"),
                value: Bytes::from_static(b"client-id"),
            }],
        };
        let req = Worker::h2_build_h1_request_with_policies(
            &head,
            &[],
            "127.0.0.1:18080"
                .parse::<SocketAddr>()
                .expect("socket addr"),
            &arc_config::forward_policies::ForwardPolicy::default(),
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            None,
            "X-Request-Id",
            "generated-id",
            false,
            None,
        );
        let text = String::from_utf8_lossy(req.as_slice());
        assert!(text.contains("\r\nx-request-id: client-id\r\n"));
        assert!(!text.contains("generated-id"));
    }

    #[test]
    fn h2_build_h1_request_override_request_id_preserves_original() {
        let head = H2RequestHead {
            method: Bytes::from_static(b"GET"),
            authority: Some(Bytes::from_static(b"example.com")),
            path: Some(Bytes::from_static(b"/")),
            headers: vec![H2Header {
                name: Bytes::from_static(b"x-request-id"),
                value: Bytes::from_static(b"client-id"),
            }],
        };
        let req = Worker::h2_build_h1_request_with_policies(
            &head,
            &[],
            "127.0.0.1:18080"
                .parse::<SocketAddr>()
                .expect("socket addr"),
            &arc_config::forward_policies::ForwardPolicy::default(),
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            None,
            "X-Request-Id",
            "generated-id",
            true,
            Some("client-id"),
        );
        let text = String::from_utf8_lossy(req.as_slice());
        assert!(text.contains("\r\nX-Request-Id: generated-id\r\n"));
        assert!(text.contains("\r\nx-original-request-id: client-id\r\n"));
        assert!(!text.contains("\r\nx-request-id: client-id\r\n"));
    }

    #[test]
    fn request_id_conflict_honors_trusted_proxies() {
        let mut trusted = [0u8; 16];
        trusted[..4].copy_from_slice(&[10, 0, 0, 0]);
        let cfg = CompiledRequestIdConfig {
            header: Arc::from("X-Request-Id"),
            format: RequestIdFormatConfig::UuidV7,
            on_conflict: RequestIdConflictConfig::Override,
            preserve_original: true,
            trusted_proxies: Arc::from([TrustedProxyCidr {
                addr: trusted,
                prefix_len: 8,
                is_ipv4: true,
            }]),
        };

        let trusted_peer =
            resolve_request_id_decision("10.1.2.3", Some("client-id".to_string()), &cfg);
        assert_eq!(trusted_peer.value, "client-id");
        assert!(!trusted_peer.force_set);
        assert!(trusted_peer.original.is_none());

        let untrusted_peer =
            resolve_request_id_decision("203.0.113.9", Some("client-id".to_string()), &cfg);
        assert!(untrusted_peer.force_set);
        assert_eq!(untrusted_peer.original.as_deref(), Some("client-id"));
        assert_ne!(untrusted_peer.value, "client-id");
    }

    fn compile_test_cfg_result(routes_json: &str) -> arc_common::Result<SharedConfig> {
        let raw = format!(
            r#"{{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {{
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  }},
  "buffers": {{ "buf_size": 8192, "buf_count": 64 }},
  "timeouts_ms": {{
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  }},
  "upstreams": [
    {{ "name": "u1", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }},
    {{ "name": "u2", "addr": "127.0.0.1:19081", "keepalive": 8, "idle_ttl_ms": 1000 }}
  ],
  "plugins": [],
  "routes": {routes_json}
}}"#
        );
        ConfigManager::compile_raw_json(raw.as_str())
    }

    fn compile_test_cfg(routes_json: &str) -> SharedConfig {
        compile_test_cfg_result(routes_json).expect("compile test config")
    }

    #[test]
    fn route_dispatch_prefers_higher_priority_for_same_path() {
        let cfg = compile_test_cfg(
            r#"[
  {
    "path": "/api",
    "upstream": "u1",
    "priority": 1,
    "matchers": [
      { "type": "method", "methods": ["GET"] },
      { "type": "host", "hosts": ["example.com"] }
    ]
  },
  {
    "path": "/api",
    "upstream": "u2",
    "priority": 9,
    "matchers": [
      { "type": "method", "methods": ["GET"] },
      { "type": "host", "hosts": ["example.com"] }
    ]
  }
]"#,
        );

        let req_head = b"GET /api?q=1 HTTP/1.1\r\nHost: Example.com:80\r\n\r\n";
        let selected =
            select_route_http1_from_cfg(&cfg, b"GET", b"/api?q=1", req_head, None, false)
                .expect("route selected");

        assert_eq!(cfg.routes[selected as usize].priority, 9);
    }

    #[test]
    fn route_dispatch_reports_ambiguous_when_priority_and_specificity_tie() {
        let err = compile_test_cfg_result(
            r#"[
  {
    "path": "/api",
    "upstream": "u1",
    "priority": 5,
    "matchers": [
      { "type": "method", "methods": ["GET"] },
      { "type": "host", "hosts": ["example.com"] }
    ]
  },
  {
    "path": "/api",
    "upstream": "u2",
    "priority": 5,
    "matchers": [
      { "type": "method", "methods": ["GET"] },
      { "type": "host", "hosts": ["example.com"] }
    ]
  }
]"#,
        )
        .expect_err("ambiguous config should fail at compile time");

        assert!(err.to_string().contains("ambiguous routes with same path/priority/specificity"));
    }

    #[test]
    fn route_dispatch_returns_not_found_when_matchers_do_not_match() {
        let cfg = compile_test_cfg(
            r#"[
  {
    "path": "/api",
    "upstream": "u1",
    "priority": 5,
    "matchers": [
      { "type": "method", "methods": ["POST"] },
      { "type": "host", "hosts": ["example.com"] }
    ]
  }
]"#,
        );

        let req_head = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let res = select_route_http1_from_cfg(&cfg, b"GET", b"/api", req_head, None, false);
        assert_eq!(res, Err(RouteSelectError::NotFound));
    }
}
