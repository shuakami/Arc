use arc_common::{ArcError, Result};
use arc_plugins::PluginCatalog;
use arc_rate_limit::Limiter;
use arc_router::Router;
use arc_swap::ArcSwap;
use bytes::Bytes;
pub mod forward_policies;
pub mod policy_compression;
pub mod policy_mirror;
pub mod policy_timeout;
mod route_rules;
use forward_policies::{
    compile_forward_policy, compile_upstreams, CompiledHeaderMutation, ForwardPolicy,
    HeaderMutation, LoadBalanceConfig, RetryPolicy, RewriteRule, RouteUpstreams,
    TrafficSplitConfig,
};
use policy_compression::{
    CompressionConfig, EffectiveCompressionGlobal, EffectiveCompressionRoute,
    RouteCompressionConfig,
};
use policy_mirror::{MirrorConfig, MirrorPolicyConfig, MirrorTargetConfig};
use policy_timeout::{EffectiveTimeoutTier, TimeoutTierConfig};
pub use route_rules::{
    build_http1_response_bytes, RouteAction, RouteActionSpec, RouteMatcher, RouteMatcherSpec,
};
use route_rules::{compile_action, compile_matchers};

use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

static CONFIG_RELOAD_DURATION_MS_SUM: AtomicU64 = AtomicU64::new(0);
static CONFIG_RELOAD_DURATION_MS_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn config_reload_duration_ms_sum() -> u64 {
    CONFIG_RELOAD_DURATION_MS_SUM.load(Ordering::Relaxed)
}
pub fn config_reload_duration_ms_count() -> u64 {
    CONFIG_RELOAD_DURATION_MS_COUNT.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSourceFormat {
    Json,
    Toml,
    Yaml,
}

impl ConfigSourceFormat {
    fn from_path(path: &Path) -> Result<Self> {
        let Some(ext) = path.extension().and_then(|v| v.to_str()) else {
            return Err(ArcError::config(format!(
                "unsupported config file extension for '{}': expected .json/.toml/.yaml/.yml",
                path.display()
            )));
        };
        let ext = ext.to_ascii_lowercase();
        match ext.as_str() {
            "json" => Ok(Self::Json),
            "toml" => Ok(Self::Toml),
            "yaml" | "yml" => Ok(Self::Yaml),
            _ => Err(ArcError::config(format!(
                "unsupported config file extension '.{ext}' for '{}': expected .json/.toml/.yaml/.yml",
                path.display()
            ))),
        }
    }
}

fn parse_config_text_with_format(
    raw: &str,
    format: ConfigSourceFormat,
) -> Result<(ConfigFile, Arc<str>)> {
    match format {
        ConfigSourceFormat::Json => {
            let cfg: ConfigFile = serde_json::from_str(raw).map_err(|e| {
                ArcError::config(format!(
                    "invalid json config at line {}, column {}: {e}",
                    e.line(),
                    e.column()
                ))
            })?;
            Ok((cfg, Arc::from(raw)))
        }
        ConfigSourceFormat::Toml => {
            let cfg: ConfigFile = toml::from_str(raw)
                .map_err(|e| ArcError::config(format!("invalid toml config: {e}")))?;
            let value: JsonValue = toml::from_str(raw)
                .map_err(|e| ArcError::config(format!("invalid toml config: {e}")))?;
            let canonical = canonical_json_from_value(value)?;
            Ok((cfg, canonical))
        }
        ConfigSourceFormat::Yaml => {
            let cfg: ConfigFile = serde_yaml::from_str(raw).map_err(|e| match e.location() {
                Some(loc) => ArcError::config(format!(
                    "invalid yaml config at line {}, column {}: {e}",
                    loc.line(),
                    loc.column()
                )),
                None => ArcError::config(format!("invalid yaml config: {e}")),
            })?;
            let value: JsonValue = serde_yaml::from_str(raw).map_err(|e| match e.location() {
                Some(loc) => ArcError::config(format!(
                    "invalid yaml config at line {}, column {}: {e}",
                    loc.line(),
                    loc.column()
                )),
                None => ArcError::config(format!("invalid yaml config: {e}")),
            })?;
            let canonical = canonical_json_from_value(value)?;
            Ok((cfg, canonical))
        }
    }
}

fn canonical_json_from_value(mut value: JsonValue) -> Result<Arc<str>> {
    sort_json_object_keys(&mut value);
    let s = serde_json::to_string(&value)
        .map_err(|e| ArcError::config(format!("serialize canonical json config failed: {e}")))?;
    Ok(Arc::from(s))
}

fn sort_json_object_keys(v: &mut JsonValue) {
    match v {
        JsonValue::Object(map) => {
            let mut entries: Vec<(String, JsonValue)> = std::mem::take(map).into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, val) in entries.iter_mut() {
                sort_json_object_keys(val);
            }
            for (k, val) in entries {
                map.insert(k, val);
            }
        }
        JsonValue::Array(arr) => {
            for item in arr.iter_mut() {
                sort_json_object_keys(item);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConfigFile {
    pub listen: String,
    pub admin_listen: String,
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: i32,

    pub workers: usize,
    #[serde(default = "default_linger_ms")]
    pub linger_ms: u32,

    pub io_uring: IoUringConfig,
    pub buffers: BufferConfig,
    pub timeouts_ms: TimeoutConfig,
    #[serde(default = "default_true")]
    pub require_upstream_mtls: bool,

    pub upstreams: Vec<UpstreamConfig>,
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub http2: Http2Config,
    #[serde(default)]
    pub request_id: RequestIdConfig,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub compression: CompressionConfig,
    #[serde(default)]
    pub downstream_tls: Option<DownstreamTlsConfig>,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
    #[serde(default)]
    pub global_rate_limit: GlobalRateLimitConfig,
    #[serde(default)]
    pub cluster_circuit: ClusterCircuitPolicyConfig,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct LimitsConfig {
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_upstream_leak_warn_growth")]
    pub upstream_leak_warn_growth: usize,
    #[serde(default = "default_upstream_leak_warn_window_ms")]
    pub upstream_leak_warn_window_ms: u64,
    #[serde(default = "default_upstream_leak_warn_cooldown_ms")]
    pub upstream_leak_warn_cooldown_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: default_max_request_body_bytes(),
            upstream_leak_warn_growth: default_upstream_leak_warn_growth(),
            upstream_leak_warn_window_ms: default_upstream_leak_warn_window_ms(),
            upstream_leak_warn_cooldown_ms: default_upstream_leak_warn_cooldown_ms(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RouteLimitsConfig {
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlRole {
    Standalone,
    Leader,
    Follower,
}

impl Default for ControlRole {
    fn default() -> Self {
        Self::Standalone
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ControlPlaneConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_control_bind")]
    pub bind: String,
    #[serde(default)]
    pub role: ControlRole,
    #[serde(default = "default_control_node_id")]
    pub node_id: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub quorum: usize,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub pull_from: Option<String>,
    #[serde(default = "default_control_pull_interval_ms")]
    pub pull_interval_ms: u64,
    #[serde(default = "default_control_peer_timeout_ms")]
    pub peer_timeout_ms: u64,

    // NEW (SOTA): follower sync uses long-poll (zero-waste pull)
    #[serde(default = "default_control_longpoll_timeout_ms")]
    pub longpoll_timeout_ms: u64,

    // NEW: cluster fanout concurrency cap
    #[serde(default = "default_control_peer_concurrency")]
    pub peer_concurrency: usize,

    // NEW: isolate control runtime sizing (control.rs uses this)
    #[serde(default = "default_control_runtime_threads")]
    pub runtime_threads: usize,

    // NEW: hard CPU work (json parse + compile) threads cap
    #[serde(default = "default_control_compile_threads")]
    pub compile_threads: usize,

    // NEW: body limit override for control plane endpoints
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_control_bind(),
            role: ControlRole::Standalone,
            node_id: default_control_node_id(),
            peers: Vec::new(),
            quorum: 0,
            auth_token: None,
            pull_from: None,
            pull_interval_ms: default_control_pull_interval_ms(),
            peer_timeout_ms: default_control_peer_timeout_ms(),
            longpoll_timeout_ms: default_control_longpoll_timeout_ms(),
            peer_concurrency: default_control_peer_concurrency(),
            runtime_threads: default_control_runtime_threads(),
            compile_threads: default_control_compile_threads(),
            max_body_bytes: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct IoUringConfig {
    #[serde(default = "default_io_uring_entries")]
    pub entries: u32,
    pub accept_multishot: bool,
    #[serde(default = "default_accept_prepost")]
    pub accept_prepost: u32,
    pub tick_ms: u32,
    pub sqpoll: bool,
    pub sqpoll_idle_ms: u32,
    pub iopoll: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BufferConfig {
    pub buf_size: usize,
    pub buf_count: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TimeoutConfig {
    #[serde(default = "default_cli_handshake_ms")]
    pub cli_handshake: u64,
    pub cli_read: u64,
    pub up_conn: u64,
    #[serde(default = "default_up_handshake_ms")]
    pub up_handshake: u64,
    pub up_write: u64,
    pub up_read: u64,
    pub cli_write: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_upstream_keepalive")]
    pub keepalive: usize,
    pub idle_ttl_ms: u64,
    #[serde(default = "default_dns_refresh_ms")]
    pub dns_refresh_ms: u64,
    #[serde(default)]
    pub max_connections: Option<usize>,
    #[serde(default)]
    pub tls: Option<UpstreamTlsConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamTlsConfig {
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub ca_pem: Option<String>,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    #[serde(default)]
    pub verify_server: Option<bool>,
    #[serde(default = "default_true")]
    pub enable_resumption: bool,
    #[serde(default)]
    pub min_version: Option<TlsMinVersionConfig>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum TlsMinVersionConfig {
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    V1_3,
}

impl Default for TlsMinVersionConfig {
    fn default() -> Self {
        Self::V1_2
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct TlsDownstreamConfig {
    #[serde(default)]
    pub min_version: TlsMinVersionConfig,
}

impl Default for TlsDownstreamConfig {
    fn default() -> Self {
        Self {
            min_version: TlsMinVersionConfig::V1_2,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct TlsUpstreamConfig {
    #[serde(default)]
    pub min_version: TlsMinVersionConfig,
    #[serde(default = "default_true")]
    pub verify_server: bool,
}

impl Default for TlsUpstreamConfig {
    fn default() -> Self {
        Self {
            min_version: TlsMinVersionConfig::V1_2,
            verify_server: true,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct TlsConfig {
    #[serde(default)]
    pub downstream: TlsDownstreamConfig,
    #[serde(default)]
    pub upstream: TlsUpstreamConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            downstream: TlsDownstreamConfig::default(),
            upstream: TlsUpstreamConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Http2OverflowActionConfig {
    RstRefused,
}

impl Default for Http2OverflowActionConfig {
    fn default() -> Self {
        Self::RstRefused
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct Http2Config {
    #[serde(default = "default_http2_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default = "default_http2_max_active_streams")]
    pub max_active_streams: usize,
    #[serde(default)]
    pub overflow_action: Http2OverflowActionConfig,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            max_concurrent_streams: default_http2_max_concurrent_streams(),
            max_active_streams: default_http2_max_active_streams(),
            overflow_action: Http2OverflowActionConfig::RstRefused,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestIdFormatConfig {
    UuidV7,
}

impl Default for RequestIdFormatConfig {
    fn default() -> Self {
        Self::UuidV7
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestIdConflictConfig {
    Override,
    Preserve,
}

impl Default for RequestIdConflictConfig {
    fn default() -> Self {
        Self::Override
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RequestIdConfig {
    #[serde(default = "default_request_id_header")]
    pub header: String,
    #[serde(default)]
    pub format: RequestIdFormatConfig,
    #[serde(default)]
    pub on_conflict: RequestIdConflictConfig,
    #[serde(default = "default_true")]
    pub preserve_original: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for RequestIdConfig {
    fn default() -> Self {
        Self {
            header: default_request_id_header(),
            format: RequestIdFormatConfig::UuidV7,
            on_conflict: RequestIdConflictConfig::Override,
            preserve_original: true,
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PluginConfig {
    pub name: String,
    pub path: String,
    pub pool: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub rps: u64,
    pub burst: u64,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPageWhen {
    Any,
    UpstreamError,
}

impl Default for ErrorPageWhen {
    fn default() -> Self {
        Self::Any
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ErrorPageConfig {
    #[serde(default)]
    pub when: ErrorPageWhen,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub redirect: Option<String>,
    #[serde(default)]
    pub code: Option<u16>,
    #[serde(default)]
    pub upstream: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct DefaultsConfig {
    #[serde(default)]
    pub error_pages: HashMap<String, ErrorPageConfig>,
    #[serde(default)]
    pub timeout: Option<TimeoutTierConfig>,
    #[serde(default)]
    pub mirror_policy: Option<MirrorPolicyConfig>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GlobalRateLimitBackend {
    InMemory,
    Redis,
}

impl Default for GlobalRateLimitBackend {
    fn default() -> Self {
        Self::InMemory
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct GlobalRateLimitRedisConfig {
    pub url: String,
    #[serde(default = "default_global_rate_limit_redis_budget_ms")]
    pub budget_ms: u64,
    #[serde(default = "default_global_rate_limit_redis_circuit_open_ms")]
    pub circuit_open_ms: u64,
    #[serde(default = "default_global_rate_limit_redis_prefetch")]
    pub prefetch: u32,
    #[serde(default = "default_global_rate_limit_redis_low_watermark")]
    pub low_watermark: u32,
    #[serde(default = "default_global_rate_limit_redis_refill_backoff_ms")]
    pub refill_backoff_ms: u64,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct GlobalRateLimitConfig {
    #[serde(default)]
    pub backend: GlobalRateLimitBackend,
    #[serde(default)]
    pub redis: Option<GlobalRateLimitRedisConfig>,
}

impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            backend: GlobalRateLimitBackend::InMemory,
            redis: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ClusterCircuitPolicyConfig {
    #[serde(default = "default_cluster_circuit_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_cluster_circuit_open_ms")]
    pub circuit_open_ms: u64,
    #[serde(default = "default_cluster_circuit_quorum")]
    pub quorum: usize,
    #[serde(default = "default_cluster_circuit_half_open_probe_interval_ms")]
    pub half_open_probe_interval_ms: u64,
    #[serde(default = "default_cluster_circuit_active_probe_enabled")]
    pub active_probe_enabled: bool,
    #[serde(default = "default_cluster_circuit_active_probe_interval_ms")]
    pub active_probe_interval_ms: u64,
    #[serde(default = "default_cluster_circuit_active_probe_timeout_ms")]
    pub active_probe_timeout_ms: u64,
}

impl Default for ClusterCircuitPolicyConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_cluster_circuit_failure_threshold(),
            circuit_open_ms: default_cluster_circuit_open_ms(),
            quorum: default_cluster_circuit_quorum(),
            half_open_probe_interval_ms: default_cluster_circuit_half_open_probe_interval_ms(),
            active_probe_enabled: default_cluster_circuit_active_probe_enabled(),
            active_probe_interval_ms: default_cluster_circuit_active_probe_interval_ms(),
            active_probe_timeout_ms: default_cluster_circuit_active_probe_timeout_ms(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub path: String,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub split: Option<TrafficSplitConfig>,
    #[serde(default)]
    pub load_balance: Option<LoadBalanceConfig>,
    #[serde(default)]
    pub rewrite: Option<RewriteRule>,
    #[serde(default)]
    pub headers: Vec<HeaderMutation>,
    #[serde(default)]
    pub response_headers: ResponseHeadersConfig,
    #[serde(default)]
    pub forwarded_for: bool,
    #[serde(default)]
    pub real_ip_header: Option<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub retry: RetryPolicy,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub matchers: Vec<RouteMatcherSpec>,
    #[serde(default)]
    pub action: RouteActionSpec,
    #[serde(default)]
    pub plugins: Vec<String>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub error_pages: HashMap<String, ErrorPageConfig>,
    #[serde(default)]
    pub timeout: Option<TimeoutTierConfig>,
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,
    #[serde(default)]
    pub compression: Option<RouteCompressionConfig>,
    #[serde(default)]
    pub limits: Option<RouteLimitsConfig>,
}

// ---------------- Downstream TLS + ACME ----------------

#[derive(Debug, Deserialize, Clone)]
pub struct DownstreamTlsConfig {
    #[serde(default = "default_true")]
    pub enable_h2: bool,
    #[serde(default)]
    pub min_version: Option<TlsMinVersionConfig>,
    /// Static certificates loaded from disk.
    #[serde(default)]
    pub certificates: Vec<DownstreamTlsCertConfig>,
    #[serde(default)]
    pub sni_routes: Vec<SniRouteConfig>,

    /// Optional ACME automation: managed certs can start missing on cold start.
    #[serde(default)]
    pub acme: Option<DownstreamAcmeConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DownstreamTlsCertConfig {
    pub sni: String,
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SniRouteConfig {
    pub sni: String,
    /// Bind SNI host(pattern) to an existing `routes[].path`.
    pub path: String,
}

// ---- ACME config (NEW) ----

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeAccountKeyAlgorithm {
    Ed25519,
    Rsa2048,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AcmePassphraseSourceConfig {
    Env { name: String },
    File { path: String },
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeAccountKeyConfig {
    pub algorithm: AcmeAccountKeyAlgorithm,
    pub encrypted_key_path: String,
    pub passphrase: AcmePassphraseSourceConfig,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallengeType {
    Http01,
    TlsAlpn01,
    Dns01,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeHttp01Config {
    pub listen: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsHookConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,

    #[serde(default = "default_acme_dns_propagation_timeout_secs")]
    pub propagation_timeout_secs: u64,
    #[serde(default = "default_acme_dns_poll_interval_secs")]
    pub poll_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeManagedCertConfig {
    /// ACME identifier (can be "*.example.com").
    pub domain: String,
    /// Where to write cert chain PEM.
    pub cert_pem: String,
    /// Where to write leaf private key PEM.
    pub key_pem: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DownstreamAcmeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_lets_encrypt_directory_url")]
    pub directory_url: String,

    /// Optional custom CA bundle (PEM) to trust for ACME HTTPS endpoint.
    #[serde(default)]
    pub directory_ca_pem: Option<String>,

    #[serde(default)]
    pub email: Option<String>,

    pub account_key: AcmeAccountKeyConfig,

    /// Challenge preference order (e.g. ["tls_alpn01","http01","dns01"]).
    #[serde(default = "default_acme_challenge_priority")]
    pub challenge_priority: Vec<AcmeChallengeType>,

    #[serde(default)]
    pub dns_hook: Option<DnsHookConfig>,

    #[serde(default)]
    pub http01: Option<AcmeHttp01Config>,

    #[serde(default = "default_acme_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Members list for rendezvous hashing; empty => [control_plane.node_id].
    #[serde(default)]
    pub members: Vec<String>,

    /// Managed certificates.
    #[serde(default)]
    pub certificates: Vec<AcmeManagedCertConfig>,
}

/// Compiled config shared by all workers (read-only, Sync).
#[derive(Debug)]
pub struct SharedConfig {
    /// Deterministic config generation (stable across nodes):
    /// hash(raw_json + referenced file contents).
    pub generation: u64,
    pub raw_json: Arc<str>,

    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub listen_backlog: i32,

    pub workers: usize,
    pub linger_ms: u32,
    pub io_uring: IoUringConfig,
    pub buffers: BufferConfig,
    pub timeouts_ms: TimeoutConfig,

    pub router: Router,
    pub routes: Arc<[CompiledRoute]>,
    pub route_candidate_groups: Arc<[Arc<[u32]>]>,
    pub upstreams: Arc<[CompiledUpstream]>,
    pub control_plane: ControlPlaneConfig,
    pub global_rate_limit: GlobalRateLimitConfig,
    pub cluster_circuit: ClusterCircuitPolicyConfig,
    pub compression: EffectiveCompressionGlobal,
    pub limits: LimitsConfig,
    pub http2: Http2Config,
    pub request_id: CompiledRequestIdConfig,
    pub default_error_pages: Arc<[CompiledErrorPageRule]>,

    pub plugins: Arc<CompiledPlugins>,
    pub downstream_tls: Option<Arc<CompiledDownstreamTls>>,
}

pub fn restart_required_changes(old: &SharedConfig, new: &SharedConfig) -> Vec<&'static str> {
    let mut changed = Vec::new();
    macro_rules! push_if_changed {
        ($path:literal, $old:expr, $new:expr) => {
            if $old != $new {
                changed.push($path);
            }
        };
    }

    // startup-bound sockets / workers
    push_if_changed!("listen", old.listen, new.listen);
    push_if_changed!("admin_listen", old.admin_listen, new.admin_listen);
    push_if_changed!("listen_backlog", old.listen_backlog, new.listen_backlog);
    push_if_changed!("workers", old.workers, new.workers);

    // io_uring ring lifecycle (startup-time)
    push_if_changed!(
        "io_uring.entries",
        old.io_uring.entries,
        new.io_uring.entries
    );
    push_if_changed!(
        "io_uring.accept_multishot",
        old.io_uring.accept_multishot,
        new.io_uring.accept_multishot
    );
    push_if_changed!(
        "io_uring.accept_prepost",
        old.io_uring.accept_prepost,
        new.io_uring.accept_prepost
    );
    push_if_changed!(
        "io_uring.tick_ms",
        old.io_uring.tick_ms,
        new.io_uring.tick_ms
    );
    push_if_changed!("io_uring.sqpoll", old.io_uring.sqpoll, new.io_uring.sqpoll);
    push_if_changed!(
        "io_uring.sqpoll_idle_ms",
        old.io_uring.sqpoll_idle_ms,
        new.io_uring.sqpoll_idle_ms
    );
    push_if_changed!("io_uring.iopoll", old.io_uring.iopoll, new.io_uring.iopoll);

    // fixed buffers are allocated/registered at startup
    push_if_changed!(
        "buffers.buf_size",
        old.buffers.buf_size,
        new.buffers.buf_size
    );
    push_if_changed!(
        "buffers.buf_count",
        old.buffers.buf_count,
        new.buffers.buf_count
    );

    // control plane runtime is bootstrapped once from boot config
    push_if_changed!(
        "control_plane.enabled",
        old.control_plane.enabled,
        new.control_plane.enabled
    );
    push_if_changed!(
        "control_plane.bind",
        old.control_plane.bind,
        new.control_plane.bind
    );
    push_if_changed!(
        "control_plane.role",
        old.control_plane.role,
        new.control_plane.role
    );
    push_if_changed!(
        "control_plane.node_id",
        old.control_plane.node_id,
        new.control_plane.node_id
    );
    push_if_changed!(
        "control_plane.peers",
        old.control_plane.peers,
        new.control_plane.peers
    );
    push_if_changed!(
        "control_plane.quorum",
        old.control_plane.quorum,
        new.control_plane.quorum
    );
    push_if_changed!(
        "control_plane.auth_token",
        old.control_plane.auth_token,
        new.control_plane.auth_token
    );
    push_if_changed!(
        "control_plane.pull_from",
        old.control_plane.pull_from,
        new.control_plane.pull_from
    );
    push_if_changed!(
        "control_plane.pull_interval_ms",
        old.control_plane.pull_interval_ms,
        new.control_plane.pull_interval_ms
    );
    push_if_changed!(
        "control_plane.peer_timeout_ms",
        old.control_plane.peer_timeout_ms,
        new.control_plane.peer_timeout_ms
    );
    push_if_changed!(
        "control_plane.longpoll_timeout_ms",
        old.control_plane.longpoll_timeout_ms,
        new.control_plane.longpoll_timeout_ms
    );
    push_if_changed!(
        "control_plane.peer_concurrency",
        old.control_plane.peer_concurrency,
        new.control_plane.peer_concurrency
    );
    push_if_changed!(
        "control_plane.runtime_threads",
        old.control_plane.runtime_threads,
        new.control_plane.runtime_threads
    );
    push_if_changed!(
        "control_plane.compile_threads",
        old.control_plane.compile_threads,
        new.control_plane.compile_threads
    );
    push_if_changed!(
        "control_plane.max_body_bytes",
        old.control_plane.max_body_bytes,
        new.control_plane.max_body_bytes
    );

    // global rate limiter backend/runtime is built at startup
    if old.global_rate_limit != new.global_rate_limit {
        changed.push("global_rate_limit");
    }

    // immutable cluster-circuit semantics
    push_if_changed!(
        "cluster_circuit.failure_threshold",
        old.cluster_circuit.failure_threshold,
        new.cluster_circuit.failure_threshold
    );
    push_if_changed!(
        "cluster_circuit.quorum",
        old.cluster_circuit.quorum,
        new.cluster_circuit.quorum
    );
    push_if_changed!(
        "cluster_circuit.active_probe_enabled",
        old.cluster_circuit.active_probe_enabled,
        new.cluster_circuit.active_probe_enabled
    );
    push_if_changed!(
        "cluster_circuit.active_probe_interval_ms",
        old.cluster_circuit.active_probe_interval_ms,
        new.cluster_circuit.active_probe_interval_ms
    );
    push_if_changed!(
        "cluster_circuit.active_probe_timeout_ms",
        old.cluster_circuit.active_probe_timeout_ms,
        new.cluster_circuit.active_probe_timeout_ms
    );

    changed
}

#[derive(Debug)]
pub struct CompiledUpstream {
    pub name: Arc<str>,
    pub addr: SocketAddr,
    pub host: Option<Arc<str>>,
    pub port: u16,
    pub keepalive: usize,
    pub idle_ttl_ms: u64,
    pub dns_refresh_ms: u64,
    pub max_connections: Option<usize>,
    pub tls: Option<Arc<CompiledUpstreamTls>>,
}

#[derive(Debug)]
pub struct CompiledRoute {
    pub path: Bytes,
    pub priority: i32,
    pub matchers: Arc<[RouteMatcher]>,
    pub action: RouteAction,
    pub upstreams: RouteUpstreams,
    pub forward: ForwardPolicy,
    pub response_header_muts: Arc<[CompiledHeaderMutation]>,
    pub plugin_ids: Arc<[usize]>,
    pub limiter: Option<Arc<Limiter>>,
    pub rate_limit_policy: Option<RateLimitPolicy>,
    pub error_pages: Arc<[CompiledErrorPageRule]>,
    pub timeout_tier: Option<CompiledTimeoutTier>,
    pub mirror_policy: Option<CompiledMirrorPolicy>,
    pub mirror_targets: Arc<[CompiledMirrorTarget]>,
    pub compression: EffectiveCompressionRoute,
    pub max_request_body_bytes: usize,
    pub forwarded_for: bool,
    pub real_ip_header: Arc<str>,
    pub trusted_proxies: Arc<[TrustedProxyCidr]>,
}

#[derive(Debug, Clone)]
pub struct CompiledRequestIdConfig {
    pub header: Arc<str>,
    pub format: RequestIdFormatConfig,
    pub on_conflict: RequestIdConflictConfig,
    pub preserve_original: bool,
    pub trusted_proxies: Arc<[TrustedProxyCidr]>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ResponseHeadersConfig {
    #[serde(default)]
    pub set: HashMap<String, String>,
    #[serde(default)]
    pub add: HashMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

impl CompiledRoute {
    #[inline]
    pub fn specificity(&self) -> u32 {
        (self.path.len() as u32) * 1024 + (self.matchers.len() as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxyCidr {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub is_ipv4: bool,
}

impl TrustedProxyCidr {
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        let (other, plen) = match ip {
            IpAddr::V4(v4) => {
                if !self.is_ipv4 {
                    return false;
                }
                let mut out = [0u8; 16];
                out[..4].copy_from_slice(&v4.octets());
                (out, 32usize)
            }
            IpAddr::V6(v6) => {
                if self.is_ipv4 {
                    return false;
                }
                (v6.octets(), 128usize)
            }
        };
        let prefix = (self.prefix_len as usize).min(plen);
        let full_bytes = prefix / 8;
        let rem_bits = prefix % 8;
        if full_bytes > 0 && self.addr[..full_bytes] != other[..full_bytes] {
            return false;
        }
        if rem_bits == 0 {
            return true;
        }
        let mask: u8 = 0xFFu8 << (8 - rem_bits);
        (self.addr[full_bytes] & mask) == (other[full_bytes] & mask)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    pub rps: u64,
    pub burst: u64,
}

#[derive(Debug, Clone)]
pub struct CompiledTimeoutTier {
    pub connect_ms: u64,
    pub response_header_ms: u64,
    pub per_try_ms: u64,
    pub total_ms: u64,
    pub deadline_propagation: Option<CompiledDeadlinePropagation>,
}

#[derive(Debug, Clone)]
pub struct CompiledDeadlinePropagation {
    pub header: Arc<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledMirrorOnDiff {
    Log,
}

#[derive(Debug, Clone)]
pub struct CompiledMirrorPolicy {
    pub max_queue_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct CompiledMirrorTarget {
    pub upstream_id: usize,
    pub sample: f64,
    pub timeout_ms: u64,
    pub transform_path: Option<Arc<str>>,
    pub transform_set_headers: Arc<[(Arc<str>, Arc<str>)]>,
    pub transform_remove_headers: Arc<[Arc<str>]>,
    pub compare_enabled: bool,
    pub compare_ignore_headers: Arc<[Arc<str>]>,
    pub compare_ignore_body_fields: Arc<[Arc<str>]>,
    pub compare_on_diff: CompiledMirrorOnDiff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledErrorPagePattern {
    Exact(u16),
    Class(u16),
    Range { start: u16, end: u16 },
}

impl CompiledErrorPagePattern {
    #[inline]
    pub fn matches(self, status: u16) -> bool {
        match self {
            CompiledErrorPagePattern::Exact(v) => status == v,
            CompiledErrorPagePattern::Class(v) => status / 100 == v,
            CompiledErrorPagePattern::Range { start, end } => status >= start && status <= end,
        }
    }

    #[inline]
    fn priority_key(self) -> (u8, u16, u16) {
        match self {
            CompiledErrorPagePattern::Exact(v) => (0, v, v),
            CompiledErrorPagePattern::Range { start, end } => {
                let width = end.saturating_sub(start);
                (1, width, start)
            }
            CompiledErrorPagePattern::Class(v) => (2, v, v),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CompiledErrorPageAction {
    Inline {
        template: Arc<[u8]>,
        content_type: Arc<str>,
    },
    Redirect {
        location: Arc<str>,
        code: u16,
    },
    Upstream {
        upstream_id: usize,
    },
}

#[derive(Debug, Clone)]
pub struct CompiledErrorPageRule {
    pub pattern: CompiledErrorPagePattern,
    pub when: ErrorPageWhen,
    pub action: CompiledErrorPageAction,
}

#[derive(Debug)]
pub struct CompiledUpstreamTls {
    pub server_name: Option<Arc<str>>,
    pub ca_pem: Option<Arc<[u8]>>,
    pub client_cert_pem: Arc<[u8]>,
    pub client_key_pem: Arc<[u8]>,
    pub verify_server: bool,
    pub enable_resumption: bool,
    pub min_version: TlsMinVersionConfig,
}

#[derive(Debug)]
pub struct CompiledPlugins {
    pub catalog: Option<PluginCatalog>,
    pub names: Arc<[Arc<str>]>,
}

#[derive(Debug)]
pub struct CompiledDownstreamTls {
    pub enable_h2: bool,
    pub min_version: TlsMinVersionConfig,
    pub certificates: Arc<[CompiledDownstreamCertificate]>,
    pub sni_routes: CompiledSniRoutes,

    /// ACME runtime config (control-plane thread will use this).
    pub acme: Option<Arc<CompiledDownstreamAcme>>,
}

#[derive(Debug)]
pub struct CompiledDownstreamCertificate {
    pub wildcard: bool,
    pub sni: Arc<str>,
    pub cert_pem: Arc<[u8]>,
    pub key_pem: Arc<[u8]>,
    /// true => allow empty cert/key on cold start (placeholder will be used).
    pub acme_managed: bool,
}

#[derive(Debug, Default)]
pub struct CompiledSniRoutes {
    exact: HashMap<Arc<str>, u32>,
    wildcard_suffix: Vec<(Arc<str>, u32)>,
}

impl CompiledSniRoutes {
    pub fn resolve_route(&self, sni: &str) -> Option<u32> {
        let host = normalize_sni_host(sni)?;
        if let Some(v) = self.exact.get(host.as_str()) {
            return Some(*v);
        }
        for (suffix, route_id) in &self.wildcard_suffix {
            if host.len() <= suffix.len() {
                continue;
            }
            if host.ends_with(suffix.as_ref())
                && host.as_bytes()[host.len().saturating_sub(suffix.len() + 1)] == b'.'
            {
                return Some(*route_id);
            }
        }
        None
    }
}

// ---- compiled ACME ----

#[derive(Debug)]
pub struct CompiledDownstreamAcme {
    pub enabled: bool,
    pub directory_url: Arc<str>,
    pub directory_ca_pem: Option<Arc<[u8]>>,
    pub email: Option<Arc<str>>,
    pub account_key: CompiledAcmeAccountKeyConfig,
    pub challenge_priority: Arc<[AcmeChallengeType]>,
    pub dns_hook: Option<Arc<CompiledDnsHookConfig>>,
    pub http01: Option<CompiledAcmeHttp01Config>,
    pub poll_interval_secs: u64,
    pub members: Arc<[Arc<str>]>,
    pub certificates: Arc<[CompiledAcmeManagedCert]>,
}

#[derive(Debug)]
pub struct CompiledAcmeAccountKeyConfig {
    pub algorithm: AcmeAccountKeyAlgorithm,
    pub encrypted_key_path: PathBuf,
    pub passphrase: CompiledAcmePassphraseSource,
}

#[derive(Debug, Clone)]
pub enum CompiledAcmePassphraseSource {
    Env { name: Arc<str> },
    File { path: PathBuf },
}

#[derive(Debug)]
pub struct CompiledDnsHookConfig {
    pub command: Arc<str>,
    pub args: Arc<[Arc<str>]>,
    pub env: Arc<[(Arc<str>, Arc<str>)]>,
    pub propagation_timeout_secs: u64,
    pub poll_interval_secs: u64,
}

#[derive(Debug)]
pub struct CompiledAcmeHttp01Config {
    pub listen: SocketAddr,
}

#[derive(Debug)]
pub struct CompiledAcmeManagedCert {
    pub domain: Arc<str>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Default)]
struct ConfigSignal {
    mu: Mutex<()>,
    cv: Condvar,
}

impl ConfigSignal {
    fn notify_all(&self) {
        let _g = self.mu.lock().unwrap_or_else(|p| p.into_inner());
        self.cv.notify_all();
    }

    fn wait_timeout(&self, timeout: Duration) {
        let g = self.mu.lock().unwrap_or_else(|p| p.into_inner());
        let _ = self.cv.wait_timeout(g, timeout);
    }
}

#[derive(Clone)]
pub struct ConfigManager {
    swap: Arc<ArcSwap<SharedConfig>>,
    signal: Arc<ConfigSignal>,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigCheckReport {
    pub errors: Vec<String>,
}

impl ConfigManager {
    pub fn new(initial: SharedConfig) -> Self {
        Self {
            swap: Arc::new(ArcSwap::from_pointee(initial)),
            signal: Arc::new(ConfigSignal::default()),
        }
    }

    #[inline]
    pub fn swap(&self) -> Arc<ArcSwap<SharedConfig>> {
        self.swap.clone()
    }

    #[inline]
    pub fn current(&self) -> Arc<SharedConfig> {
        self.swap.load_full()
    }

    #[inline]
    pub fn current_generation(&self) -> u64 {
        self.swap.load().generation
    }

    #[inline]
    pub fn current_raw_json(&self) -> Arc<str> {
        self.swap.load().raw_json.clone()
    }

    pub fn compile_raw_json(raw_json: &str) -> Result<SharedConfig> {
        let (cfg, canonical_json) =
            parse_config_text_with_format(raw_json, ConfigSourceFormat::Json)?;
        compile_config(cfg, canonical_json)
    }

    pub fn apply_compiled(&self, compiled: SharedConfig) -> u64 {
        let gen = compiled.generation;
        let cur = self.swap.load().generation;
        if cur == gen {
            return gen;
        }
        self.swap.store(Arc::new(compiled));
        self.signal.notify_all();
        gen
    }

    pub fn apply_raw_json(&self, raw_json: String) -> Result<u64> {
        let compiled = Self::compile_raw_json(&raw_json)?;
        Ok(self.apply_compiled(compiled))
    }

    pub fn load_from_path(path: &Path) -> Result<SharedConfig> {
        let raw = fs::read_to_string(path).map_err(|e| ArcError::io("read config file", e))?;
        let format = ConfigSourceFormat::from_path(path)?;
        let (cfg, canonical_json) = parse_config_text_with_format(&raw, format)?;
        compile_config(cfg, canonical_json)
    }

    pub fn check_from_path(path: &Path) -> Result<ConfigCheckReport> {
        let raw = fs::read_to_string(path).map_err(|e| ArcError::io("read config file", e))?;
        let format = ConfigSourceFormat::from_path(path)?;
        let (cfg, canonical_json) = parse_config_text_with_format(&raw, format)?;

        let mut errors = collect_non_fatal_check_errors(&cfg);
        if let Err(e) = compile_config(cfg, canonical_json) {
            let msg = e.to_string();
            let normalized = msg
                .strip_prefix("config error: ")
                .unwrap_or(msg.as_str())
                .to_string();
            errors.push(normalized);
        }
        dedup_check_errors(&mut errors);

        Ok(ConfigCheckReport { errors })
    }

    pub fn wait_for_generation_change(&self, since: u64, timeout: Duration) -> bool {
        if self.current_generation() != since {
            return true;
        }
        self.signal.wait_timeout(timeout);
        self.current_generation() != since
    }

    pub fn spawn_hot_reload(&self, path: PathBuf, interval_ms: u64) {
        let swap = self.swap.clone();
        let signal = self.signal.clone();

        thread::spawn(move || {
            let format = match ConfigSourceFormat::from_path(&path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("config reload disabled: {e}");
                    return;
                }
            };
            // Seed with current on-disk fingerprint to avoid a first-iteration rollback:
            // if config was just updated in-memory via control plane/gossip and file is unchanged,
            // the watcher must not immediately re-apply the stale file.
            let mut last_fingerprint: Option<u64> = (|| {
                let raw = fs::read_to_string(&path).ok()?;
                let (cfg_file, _) = parse_config_text_with_format(&raw, format).ok()?;
                reload_fingerprint(&path, &cfg_file).ok()
            })();

            loop {
                thread::sleep(Duration::from_millis(interval_ms));

                let raw = match fs::read_to_string(&path) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let (cfg_file, canonical_json) = match parse_config_text_with_format(&raw, format) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("config reload parse failed: {e}");
                        continue;
                    }
                };

                let fp = match reload_fingerprint(&path, &cfg_file) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if last_fingerprint == Some(fp) {
                    continue;
                }

                let started = std::time::Instant::now();
                match compile_config(cfg_file, canonical_json) {
                    Ok(new_cfg) => {
                        let gen = new_cfg.generation;
                        let cur = swap.load().generation;
                        if cur != gen {
                            swap.store(Arc::new(new_cfg));
                            signal.notify_all();
                        }
                        last_fingerprint = Some(fp);

                        let ms = started.elapsed().as_millis() as u64;
                        CONFIG_RELOAD_DURATION_MS_SUM.fetch_add(ms, Ordering::Relaxed);
                        CONFIG_RELOAD_DURATION_MS_COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("config reload failed: {e}");
                    }
                }
            }
        });
    }
}

fn compile_config(cfg: ConfigFile, raw_json: Arc<str>) -> Result<SharedConfig> {
    let mut gen_hasher = Fnv1a64::new();
    gen_hasher.write(raw_json.as_bytes());

    let listen: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|_| ArcError::config(format!("invalid listen addr: {}", cfg.listen)))?;
    let admin_listen: SocketAddr = cfg.admin_listen.parse().map_err(|_| {
        ArcError::config(format!("invalid admin_listen addr: {}", cfg.admin_listen))
    })?;
    if cfg.control_plane.enabled {
        let cp_bind: SocketAddr = cfg.control_plane.bind.parse().map_err(|_| {
            ArcError::config(format!(
                "invalid control_plane.bind addr: {}",
                cfg.control_plane.bind
            ))
        })?;
        if cp_bind == listen {
            return Err(ArcError::config(
                "control_plane.bind must not be the same as listen".to_string(),
            ));
        }
        if cp_bind == admin_listen {
            return Err(ArcError::config(
                "control_plane.bind must not be the same as admin_listen".to_string(),
            ));
        }
    }

    if cfg.io_uring.entries == 0 {
        return Err(ArcError::config("io_uring.entries must be > 0".to_string()));
    }
    if cfg.io_uring.accept_prepost == 0 {
        return Err(ArcError::config(
            "io_uring.accept_prepost must be > 0".to_string(),
        ));
    }
    if cfg.io_uring.tick_ms == 0 {
        return Err(ArcError::config("io_uring.tick_ms must be > 0".to_string()));
    }
    if cfg.listen_backlog <= 0 {
        return Err(ArcError::config("listen_backlog must be > 0".to_string()));
    }
    if cfg.buffers.buf_size == 0 {
        return Err(ArcError::config("buffers.buf_size must be > 0".to_string()));
    }

    if cfg.global_rate_limit.backend == GlobalRateLimitBackend::Redis {
        let Some(redis) = cfg.global_rate_limit.redis.as_ref() else {
            return Err(ArcError::config(
                "global_rate_limit.backend=redis requires global_rate_limit.redis".to_string(),
            ));
        };
        if redis.url.trim().is_empty() {
            return Err(ArcError::config(
                "global_rate_limit.redis.url must not be empty".to_string(),
            ));
        }
        if redis.budget_ms == 0 {
            return Err(ArcError::config(
                "global_rate_limit.redis.budget_ms must be > 0".to_string(),
            ));
        }
        if redis.circuit_open_ms == 0 {
            return Err(ArcError::config(
                "global_rate_limit.redis.circuit_open_ms must be > 0".to_string(),
            ));
        }
        if redis.prefetch == 0 {
            return Err(ArcError::config(
                "global_rate_limit.redis.prefetch must be > 0".to_string(),
            ));
        }
        if redis.low_watermark == 0 {
            return Err(ArcError::config(
                "global_rate_limit.redis.low_watermark must be > 0".to_string(),
            ));
        }
        if redis.low_watermark >= redis.prefetch {
            return Err(ArcError::config(
                "global_rate_limit.redis.low_watermark must be < prefetch".to_string(),
            ));
        }
        if redis.refill_backoff_ms == 0 {
            return Err(ArcError::config(
                "global_rate_limit.redis.refill_backoff_ms must be > 0".to_string(),
            ));
        }
    }

    if cfg.cluster_circuit.failure_threshold == 0 {
        return Err(ArcError::config(
            "cluster_circuit.failure_threshold must be > 0".to_string(),
        ));
    }
    if cfg.cluster_circuit.circuit_open_ms == 0 {
        return Err(ArcError::config(
            "cluster_circuit.circuit_open_ms must be > 0".to_string(),
        ));
    }
    if cfg.cluster_circuit.quorum == 0 {
        return Err(ArcError::config(
            "cluster_circuit.quorum must be > 0".to_string(),
        ));
    }
    if cfg.cluster_circuit.half_open_probe_interval_ms == 0 {
        return Err(ArcError::config(
            "cluster_circuit.half_open_probe_interval_ms must be > 0".to_string(),
        ));
    }
    if cfg.cluster_circuit.active_probe_interval_ms == 0 {
        return Err(ArcError::config(
            "cluster_circuit.active_probe_interval_ms must be > 0".to_string(),
        ));
    }
    if cfg.cluster_circuit.active_probe_timeout_ms == 0 {
        return Err(ArcError::config(
            "cluster_circuit.active_probe_timeout_ms must be > 0".to_string(),
        ));
    }
    if cfg.cluster_circuit.active_probe_timeout_ms > cfg.cluster_circuit.active_probe_interval_ms {
        return Err(ArcError::config(
            "cluster_circuit.active_probe_timeout_ms must be <= active_probe_interval_ms"
                .to_string(),
        ));
    }

    let mut upstream_name_to_id: HashMap<&str, usize> = HashMap::with_capacity(cfg.upstreams.len());
    for (i, u) in cfg.upstreams.iter().enumerate() {
        if upstream_name_to_id.insert(u.name.as_str(), i).is_some() {
            return Err(ArcError::config(format!(
                "duplicated upstream name: {}",
                u.name
            )));
        }
    }

    let mut plugin_name_to_id: HashMap<&str, usize> = HashMap::with_capacity(cfg.plugins.len());
    for (i, p) in cfg.plugins.iter().enumerate() {
        if plugin_name_to_id.insert(p.name.as_str(), i).is_some() {
            return Err(ArcError::config(format!(
                "duplicated plugin name: {}",
                p.name
            )));
        }
    }

    let mut route_path_to_ids: HashMap<&str, Vec<u32>> = HashMap::with_capacity(cfg.routes.len());
    for (i, r) in cfg.routes.iter().enumerate() {
        route_path_to_ids
            .entry(r.path.as_str())
            .or_default()
            .push(i as u32);
    }
    if let Some(conflict) = collect_route_priority_specificity_conflicts(&cfg.routes).first() {
        return Err(ArcError::config(conflict.clone()));
    }

    // upstreams compile
    let mut upstreams: Vec<CompiledUpstream> = Vec::with_capacity(cfg.upstreams.len());
    for u in &cfg.upstreams {
        let addr_raw = u.addr.as_deref().map(str::trim).filter(|v| !v.is_empty());
        let host_raw = u.host.as_deref().map(str::trim).filter(|v| !v.is_empty());
        let port_raw = u.port;
        let (addr, host, port) = match (addr_raw, host_raw, port_raw) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(ArcError::config(format!(
                    "upstream '{}' must set either addr or host+port, not both",
                    u.name
                )));
            }
            (Some(addr_text), None, None) => {
                let mut it = addr_text.to_socket_addrs().map_err(|_| {
                    ArcError::config(format!("invalid upstream addr: {}", addr_text))
                })?;
                let addr = it.next().ok_or_else(|| {
                    ArcError::config(format!("upstream '{}' addr resolved no address", u.name))
                })?;
                (addr, None, addr.port())
            }
            (None, Some(host_text), Some(port)) => {
                let addr = resolve_host_port_once(host_text, port).map_err(|e| {
                    ArcError::config(format!(
                        "upstream '{}' resolve host '{}' failed: {}",
                        u.name, host_text, e
                    ))
                })?;
                (addr, Some(Arc::from(host_text)), port)
            }
            _ => {
                return Err(ArcError::config(format!(
                    "upstream '{}' requires addr or host+port",
                    u.name
                )));
            }
        };
        if let Some(max) = u.max_connections {
            if max == 0 {
                return Err(ArcError::config(format!(
                    "upstream '{}' max_connections must be > 0",
                    u.name
                )));
            }
        }
        if cfg.require_upstream_mtls && u.tls.is_none() {
            return Err(ArcError::config(format!(
                "require_upstream_mtls=true but upstream '{}' has no tls config",
                u.name
            )));
        }
        let tls = if let Some(t) = u.tls.as_ref() {
            let verify_server = t.verify_server.unwrap_or(cfg.tls.upstream.verify_server);
            if verify_server && t.ca_pem.is_none() {
                return Err(ArcError::config(format!(
                    "upstream '{}' tls.ca_pem is required when tls.verify_server=true",
                    u.name
                )));
            }
            let cert_bytes = fs::read(&t.client_cert_pem)
                .map_err(|e| ArcError::io("read upstream tls client_cert_pem", e))?;
            let key_bytes = fs::read(&t.client_key_pem)
                .map_err(|e| ArcError::io("read upstream tls client_key_pem", e))?;
            if cert_bytes.is_empty() {
                return Err(ArcError::config(format!(
                    "empty upstream tls client_cert_pem: {}",
                    t.client_cert_pem
                )));
            }
            if key_bytes.is_empty() {
                return Err(ArcError::config(format!(
                    "empty upstream tls client_key_pem: {}",
                    t.client_key_pem
                )));
            }
            gen_hasher.write(cert_bytes.as_slice());
            gen_hasher.write(key_bytes.as_slice());

            let ca_bytes = if let Some(ca) = t.ca_pem.as_ref() {
                let v = fs::read(ca).map_err(|e| ArcError::io("read upstream tls ca_pem", e))?;
                if v.is_empty() {
                    return Err(ArcError::config(format!("empty upstream tls ca_pem: {ca}")));
                }
                gen_hasher.write(v.as_slice());
                Some(v.into())
            } else {
                None
            };
            Some(Arc::new(CompiledUpstreamTls {
                server_name: t.server_name.as_deref().map(Arc::from),
                ca_pem: ca_bytes,
                client_cert_pem: cert_bytes.into(),
                client_key_pem: key_bytes.into(),
                verify_server,
                enable_resumption: t.enable_resumption,
                min_version: t.min_version.unwrap_or(cfg.tls.upstream.min_version),
            }))
        } else {
            None
        };
        upstreams.push(CompiledUpstream {
            name: Arc::from(u.name.as_str()),
            addr,
            host,
            port,
            keepalive: u.keepalive.max(1),
            idle_ttl_ms: u.idle_ttl_ms.max(1),
            dns_refresh_ms: u.dns_refresh_ms,
            max_connections: u.max_connections,
            tls,
        });
    }

    for p in &cfg.plugins {
        hash_file_contents(Path::new(&p.path), &mut gen_hasher)
            .map_err(|e| ArcError::io("read plugin wasm for generation hash", e))?;
    }

    let catalog = if cfg.plugins.is_empty() {
        None
    } else {
        let defs: Vec<(String, String, usize, u64)> = cfg
            .plugins
            .iter()
            .map(|p| (p.name.clone(), p.path.clone(), p.pool, p.timeout_ms))
            .collect();
        Some(PluginCatalog::load_from_defs(defs)?)
    };

    let plugin_names: Vec<Arc<str>> = cfg
        .plugins
        .iter()
        .map(|p| Arc::from(p.name.as_str()))
        .collect();

    let default_error_pages = compile_error_pages(
        &cfg.defaults.error_pages,
        &upstream_name_to_id,
        &mut gen_hasher,
        "defaults.error_pages",
    )?;
    if cfg.limits.max_request_body_bytes == 0 {
        return Err(ArcError::config(
            "limits.max_request_body_bytes must be > 0".to_string(),
        ));
    }
    if cfg.limits.upstream_leak_warn_growth > 0 && cfg.limits.upstream_leak_warn_window_ms == 0 {
        return Err(ArcError::config(
            "limits.upstream_leak_warn_window_ms must be > 0 when upstream_leak_warn_growth > 0"
                .to_string(),
        ));
    }
    if cfg.limits.upstream_leak_warn_growth > 0 && cfg.limits.upstream_leak_warn_cooldown_ms == 0
    {
        return Err(ArcError::config(
            "limits.upstream_leak_warn_cooldown_ms must be > 0 when upstream_leak_warn_growth > 0"
                .to_string(),
        ));
    }
    if cfg.http2.max_concurrent_streams == 0 {
        return Err(ArcError::config(
            "http2.max_concurrent_streams must be > 0".to_string(),
        ));
    }
    if cfg.http2.max_active_streams == 0 {
        return Err(ArcError::config(
            "http2.max_active_streams must be > 0".to_string(),
        ));
    }
    let global_max_request_body_bytes = cfg.limits.max_request_body_bytes;
    let compiled_request_id = CompiledRequestIdConfig {
        header: compile_request_id_header(cfg.request_id.header.as_str(), "request_id.header")?,
        format: cfg.request_id.format,
        on_conflict: cfg.request_id.on_conflict,
        preserve_original: cfg.request_id.preserve_original,
        trusted_proxies: compile_trusted_proxies(
            &cfg.request_id.trusted_proxies,
            "request_id.trusted_proxies",
        )?,
    };
    let compression_global = cfg.compression.resolve()?;

    let mut router = Router::new();
    let mut routes: Vec<CompiledRoute> = Vec::with_capacity(cfg.routes.len());

    for (rid, r) in cfg.routes.iter().enumerate() {
        let route_id = rid as u32;
        let matchers: Arc<[RouteMatcher]> = compile_matchers(&r.matchers)?.into();
        let action = compile_action(&r.action)?;
        let is_forward = matches!(action, RouteAction::Forward);
        let upstreams = compile_upstreams(
            is_forward,
            r.upstream.as_deref(),
            r.split.as_ref(),
            r.load_balance,
            &upstream_name_to_id,
        )?;
        let forward = if is_forward {
            compile_forward_policy(r.rewrite.as_ref(), &r.headers, &r.retry)?
        } else {
            ForwardPolicy::default()
        };
        let response_header_muts = compile_response_header_mutations(&r.response_headers, rid)?;

        let mut pids: Vec<usize> = Vec::with_capacity(r.plugins.len());
        for pname in &r.plugins {
            let pid = plugin_name_to_id
                .get(pname.as_str())
                .copied()
                .ok_or_else(|| ArcError::config(format!("unknown plugin in route: {pname}")))?;
            pids.push(pid);
        }

        let limiter = if let Some(rl) = &r.rate_limit {
            Some(Arc::new(Limiter::new(rl.rps, rl.burst)?))
        } else {
            None
        };
        let rate_limit_policy = r.rate_limit.as_ref().map(|rl| RateLimitPolicy {
            rps: rl.rps,
            burst: rl.burst,
        });
        let error_pages = compile_error_pages(
            &r.error_pages,
            &upstream_name_to_id,
            &mut gen_hasher,
            &format!("routes[{rid}].error_pages"),
        )?;
        let timeout_tier = compile_timeout_tier(
            r.timeout.as_ref(),
            cfg.defaults.timeout.as_ref(),
            r.retry.max_retries,
            rid,
        )?;
        let (mirror_policy, mirror_targets) = compile_mirror_route(
            r.mirror.as_ref(),
            cfg.defaults.mirror_policy.as_ref(),
            &upstream_name_to_id,
            rid,
        )?;
        let compression =
            CompressionConfig::resolve_route(&compression_global, r.compression.as_ref())?;
        let max_request_body_bytes = r
            .limits
            .as_ref()
            .and_then(|v| v.max_request_body_bytes)
            .unwrap_or(global_max_request_body_bytes);
        if max_request_body_bytes == 0 {
            return Err(ArcError::config(format!(
                "routes[{rid}].limits.max_request_body_bytes must be > 0"
            )));
        }
        let real_ip_header = compile_real_ip_header(r.real_ip_header.as_deref(), rid)?;
        let trusted_proxies = compile_trusted_proxies(
            &r.trusted_proxies,
            &format!("routes[{rid}].trusted_proxies"),
        )?;

        let path_group = route_path_to_ids.get(r.path.as_str()).ok_or_else(|| {
            ArcError::config(format!("internal route path index missing: {}", r.path))
        })?;
        if path_group.first().copied() == Some(route_id) {
            router.insert(&r.path, route_id)?;
        }

        routes.push(CompiledRoute {
            path: Bytes::copy_from_slice(r.path.as_bytes()),
            priority: r.priority,
            matchers,
            action,
            upstreams,
            forward,
            response_header_muts,
            plugin_ids: pids.into(),
            limiter,
            rate_limit_policy,
            error_pages,
            timeout_tier,
            mirror_policy,
            mirror_targets,
            compression,
            max_request_body_bytes,
            forwarded_for: r.forwarded_for,
            real_ip_header,
            trusted_proxies,
        });
    }

    // ---------------- downstream tls compile (updated for ACME) ----------------
    let downstream_tls = if let Some(tls) = cfg.downstream_tls.as_ref() {
        let acme_cfg = tls.acme.as_ref().filter(|a| a.enabled);

        if tls.certificates.is_empty() && acme_cfg.map_or(true, |a| a.certificates.is_empty()) {
            return Err(ArcError::config(
                "downstream_tls has neither static certificates nor acme.certificates".to_string(),
            ));
        }

        // compile acme config first
        let compiled_acme: Option<Arc<CompiledDownstreamAcme>> = if let Some(acme) = acme_cfg {
            if acme.certificates.is_empty() {
                return Err(ArcError::config(
                    "downstream_tls.acme.enabled=true but acme.certificates is empty".to_string(),
                ));
            }

            // validate challenge deps
            let want_dns = acme
                .challenge_priority
                .iter()
                .any(|c| *c == AcmeChallengeType::Dns01);
            if want_dns && acme.dns_hook.is_none() {
                return Err(ArcError::config(
                    "acme.challenge_priority includes dns01 but acme.dns_hook is missing"
                        .to_string(),
                ));
            }

            let want_http = acme
                .challenge_priority
                .iter()
                .any(|c| *c == AcmeChallengeType::Http01);
            if want_http && acme.http01.is_none() {
                return Err(ArcError::config(
                    "acme.challenge_priority includes http01 but acme.http01 is missing"
                        .to_string(),
                ));
            }

            let directory_ca_pem = if let Some(p) = acme.directory_ca_pem.as_ref() {
                let b = fs::read(p).map_err(|e| ArcError::io("read acme directory_ca_pem", e))?;
                if b.is_empty() {
                    return Err(ArcError::config(format!(
                        "empty acme directory_ca_pem: {p}"
                    )));
                }
                gen_hasher.write(b.as_slice());
                Some(b.into())
            } else {
                None
            };

            let passphrase = match &acme.account_key.passphrase {
                AcmePassphraseSourceConfig::Env { name } => CompiledAcmePassphraseSource::Env {
                    name: Arc::from(name.as_str()),
                },
                AcmePassphraseSourceConfig::File { path } => CompiledAcmePassphraseSource::File {
                    path: PathBuf::from(path),
                },
            };

            let account_key = CompiledAcmeAccountKeyConfig {
                algorithm: acme.account_key.algorithm,
                encrypted_key_path: PathBuf::from(acme.account_key.encrypted_key_path.as_str()),
                passphrase,
            };

            let dns_hook = if let Some(h) = acme.dns_hook.as_ref() {
                let args: Vec<Arc<str>> = h.args.iter().map(|s| Arc::from(s.as_str())).collect();
                let env: Vec<(Arc<str>, Arc<str>)> = h
                    .env
                    .iter()
                    .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
                    .collect();
                Some(Arc::new(CompiledDnsHookConfig {
                    command: Arc::from(h.command.as_str()),
                    args: args.into(),
                    env: env.into(),
                    propagation_timeout_secs: h.propagation_timeout_secs.max(1),
                    poll_interval_secs: h.poll_interval_secs.max(1),
                }))
            } else {
                None
            };

            let http01 = if let Some(h) = acme.http01.as_ref() {
                let listen: SocketAddr = h.listen.parse().map_err(|_| {
                    ArcError::config(format!("invalid acme.http01.listen addr: {}", h.listen))
                })?;
                Some(CompiledAcmeHttp01Config { listen })
            } else {
                None
            };

            let members: Vec<Arc<str>> =
                acme.members.iter().map(|s| Arc::from(s.as_str())).collect();

            let mut managed: Vec<CompiledAcmeManagedCert> =
                Vec::with_capacity(acme.certificates.len());
            for c in &acme.certificates {
                if c.domain.trim().is_empty() {
                    return Err(ArcError::config(
                        "acme.certificates[].domain must not be empty".to_string(),
                    ));
                }
                managed.push(CompiledAcmeManagedCert {
                    domain: Arc::from(c.domain.as_str()),
                    cert_path: PathBuf::from(c.cert_pem.as_str()),
                    key_path: PathBuf::from(c.key_pem.as_str()),
                });
            }

            Some(Arc::new(CompiledDownstreamAcme {
                enabled: true,
                directory_url: Arc::from(acme.directory_url.as_str()),
                directory_ca_pem,
                email: acme.email.as_deref().map(Arc::from),
                account_key,
                challenge_priority: acme.challenge_priority.clone().into(),
                dns_hook,
                http01,
                poll_interval_secs: acme.poll_interval_secs.max(1),
                members: members.into(),
                certificates: managed.into(),
            }))
        } else {
            None
        };

        // compile certificates (static + acme-managed)
        let mut certs: Vec<CompiledDownstreamCertificate> = Vec::new();

        // static certs must exist
        for cert in &tls.certificates {
            let (wildcard, pat) = normalize_sni_pattern(&cert.sni)?;
            let cert_bytes = fs::read(&cert.cert_pem)
                .map_err(|e| ArcError::io("read downstream tls cert_pem", e))?;
            let key_bytes = fs::read(&cert.key_pem)
                .map_err(|e| ArcError::io("read downstream tls key_pem", e))?;
            if cert_bytes.is_empty() {
                return Err(ArcError::config(format!(
                    "empty downstream tls cert_pem: {}",
                    cert.cert_pem
                )));
            }
            if key_bytes.is_empty() {
                return Err(ArcError::config(format!(
                    "empty downstream tls key_pem: {}",
                    cert.key_pem
                )));
            }
            gen_hasher.write(cert_bytes.as_slice());
            gen_hasher.write(key_bytes.as_slice());

            certs.push(CompiledDownstreamCertificate {
                wildcard,
                sni: Arc::from(pat),
                cert_pem: cert_bytes.into(),
                key_pem: key_bytes.into(),
                acme_managed: false,
            });
        }

        // acme-managed certs: files may be missing on cold start
        if let Some(acme) = tls.acme.as_ref().filter(|a| a.enabled) {
            for c in &acme.certificates {
                let (wildcard, pat) = normalize_sni_pattern(&c.domain)?;
                let cert_path = Path::new(&c.cert_pem);
                let key_path = Path::new(&c.key_pem);

                let cert_bytes = match fs::read(cert_path) {
                    Ok(v) => v,
                    Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
                    Err(e) => return Err(ArcError::io("read acme managed cert_pem", e)),
                };
                let key_bytes = match fs::read(key_path) {
                    Ok(v) => v,
                    Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
                    Err(e) => return Err(ArcError::io("read acme managed key_pem", e)),
                };

                if cert_bytes.is_empty() != key_bytes.is_empty() {
                    return Err(ArcError::config(format!(
                        "acme managed cert/key must both exist or both be missing: domain={} cert_pem={} key_pem={}",
                        c.domain, c.cert_pem, c.key_pem
                    )));
                }
                if !cert_bytes.is_empty() {
                    gen_hasher.write(cert_bytes.as_slice());
                    gen_hasher.write(key_bytes.as_slice());
                }

                certs.push(CompiledDownstreamCertificate {
                    wildcard,
                    sni: Arc::from(pat),
                    cert_pem: cert_bytes.into(),
                    key_pem: key_bytes.into(),
                    acme_managed: true,
                });
            }
        }

        if certs.is_empty() {
            return Err(ArcError::config(
                "downstream tls has no certificates".to_string(),
            ));
        }

        let mut exact: HashMap<Arc<str>, u32> = HashMap::new();
        let mut wildcard_suffix: Vec<(Arc<str>, u32)> = Vec::new();
        for rule in &tls.sni_routes {
            let route_ids = route_path_to_ids.get(rule.path.as_str()).ok_or_else(|| {
                ArcError::config(format!(
                    "unknown route path in downstream_tls.sni_routes: {}",
                    rule.path
                ))
            })?;
            if route_ids.len() != 1 {
                return Err(ArcError::config(format!(
                    "ambiguous route path in downstream_tls.sni_routes: {} ({} routes share this path)",
                    rule.path,
                    route_ids.len()
                )));
            }
            let route_id = route_ids[0];

            let (is_wildcard, normalized) = normalize_sni_pattern(&rule.sni)?;
            if is_wildcard {
                wildcard_suffix.push((Arc::from(normalized), route_id));
            } else {
                let key: Arc<str> = Arc::from(normalized);
                if exact.insert(key.clone(), route_id).is_some() {
                    return Err(ArcError::config(format!(
                        "duplicated exact SNI rule in downstream_tls.sni_routes: {}",
                        key
                    )));
                }
            }
        }

        wildcard_suffix.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Some(Arc::new(CompiledDownstreamTls {
            enable_h2: tls.enable_h2,
            min_version: tls.min_version.unwrap_or(cfg.tls.downstream.min_version),
            certificates: certs.into(),
            sni_routes: CompiledSniRoutes {
                exact,
                wildcard_suffix,
            },
            acme: compiled_acme,
        }))
    } else {
        None
    };

    let empty_group: Arc<[u32]> = Arc::from([]);
    let mut route_candidate_groups: Vec<Arc<[u32]>> = vec![empty_group; routes.len()];
    for ids in route_path_to_ids.values() {
        let group: Arc<[u32]> = ids.clone().into();
        for &rid in ids {
            route_candidate_groups[rid as usize] = group.clone();
        }
    }

    let generation = gen_hasher.finish();

    Ok(SharedConfig {
        generation,
        raw_json,

        listen,
        admin_listen,
        listen_backlog: cfg.listen_backlog,

        workers: cfg.workers,
        linger_ms: cfg.linger_ms,
        io_uring: cfg.io_uring,
        buffers: cfg.buffers,
        timeouts_ms: cfg.timeouts_ms,

        router,
        routes: routes.into(),
        route_candidate_groups: route_candidate_groups.into(),
        upstreams: upstreams.into(),
        control_plane: cfg.control_plane,
        global_rate_limit: cfg.global_rate_limit,
        cluster_circuit: cfg.cluster_circuit,
        compression: compression_global,
        limits: cfg.limits,
        http2: cfg.http2,
        request_id: compiled_request_id,
        default_error_pages,

        plugins: Arc::new(CompiledPlugins {
            catalog,
            names: plugin_names.into(),
        }),
        downstream_tls,
    })
}

fn dedup_check_errors(errors: &mut Vec<String>) {
    let mut seen = HashSet::<String>::with_capacity(errors.len());
    errors.retain(|v| seen.insert(v.clone()));
}

fn collect_non_fatal_check_errors(cfg: &ConfigFile) -> Vec<String> {
    let mut errors = Vec::<String>::new();

    if cfg.workers == 0 {
        errors.push("workers must be > 0".to_string());
    }
    if cfg.io_uring.entries == 0 {
        errors.push("io_uring.entries must be > 0".to_string());
    }
    if cfg.io_uring.accept_prepost == 0 {
        errors.push("io_uring.accept_prepost must be > 0".to_string());
    }
    if cfg.io_uring.tick_ms == 0 {
        errors.push("io_uring.tick_ms must be > 0".to_string());
    }
    if cfg.listen_backlog <= 0 {
        errors.push("listen_backlog must be > 0".to_string());
    }
    if cfg.buffers.buf_size == 0 {
        errors.push("buffers.buf_size must be > 0".to_string());
    }
    if cfg.limits.max_request_body_bytes == 0 {
        errors.push("limits.max_request_body_bytes must be > 0".to_string());
    }
    if cfg.limits.upstream_leak_warn_growth > 0 && cfg.limits.upstream_leak_warn_window_ms == 0 {
        errors.push(
            "limits.upstream_leak_warn_window_ms must be > 0 when upstream_leak_warn_growth > 0"
                .to_string(),
        );
    }
    if cfg.limits.upstream_leak_warn_growth > 0 && cfg.limits.upstream_leak_warn_cooldown_ms == 0
    {
        errors.push(
            "limits.upstream_leak_warn_cooldown_ms must be > 0 when upstream_leak_warn_growth > 0"
                .to_string(),
        );
    }
    if cfg.http2.max_concurrent_streams == 0 {
        errors.push("http2.max_concurrent_streams must be > 0".to_string());
    }
    if cfg.http2.max_active_streams == 0 {
        errors.push("http2.max_active_streams must be > 0".to_string());
    }

    let mut upstream_name_to_id: HashMap<&str, usize> = HashMap::with_capacity(cfg.upstreams.len());
    for (i, u) in cfg.upstreams.iter().enumerate() {
        if upstream_name_to_id.insert(u.name.as_str(), i).is_some() {
            errors.push(format!("duplicated upstream name: {}", u.name));
        }
    }
    let mut plugin_name_to_id: HashMap<&str, usize> = HashMap::with_capacity(cfg.plugins.len());
    for (i, p) in cfg.plugins.iter().enumerate() {
        if plugin_name_to_id.insert(p.name.as_str(), i).is_some() {
            errors.push(format!("duplicated plugin name: {}", p.name));
        }
    }

    for u in &cfg.upstreams {
        let addr_raw = u.addr.as_deref().map(str::trim).filter(|v| !v.is_empty());
        let host_raw = u.host.as_deref().map(str::trim).filter(|v| !v.is_empty());
        let port_raw = u.port;
        match (addr_raw, host_raw, port_raw) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                errors.push(format!(
                    "upstream '{}' must set either addr or host+port, not both",
                    u.name
                ));
            }
            (Some(addr_text), None, None) => {
                if addr_text.to_socket_addrs().is_err() {
                    errors.push(format!("invalid upstream addr: {}", addr_text));
                }
            }
            (None, Some(host_text), Some(port)) => {
                if let Err(e) = resolve_host_port_once(host_text, port) {
                    errors.push(format!(
                        "upstream '{}' resolve host '{}' failed: {}",
                        u.name, host_text, e
                    ));
                }
            }
            _ => {
                errors.push(format!("upstream '{}' requires addr or host+port", u.name));
            }
        }

        if let Some(max) = u.max_connections {
            if max == 0 {
                errors.push(format!("upstream '{}' max_connections must be > 0", u.name));
            }
        }
        if cfg.require_upstream_mtls && u.tls.is_none() {
            errors.push(format!(
                "require_upstream_mtls=true but upstream '{}' has no tls config",
                u.name
            ));
        }
        if let Some(t) = u.tls.as_ref() {
            let verify_server = t.verify_server.unwrap_or(cfg.tls.upstream.verify_server);
            if verify_server && t.ca_pem.is_none() {
                errors.push(format!(
                    "upstream '{}' tls.ca_pem is required when tls.verify_server=true",
                    u.name
                ));
            }
            push_file_readable_non_empty(
                &mut errors,
                &t.client_cert_pem,
                "upstream tls client_cert_pem",
            );
            push_file_readable_non_empty(
                &mut errors,
                &t.client_key_pem,
                "upstream tls client_key_pem",
            );
            if let Some(ca) = t.ca_pem.as_ref() {
                push_file_readable_non_empty(&mut errors, ca, "upstream tls ca_pem");
            }
        }
    }

    if let Some(tls) = cfg.downstream_tls.as_ref() {
        if tls.certificates.is_empty() && tls.acme.as_ref().map_or(true, |a| a.certificates.is_empty()) {
            errors.push("downstream_tls has neither static certificates nor acme.certificates".to_string());
        }
        for cert in &tls.certificates {
            push_file_readable_non_empty(&mut errors, &cert.cert_pem, "downstream tls cert_pem");
            push_file_readable_non_empty(&mut errors, &cert.key_pem, "downstream tls key_pem");
        }
    }

    errors.extend(collect_route_priority_specificity_conflicts(&cfg.routes));

    errors
}

fn push_file_readable_non_empty(errors: &mut Vec<String>, path: &str, label: &str) {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.len() == 0 {
                errors.push(format!("empty {label}: {path}"));
            }
        }
        Err(e) => {
            errors.push(format!("{label} not found/readable: {path} ({e})"));
        }
    }
}

fn collect_route_priority_specificity_conflicts(routes: &[RouteConfig]) -> Vec<String> {
    let mut groups: HashMap<(String, i32, u32), Vec<usize>> = HashMap::new();
    for (rid, route) in routes.iter().enumerate() {
        let spec = route_specificity(route);
        groups
            .entry((route.path.clone(), route.priority, spec))
            .or_default()
            .push(rid);
    }

    let mut conflicts = Vec::<String>::new();
    let mut keys: Vec<(String, i32, u32)> = groups.keys().cloned().collect();
    keys.sort_by(|a, b| a.cmp(b));
    for key in keys {
        if let Some(ids) = groups.get(&key) {
            if ids.len() <= 1 {
                continue;
            }
            let ids_joined = ids
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            conflicts.push(format!(
                "ambiguous routes with same path/priority/specificity: path='{}', priority={}, specificity={}, route_ids=[{}]",
                key.0, key.1, key.2, ids_joined
            ));
        }
    }
    conflicts
}

#[inline]
fn route_specificity(route: &RouteConfig) -> u32 {
    (route.path.len() as u32) * 1024 + (route.matchers.len() as u32)
}

#[derive(Clone, Copy)]
struct Fnv1a64(u64);

impl Fnv1a64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;

    #[inline]
    fn new() -> Self {
        Self(Self::OFFSET)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(Self::PRIME);
        }
        self.0 = h;
    }

    #[inline]
    fn finish(self) -> u64 {
        self.0
    }
}

fn reload_fingerprint(path: &Path, cfg: &ConfigFile) -> std::io::Result<u64> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    hash_file_state(path, &mut hasher)?;
    for up in &cfg.upstreams {
        if let Some(tls) = up.tls.as_ref() {
            hash_file_state(Path::new(&tls.client_cert_pem), &mut hasher)?;
            hash_file_state(Path::new(&tls.client_key_pem), &mut hasher)?;
            if let Some(ca) = tls.ca_pem.as_ref() {
                hash_file_state(Path::new(ca), &mut hasher)?;
            }
        }
    }
    if let Some(tls) = cfg.downstream_tls.as_ref() {
        for cert in &tls.certificates {
            hash_file_state(Path::new(&cert.cert_pem), &mut hasher)?;
            hash_file_state(Path::new(&cert.key_pem), &mut hasher)?;
        }
        // ACME-managed certs can be missing initially => optional
        if let Some(acme) = tls.acme.as_ref() {
            for c in &acme.certificates {
                hash_file_state_optional(Path::new(&c.cert_pem), &mut hasher)?;
                hash_file_state_optional(Path::new(&c.key_pem), &mut hasher)?;
            }
            if let Some(p) = acme.directory_ca_pem.as_ref() {
                hash_file_state(Path::new(p), &mut hasher)?;
            }
        }
    }
    for p in &cfg.plugins {
        hash_file_state(Path::new(&p.path), &mut hasher)?;
    }
    hash_error_page_file_states(&cfg.defaults.error_pages, &mut hasher)?;
    for route in &cfg.routes {
        hash_error_page_file_states(&route.error_pages, &mut hasher)?;
    }

    Ok(hasher.finish())
}

fn hash_error_page_file_states(
    cfg: &HashMap<String, ErrorPageConfig>,
    hasher: &mut impl Hasher,
) -> std::io::Result<()> {
    if cfg.is_empty() {
        return Ok(());
    }

    let mut entries: Vec<(&str, &ErrorPageConfig)> =
        cfg.iter().map(|(k, v)| (k.as_str(), v)).collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (_key, ep) in entries {
        if let Some(path) = ep.file.as_deref() {
            hash_file_state(Path::new(path), hasher)?;
        }
    }
    Ok(())
}

fn hash_file_state(path: &Path, hasher: &mut impl Hasher) -> std::io::Result<()> {
    path.as_os_str().to_string_lossy().hash(hasher);
    let meta = fs::metadata(path)?;
    meta.len().hash(hasher);
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let dur = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    dur.as_secs().hash(hasher);
    dur.subsec_nanos().hash(hasher);
    Ok(())
}

fn hash_file_state_optional(path: &Path, hasher: &mut impl Hasher) -> std::io::Result<()> {
    path.as_os_str().to_string_lossy().hash(hasher);
    match fs::metadata(path) {
        Ok(meta) => {
            meta.len().hash(hasher);
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let dur = modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0));
            dur.as_secs().hash(hasher);
            dur.subsec_nanos().hash(hasher);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn hash_file_contents(path: &Path, hasher: &mut Fnv1a64) -> std::io::Result<()> {
    let mut f = fs::File::open(path)?;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.write(&buf[..n]);
    }
    Ok(())
}

fn parse_error_page_pattern(key: &str, scope: &str) -> Result<CompiledErrorPagePattern> {
    let k = key.trim();
    if k.len() == 3 && k.ends_with("xx") {
        let cls = k.as_bytes()[0];
        if !(b'1'..=b'5').contains(&cls) {
            return Err(ArcError::config(format!(
                "{scope}: invalid error_pages key '{k}' (class must be 1xx..5xx)"
            )));
        }
        return Ok(CompiledErrorPagePattern::Class((cls - b'0') as u16));
    }

    if let Some((start, end)) = k.split_once('-') {
        let s = start.trim().parse::<u16>().map_err(|_| {
            ArcError::config(format!(
                "{scope}: invalid error_pages range start '{start}'"
            ))
        })?;
        let e = end.trim().parse::<u16>().map_err(|_| {
            ArcError::config(format!("{scope}: invalid error_pages range end '{end}'"))
        })?;
        if s < 100 || e > 599 || s > e {
            return Err(ArcError::config(format!(
                "{scope}: invalid error_pages range '{k}' (must be 100-599 and start<=end)"
            )));
        }
        return Ok(CompiledErrorPagePattern::Range { start: s, end: e });
    }

    let code = k
        .parse::<u16>()
        .map_err(|_| ArcError::config(format!("{scope}: invalid error_pages key '{k}'")))?;
    if !(100..=599).contains(&code) {
        return Err(ArcError::config(format!(
            "{scope}: invalid error_pages status '{k}' (must be 100..=599)"
        )));
    }
    Ok(CompiledErrorPagePattern::Exact(code))
}

fn compile_error_pages(
    cfg: &HashMap<String, ErrorPageConfig>,
    upstream_name_to_id: &HashMap<&str, usize>,
    gen_hasher: &mut Fnv1a64,
    scope: &str,
) -> Result<Arc<[CompiledErrorPageRule]>> {
    if cfg.is_empty() {
        return Ok(Arc::from([]));
    }

    let mut entries: Vec<(&str, &ErrorPageConfig)> =
        cfg.iter().map(|(k, v)| (k.as_str(), v)).collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = Vec::with_capacity(entries.len());
    for (key, ep) in entries {
        let pattern = parse_error_page_pattern(key, scope)?;

        let has_body = ep.body.is_some();
        let has_file = ep.file.is_some();
        let has_redirect = ep.redirect.is_some();
        let has_upstream = ep.upstream.is_some();
        let actions = has_body as u8 + has_file as u8 + has_redirect as u8 + has_upstream as u8;
        if actions != 1 {
            return Err(ArcError::config(format!(
                "{scope}: error_pages['{key}'] must set exactly one action: body | file | redirect | upstream"
            )));
        }

        if ep.code.is_some() && !has_redirect {
            return Err(ArcError::config(format!(
                "{scope}: error_pages['{key}'].code is only valid with redirect"
            )));
        }
        if ep.content_type.is_some() && !(has_body || has_file) {
            return Err(ArcError::config(format!(
                "{scope}: error_pages['{key}'].content_type is only valid with body/file"
            )));
        }

        let action = if let Some(body) = ep.body.as_ref() {
            let ct = ep
                .content_type
                .as_deref()
                .unwrap_or("text/plain; charset=utf-8")
                .trim();
            if ct.is_empty() {
                return Err(ArcError::config(format!(
                    "{scope}: error_pages['{key}'].content_type must not be empty"
                )));
            }
            CompiledErrorPageAction::Inline {
                template: Arc::from(body.as_bytes()),
                content_type: Arc::from(ct),
            }
        } else if let Some(path) = ep.file.as_ref() {
            let bytes = fs::read(path).map_err(|e| ArcError::io("read error_page file", e))?;
            gen_hasher.write(bytes.as_slice());
            let ct = ep
                .content_type
                .as_deref()
                .unwrap_or("text/html; charset=utf-8")
                .trim();
            if ct.is_empty() {
                return Err(ArcError::config(format!(
                    "{scope}: error_pages['{key}'].content_type must not be empty"
                )));
            }
            CompiledErrorPageAction::Inline {
                template: bytes.into(),
                content_type: Arc::from(ct),
            }
        } else if let Some(loc) = ep.redirect.as_ref() {
            let code = ep.code.unwrap_or(302);
            if !(300..=399).contains(&code) {
                return Err(ArcError::config(format!(
                    "{scope}: error_pages['{key}'].code must be 300..=399 for redirect"
                )));
            }
            if loc.trim().is_empty() {
                return Err(ArcError::config(format!(
                    "{scope}: error_pages['{key}'].redirect must not be empty"
                )));
            }
            CompiledErrorPageAction::Redirect {
                location: Arc::from(loc.trim()),
                code,
            }
        } else {
            let Some(up_name) = ep.upstream.as_ref() else {
                return Err(ArcError::config(format!(
                    "{scope}: error_pages['{key}'] upstream action missing upstream name"
                )));
            };
            let up_id = upstream_name_to_id
                .get(up_name.as_str())
                .copied()
                .ok_or_else(|| {
                    ArcError::config(format!(
                        "{scope}: error_pages['{key}'] unknown upstream '{up_name}'"
                    ))
                })?;
            CompiledErrorPageAction::Upstream { upstream_id: up_id }
        };

        out.push(CompiledErrorPageRule {
            pattern,
            when: ep.when,
            action,
        });
    }

    out.sort_by_key(|r| r.pattern.priority_key());
    Ok(out.into())
}

fn duration_to_ms_nonzero(d: Duration) -> u64 {
    let ms = d.as_millis();
    if ms == 0 {
        1
    } else if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

fn compile_timeout_tier(
    route_timeout: Option<&TimeoutTierConfig>,
    default_timeout: Option<&TimeoutTierConfig>,
    max_retries: u32,
    route_index: usize,
) -> Result<Option<CompiledTimeoutTier>> {
    if route_timeout.is_none() && default_timeout.is_none() {
        return Ok(None);
    }

    let eff: EffectiveTimeoutTier = TimeoutTierConfig::resolve(route_timeout, default_timeout);
    eff.validate(
        max_retries.saturating_add(1),
        format!("routes[{route_index}].timeout"),
    )
    .map_err(|e| ArcError::config(e.to_string()))?;

    let deadline_propagation = if eff.deadline_propagation.enabled {
        let header = eff.deadline_propagation.header.trim();
        if header.is_empty() {
            return Err(ArcError::config(format!(
                "routes[{route_index}].timeout.deadline_propagation.header must not be empty"
            )));
        }
        Some(CompiledDeadlinePropagation {
            header: Arc::from(header),
        })
    } else {
        None
    };

    Ok(Some(CompiledTimeoutTier {
        connect_ms: duration_to_ms_nonzero(eff.connect),
        response_header_ms: duration_to_ms_nonzero(eff.response_header),
        per_try_ms: duration_to_ms_nonzero(eff.per_try),
        total_ms: duration_to_ms_nonzero(eff.total),
        deadline_propagation,
    }))
}

fn compile_mirror_route(
    mirror: Option<&MirrorConfig>,
    default_policy: Option<&MirrorPolicyConfig>,
    upstream_name_to_id: &HashMap<&str, usize>,
    route_index: usize,
) -> Result<(Option<CompiledMirrorPolicy>, Arc<[CompiledMirrorTarget]>)> {
    let Some(mirror_cfg) = mirror else {
        return Ok((None, Arc::from([])));
    };

    let policy = default_policy.cloned().unwrap_or_default();
    policy
        .validate(format!("routes[{route_index}]"))
        .map_err(|e| ArcError::config(e.to_string()))?;
    mirror_cfg
        .validate(Some(&policy), format!("routes[{route_index}]"))
        .map_err(|e| ArcError::config(e.to_string()))?;

    let expanded: Vec<MirrorTargetConfig> = match mirror_cfg {
        MirrorConfig::Single(upstream) => vec![MirrorTargetConfig {
            upstream: upstream.clone(),
            sample: 1.0,
            timeout: policy_mirror::BUILTIN_MIRROR_TIMEOUT,
            transform: Default::default(),
            compare: Default::default(),
        }],
        MirrorConfig::Multi(list) => list.clone(),
    };

    let mut out: Vec<CompiledMirrorTarget> = Vec::with_capacity(expanded.len());
    for (i, t) in expanded.iter().enumerate() {
        t.validate(format!("routes[{route_index}].mirror[{i}]"))
            .map_err(|e| ArcError::config(e.to_string()))?;

        let upstream_id = upstream_name_to_id
            .get(t.upstream.as_str())
            .copied()
            .ok_or_else(|| {
                ArcError::config(format!(
                    "routes[{route_index}].mirror[{i}]: unknown upstream '{}'",
                    t.upstream
                ))
            })?;

        let transform_path = t
            .transform
            .path
            .as_ref()
            .map(|p| Arc::from(p.trim()))
            .filter(|p: &Arc<str>| !p.is_empty());

        let mut set_headers: Vec<(Arc<str>, Arc<str>)> =
            Vec::with_capacity(t.transform.headers.set.len());
        for (k, v) in &t.transform.headers.set {
            let name = k.trim();
            if name.is_empty() {
                return Err(ArcError::config(format!(
                    "routes[{route_index}].mirror[{i}].transform.headers.set has empty header name"
                )));
            }
            set_headers.push((Arc::from(name), Arc::from(v.as_str())));
        }

        let mut remove_headers: Vec<Arc<str>> =
            Vec::with_capacity(t.transform.headers.remove.len());
        for h in &t.transform.headers.remove {
            let name = h.trim();
            if name.is_empty() {
                return Err(ArcError::config(format!(
                    "routes[{route_index}].mirror[{i}].transform.headers.remove has empty header name"
                )));
            }
            remove_headers.push(Arc::from(name));
        }

        let compare_on_diff = match t.compare.on_diff {
            policy_mirror::MirrorOnDiff::Log => CompiledMirrorOnDiff::Log,
        };

        let compare_ignore_headers: Vec<Arc<str>> = t
            .compare
            .ignore_headers
            .iter()
            .map(|v| Arc::from(v.as_str()))
            .collect();
        let compare_ignore_body_fields: Vec<Arc<str>> = t
            .compare
            .ignore_body_fields
            .iter()
            .map(|v| Arc::from(v.as_str()))
            .collect();

        out.push(CompiledMirrorTarget {
            upstream_id,
            sample: t.sample,
            timeout_ms: duration_to_ms_nonzero(t.timeout),
            transform_path,
            transform_set_headers: set_headers.into(),
            transform_remove_headers: remove_headers.into(),
            compare_enabled: t.compare.enabled,
            compare_ignore_headers: compare_ignore_headers.into(),
            compare_ignore_body_fields: compare_ignore_body_fields.into(),
            compare_on_diff,
        });
    }

    let compiled_policy = Some(CompiledMirrorPolicy {
        max_queue_bytes: policy.max_queue_bytes,
    });

    Ok((compiled_policy, out.into()))
}

fn normalize_sni_host(sni: &str) -> Option<String> {
    let host = sni.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if host
        .as_bytes()
        .iter()
        .any(|b| b.is_ascii_whitespace() || *b == b'/')
    {
        return None;
    }
    Some(host)
}

fn normalize_sni_pattern(sni: &str) -> Result<(bool, String)> {
    let s = sni.trim();
    if let Some(rest) = s.strip_prefix("*.") {
        let suffix = normalize_sni_host(rest)
            .ok_or_else(|| ArcError::config(format!("invalid wildcard SNI pattern: {sni}")))?;
        if suffix.contains('*') {
            return Err(ArcError::config(format!(
                "invalid wildcard SNI pattern: {sni}"
            )));
        }
        return Ok((true, suffix));
    }
    let host = normalize_sni_host(s)
        .ok_or_else(|| ArcError::config(format!("invalid exact SNI pattern: {sni}")))?;
    Ok((false, host))
}

fn resolve_host_port_once(host: &str, port: u16) -> std::result::Result<SocketAddr, String> {
    let mut it = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("dns lookup error: {e}"))?;
    it.next()
        .ok_or_else(|| "dns lookup returned empty address list".to_string())
}

fn compile_response_header_mutations(
    cfg: &ResponseHeadersConfig,
    route_index: usize,
) -> Result<Arc<[CompiledHeaderMutation]>> {
    const FORBIDDEN: [&[u8]; 8] = [
        b"connection",
        b"proxy-connection",
        b"keep-alive",
        b"transfer-encoding",
        b"upgrade",
        b"te",
        b"trailer",
        b"content-length",
    ];
    let mut out = Vec::new();
    for (name, value) in cfg.set.iter() {
        let (n, n_lower, v) =
            compile_response_header_kv(name, value, route_index, "set", &FORBIDDEN)?;
        out.push(CompiledHeaderMutation::Set {
            name: Bytes::copy_from_slice(n.as_bytes()),
            name_lower: Bytes::copy_from_slice(n_lower.as_bytes()),
            value: Bytes::copy_from_slice(v.as_bytes()),
        });
    }
    for (name, value) in cfg.add.iter() {
        let (n, n_lower, v) =
            compile_response_header_kv(name, value, route_index, "add", &FORBIDDEN)?;
        out.push(CompiledHeaderMutation::Add {
            name: Bytes::copy_from_slice(n.as_bytes()),
            name_lower: Bytes::copy_from_slice(n_lower.as_bytes()),
            value: Bytes::copy_from_slice(v.as_bytes()),
        });
    }
    for (idx, name) in cfg.remove.iter().enumerate() {
        let n = name.trim();
        if n.is_empty() {
            return Err(ArcError::config(format!(
                "routes[{route_index}].response_headers.remove[{idx}] must not be empty"
            )));
        }
        if !is_http_header_name_token(n.as_bytes()) {
            return Err(ArcError::config(format!(
                "routes[{route_index}].response_headers.remove[{idx}] invalid header token: {n}"
            )));
        }
        let lower = n.to_ascii_lowercase();
        if FORBIDDEN
            .iter()
            .any(|f| lower.as_bytes().eq_ignore_ascii_case(f))
        {
            return Err(ArcError::config(format!(
                "routes[{route_index}].response_headers.remove[{idx}] refuses hop-by-hop/framing header: {n}"
            )));
        }
        out.push(CompiledHeaderMutation::Remove {
            name_lower: Bytes::copy_from_slice(lower.as_bytes()),
        });
    }
    Ok(out.into())
}

fn compile_response_header_kv(
    name: &str,
    value: &str,
    route_index: usize,
    kind: &str,
    forbidden: &[&[u8]],
) -> Result<(String, String, String)> {
    let n = name.trim();
    if n.is_empty() {
        return Err(ArcError::config(format!(
            "routes[{route_index}].response_headers.{kind} has empty header name"
        )));
    }
    if !is_http_header_name_token(n.as_bytes()) {
        return Err(ArcError::config(format!(
            "routes[{route_index}].response_headers.{kind} invalid header token: {n}"
        )));
    }
    let lower = n.to_ascii_lowercase();
    if forbidden
        .iter()
        .any(|f| lower.as_bytes().eq_ignore_ascii_case(f))
    {
        return Err(ArcError::config(format!(
            "routes[{route_index}].response_headers.{kind} refuses hop-by-hop/framing header: {n}"
        )));
    }
    if value
        .as_bytes()
        .iter()
        .any(|&b| b == b'\r' || b == b'\n' || b == 0)
    {
        return Err(ArcError::config(format!(
            "routes[{route_index}].response_headers.{kind} invalid value for header: {n}"
        )));
    }
    Ok((n.to_string(), lower, value.to_string()))
}

fn compile_real_ip_header(raw: Option<&str>, route_index: usize) -> Result<Arc<str>> {
    let name = raw.unwrap_or("X-Real-IP").trim();
    if name.is_empty() {
        return Err(ArcError::config(format!(
            "routes[{route_index}].real_ip_header must not be empty"
        )));
    }
    if !is_http_header_name_token(name.as_bytes()) {
        return Err(ArcError::config(format!(
            "routes[{route_index}].real_ip_header is invalid header token: {name}"
        )));
    }
    Ok(Arc::from(name))
}

fn compile_request_id_header(raw: &str, field_path: &str) -> Result<Arc<str>> {
    const FORBIDDEN: [&[u8]; 8] = [
        b"connection",
        b"proxy-connection",
        b"keep-alive",
        b"transfer-encoding",
        b"upgrade",
        b"te",
        b"trailer",
        b"content-length",
    ];
    let name = raw.trim();
    if name.is_empty() {
        return Err(ArcError::config(format!(
            "{field_path} must not be empty"
        )));
    }
    if !is_http_header_name_token(name.as_bytes()) {
        return Err(ArcError::config(format!(
            "{field_path} is invalid header token: {name}"
        )));
    }
    if FORBIDDEN
        .iter()
        .any(|f| name.as_bytes().eq_ignore_ascii_case(f))
    {
        return Err(ArcError::config(format!(
            "{field_path} refuses hop-by-hop/framing header: {name}"
        )));
    }
    Ok(Arc::from(name))
}

fn compile_trusted_proxies(
    items: &[String],
    field_path: &str,
) -> Result<Arc<[TrustedProxyCidr]>> {
    if items.is_empty() {
        return Ok(Arc::from([]));
    }
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let cidr = parse_trusted_proxy_cidr(item).map_err(|e| {
            ArcError::config(format!(
                "{field_path}[{idx}] invalid: {item} ({e})"
            ))
        })?;
        out.push(cidr);
    }
    Ok(out.into())
}

fn parse_trusted_proxy_cidr(raw: &str) -> std::result::Result<TrustedProxyCidr, &'static str> {
    let src = raw.trim();
    if src.is_empty() {
        return Err("empty value");
    }
    let (ip_part, prefix_part) = match src.split_once('/') {
        Some((ip, prefix)) => (ip.trim(), Some(prefix.trim())),
        None => (src, None),
    };
    let ip = ip_part.parse::<IpAddr>().map_err(|_| "invalid ip")?;
    match (ip, prefix_part) {
        (IpAddr::V4(v4), Some(prefix)) => {
            let plen = prefix.parse::<u8>().map_err(|_| "invalid ipv4 prefix")?;
            if plen > 32 {
                return Err("ipv4 prefix must be <= 32");
            }
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&v4.octets());
            Ok(TrustedProxyCidr {
                addr,
                prefix_len: plen,
                is_ipv4: true,
            })
        }
        (IpAddr::V4(v4), None) => {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&v4.octets());
            Ok(TrustedProxyCidr {
                addr,
                prefix_len: 32,
                is_ipv4: true,
            })
        }
        (IpAddr::V6(v6), Some(prefix)) => {
            let plen = prefix.parse::<u8>().map_err(|_| "invalid ipv6 prefix")?;
            if plen > 128 {
                return Err("ipv6 prefix must be <= 128");
            }
            Ok(TrustedProxyCidr {
                addr: v6.octets(),
                prefix_len: plen,
                is_ipv4: false,
            })
        }
        (IpAddr::V6(v6), None) => Ok(TrustedProxyCidr {
            addr: v6.octets(),
            prefix_len: 128,
            is_ipv4: false,
        }),
    }
}

fn is_http_header_name_token(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    s.iter().all(|b| {
        matches!(
            *b,
            b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
    })
}

#[inline]
fn default_true() -> bool {
    true
}

#[inline]
fn default_dns_refresh_ms() -> u64 {
    30_000
}

#[inline]
fn default_http2_max_concurrent_streams() -> u32 {
    100
}

#[inline]
fn default_http2_max_active_streams() -> usize {
    1000
}

#[inline]
fn default_max_request_body_bytes() -> usize {
    10 * 1024 * 1024
}

#[inline]
fn default_upstream_leak_warn_growth() -> usize {
    1024
}

#[inline]
fn default_upstream_leak_warn_window_ms() -> u64 {
    30_000
}

#[inline]
fn default_upstream_leak_warn_cooldown_ms() -> u64 {
    60_000
}

#[inline]
fn default_request_id_header() -> String {
    "X-Request-Id".to_string()
}

#[inline]
fn default_cli_handshake_ms() -> u64 {
    3000
}

#[inline]
fn default_up_handshake_ms() -> u64 {
    3000
}

#[inline]
fn default_linger_ms() -> u32 {
    300
}

#[inline]
fn default_accept_prepost() -> u32 {
    32
}

#[inline]
fn default_io_uring_entries() -> u32 {
    1024
}

#[inline]
fn default_listen_backlog() -> i32 {
    4096
}

#[inline]
fn default_upstream_keepalive() -> usize {
    32
}

#[inline]
fn default_control_bind() -> String {
    "127.0.0.1:19998".to_string()
}

#[inline]
fn default_control_node_id() -> String {
    "arc-node".to_string()
}

#[inline]
fn default_control_pull_interval_ms() -> u64 {
    1000
}

#[inline]
fn default_control_peer_timeout_ms() -> u64 {
    1200
}

#[inline]
fn default_control_longpoll_timeout_ms() -> u64 {
    30_000
}

#[inline]
fn default_control_peer_concurrency() -> usize {
    16
}

#[inline]
fn default_control_runtime_threads() -> usize {
    2
}

#[inline]
fn default_control_compile_threads() -> usize {
    2
}

#[inline]
fn default_global_rate_limit_redis_budget_ms() -> u64 {
    2
}

#[inline]
fn default_global_rate_limit_redis_circuit_open_ms() -> u64 {
    500
}

#[inline]
fn default_global_rate_limit_redis_prefetch() -> u32 {
    128
}

#[inline]
fn default_global_rate_limit_redis_low_watermark() -> u32 {
    16
}

#[inline]
fn default_global_rate_limit_redis_refill_backoff_ms() -> u64 {
    1
}

#[inline]
fn default_cluster_circuit_failure_threshold() -> u32 {
    8
}

#[inline]
fn default_cluster_circuit_open_ms() -> u64 {
    3000
}

#[inline]
fn default_cluster_circuit_quorum() -> usize {
    1
}

#[inline]
fn default_cluster_circuit_half_open_probe_interval_ms() -> u64 {
    200
}

#[inline]
fn default_cluster_circuit_active_probe_enabled() -> bool {
    true
}

#[inline]
fn default_cluster_circuit_active_probe_interval_ms() -> u64 {
    2000
}

#[inline]
fn default_cluster_circuit_active_probe_timeout_ms() -> u64 {
    500
}

// ---- ACME defaults ----

#[inline]
fn default_lets_encrypt_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

#[inline]
fn default_acme_challenge_priority() -> Vec<AcmeChallengeType> {
    vec![
        AcmeChallengeType::TlsAlpn01,
        AcmeChallengeType::Http01,
        AcmeChallengeType::Dns01,
    ]
}

#[inline]
fn default_acme_poll_interval_secs() -> u64 {
    1
}

#[inline]
fn default_acme_dns_propagation_timeout_secs() -> u64 {
    120
}

#[inline]
fn default_acme_dns_poll_interval_secs() -> u64 {
    2
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs::{create_dir_all, remove_file, write};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos();
        std::env::temp_dir().join(format!("arc_cfg_{name}_{n}"))
    }

    #[test]
    fn compile_downstream_tls_and_match_sni() {
        let cert_p = temp_path("cert.pem");
        let key_p = temp_path("key.pem");
        if let Some(dir) = cert_p.parent() {
            create_dir_all(dir).expect("create temp dir");
        }
        write(&cert_p, b"dummy-cert").expect("write cert");
        write(&key_p, b"dummy-key").expect("write key");

        let cfg = ConfigFile {
            listen: "127.0.0.1:18080".to_string(),
            admin_listen: "127.0.0.1:19900".to_string(),
            listen_backlog: 4096,
            workers: 1,
            linger_ms: 100,
            io_uring: IoUringConfig {
                entries: 256,
                accept_multishot: false,
                accept_prepost: 32,
                tick_ms: 10,
                sqpoll: false,
                sqpoll_idle_ms: 0,
                iopoll: false,
            },
            buffers: BufferConfig {
                buf_size: 8192,
                buf_count: 64,
            },
            timeouts_ms: TimeoutConfig {
                cli_handshake: 1000,
                cli_read: 1000,
                up_conn: 1000,
                up_handshake: 1000,
                up_write: 1000,
                up_read: 1000,
                cli_write: 1000,
            },
            require_upstream_mtls: false,
            upstreams: vec![UpstreamConfig {
                name: "u".to_string(),
                addr: Some("127.0.0.1:19000".to_string()),
                host: None,
                port: None,
                keepalive: 16,
                idle_ttl_ms: 1000,
                dns_refresh_ms: default_dns_refresh_ms(),
                max_connections: None,
                tls: None,
            }],
            plugins: vec![],
            limits: LimitsConfig::default(),
            tls: TlsConfig {
                downstream: TlsDownstreamConfig {
                    min_version: TlsMinVersionConfig::V1_3,
                },
                upstream: TlsUpstreamConfig::default(),
            },
            http2: Http2Config::default(),
            request_id: RequestIdConfig::default(),
            routes: vec![
                RouteConfig {
                    path: "/".to_string(),
                    upstream: Some("u".to_string()),
                    split: None,
                    load_balance: None,
                    rewrite: None,
                    headers: vec![],
                    response_headers: ResponseHeadersConfig::default(),
                    forwarded_for: false,
                    real_ip_header: None,
                    trusted_proxies: vec![],
                    retry: RetryPolicy::default(),
                    priority: 0,
                    matchers: vec![],
                    action: RouteActionSpec::Forward,
                    plugins: vec![],
                    rate_limit: None,
                    error_pages: HashMap::new(),
                    timeout: None,
                    mirror: None,
                    compression: None,
                    limits: None,
                },
                RouteConfig {
                    path: "/api/*".to_string(),
                    upstream: Some("u".to_string()),
                    split: None,
                    load_balance: None,
                    rewrite: None,
                    headers: vec![],
                    response_headers: ResponseHeadersConfig::default(),
                    forwarded_for: false,
                    real_ip_header: None,
                    trusted_proxies: vec![],
                    retry: RetryPolicy::default(),
                    priority: 0,
                    matchers: vec![],
                    action: RouteActionSpec::Forward,
                    plugins: vec![],
                    rate_limit: None,
                    error_pages: HashMap::new(),
                    timeout: None,
                    mirror: None,
                    compression: None,
                    limits: None,
                },
            ],
            defaults: DefaultsConfig::default(),
            compression: CompressionConfig::default(),
            downstream_tls: Some(DownstreamTlsConfig {
                enable_h2: true,
                min_version: None,
                certificates: vec![DownstreamTlsCertConfig {
                    sni: "*.example.com".to_string(),
                    cert_pem: cert_p.to_string_lossy().to_string(),
                    key_pem: key_p.to_string_lossy().to_string(),
                }],
                sni_routes: vec![
                    SniRouteConfig {
                        sni: "api.example.com".to_string(),
                        path: "/api/*".to_string(),
                    },
                    SniRouteConfig {
                        sni: "*.example.com".to_string(),
                        path: "/".to_string(),
                    },
                ],
                acme: None,
            }),
            control_plane: ControlPlaneConfig {
                enabled: false,
                bind: default_control_bind(),
                role: ControlRole::Standalone,
                node_id: default_control_node_id(),
                peers: vec![],
                quorum: 0,
                auth_token: None,
                pull_from: None,
                pull_interval_ms: default_control_pull_interval_ms(),
                peer_timeout_ms: default_control_peer_timeout_ms(),
                longpoll_timeout_ms: default_control_longpoll_timeout_ms(),
                peer_concurrency: default_control_peer_concurrency(),
                runtime_threads: default_control_runtime_threads(),
                compile_threads: default_control_compile_threads(),
                max_body_bytes: None,
            },
            global_rate_limit: GlobalRateLimitConfig::default(),
            cluster_circuit: ClusterCircuitPolicyConfig::default(),
        };

        let compiled = compile_config(cfg, Arc::from("{}")).expect("compile config");
        let tls = compiled
            .downstream_tls
            .as_ref()
            .expect("downstream tls compiled");

        assert_eq!(tls.min_version, TlsMinVersionConfig::V1_3);
        assert_eq!(tls.sni_routes.resolve_route("api.example.com"), Some(1));
        assert_eq!(tls.sni_routes.resolve_route("www.example.com"), Some(0));
        assert_eq!(tls.sni_routes.resolve_route("example.com"), None);

        let _ = remove_file(cert_p);
        let _ = remove_file(key_p);
    }

    fn ep_inline(body: &str) -> ErrorPageConfig {
        ErrorPageConfig {
            when: ErrorPageWhen::Any,
            body: Some(body.to_string()),
            content_type: None,
            file: None,
            redirect: None,
            code: None,
            upstream: None,
        }
    }

    #[test]
    fn compile_error_pages_sorts_exact_then_range_then_class() {
        let mut cfg = HashMap::new();
        cfg.insert("5xx".to_string(), ep_inline("class"));
        cfg.insert("502-504".to_string(), ep_inline("range"));
        cfg.insert("502".to_string(), ep_inline("exact"));

        let map: HashMap<&str, usize> = HashMap::new();
        let mut hasher = Fnv1a64::new();
        let compiled = compile_error_pages(&cfg, &map, &mut hasher, "test.error_pages")
            .expect("compile error pages");
        assert_eq!(compiled.len(), 3);

        match compiled[0].pattern {
            CompiledErrorPagePattern::Exact(502) => {}
            other => panic!("unexpected first pattern: {other:?}"),
        }
        match compiled[1].pattern {
            CompiledErrorPagePattern::Range {
                start: 502,
                end: 504,
            } => {}
            other => panic!("unexpected second pattern: {other:?}"),
        }
        match compiled[2].pattern {
            CompiledErrorPagePattern::Class(5) => {}
            other => panic!("unexpected third pattern: {other:?}"),
        }
    }

    #[test]
    fn compile_error_pages_file_action_preloads_bytes() {
        let file_path = temp_path("error_5xx.html");
        if let Some(dir) = file_path.parent() {
            create_dir_all(dir).expect("create temp dir");
        }
        let expected = b"<html><h1>arc 5xx</h1></html>";
        write(&file_path, expected).expect("write error page file");

        let mut cfg = HashMap::new();
        cfg.insert(
            "5xx".to_string(),
            ErrorPageConfig {
                when: ErrorPageWhen::Any,
                body: None,
                content_type: Some("text/html; charset=utf-8".to_string()),
                file: Some(file_path.to_string_lossy().to_string()),
                redirect: None,
                code: None,
                upstream: None,
            },
        );

        let map: HashMap<&str, usize> = HashMap::new();
        let mut hasher = Fnv1a64::new();
        let compiled = compile_error_pages(&cfg, &map, &mut hasher, "test.error_pages")
            .expect("compile error pages");
        assert_eq!(compiled.len(), 1);
        match &compiled[0].action {
            CompiledErrorPageAction::Inline {
                template,
                content_type,
            } => {
                assert_eq!(template.as_ref(), expected);
                assert_eq!(content_type.as_ref(), "text/html; charset=utf-8");
            }
            other => panic!("unexpected action: {other:?}"),
        }

        let _ = remove_file(file_path);
    }

    #[test]
    fn compile_error_pages_rejects_invalid_shape() {
        let mut cfg = HashMap::new();
        cfg.insert(
            "502".to_string(),
            ErrorPageConfig {
                when: ErrorPageWhen::Any,
                body: Some("bad".to_string()),
                content_type: Some("text/plain".to_string()),
                file: None,
                redirect: Some("/x".to_string()),
                code: Some(302),
                upstream: None,
            },
        );
        let map: HashMap<&str, usize> = HashMap::new();
        let mut hasher = Fnv1a64::new();
        let err = compile_error_pages(&cfg, &map, &mut hasher, "test.error_pages")
            .expect_err("expected invalid action shape");
        let msg = err.to_string();
        assert!(msg.contains("must set exactly one action"));
    }

    #[test]
    fn compile_request_body_limits_precedence() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "limits": { "max_request_body_bytes": 1024 },
  "routes": [
    { "path": "/a", "upstream": "u" },
    { "path": "/b", "upstream": "u", "limits": { "max_request_body_bytes": 2048 } }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let compiled = compile_config(cfg, Arc::from(raw)).expect("compile config");

        assert_eq!(compiled.routes.len(), 2);
        assert_eq!(compiled.routes[0].max_request_body_bytes, 1024);
        assert_eq!(compiled.routes[1].max_request_body_bytes, 2048);
    }

    #[test]
    fn compile_rejects_invalid_upstream_leak_warn_window() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "limits": {
    "max_request_body_bytes": 1024,
    "upstream_leak_warn_growth": 100,
    "upstream_leak_warn_window_ms": 0,
    "upstream_leak_warn_cooldown_ms": 1000
  },
  "routes": [
    { "path": "/a", "upstream": "u" }
  ]
}"#;
        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let err = compile_config(cfg, Arc::from(raw)).expect_err("must reject invalid leak warning");
        assert!(err.to_string().contains("upstream_leak_warn_window_ms"));
    }

    #[test]
    fn compile_forwarded_for_and_trusted_proxies() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    {
      "path": "/",
      "upstream": "u",
      "forwarded_for": true,
      "real_ip_header": "X-Client-IP",
      "trusted_proxies": ["10.0.0.0/8", "192.168.1.10/32"]
    }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let compiled = compile_config(cfg, Arc::from(raw)).expect("compile config");
        assert_eq!(compiled.routes.len(), 1);
        let route = &compiled.routes[0];
        assert!(route.forwarded_for);
        assert_eq!(route.real_ip_header.as_ref(), "X-Client-IP");
        assert_eq!(route.trusted_proxies.len(), 2);
        assert!(route.trusted_proxies[0].contains_ip("10.2.3.4".parse::<IpAddr>().expect("ip")));
        assert!(!route.trusted_proxies[0].contains_ip("11.2.3.4".parse::<IpAddr>().expect("ip")));
    }

    #[test]
    fn compile_forwarded_for_rejects_invalid_header_and_cidr() {
        let bad_header = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    {
      "path": "/",
      "upstream": "u",
      "forwarded_for": true,
      "real_ip_header": "Bad Header"
    }
  ]
}"#;
        let cfg: ConfigFile = serde_json::from_str(bad_header).expect("parse config");
        let err = compile_config(cfg, Arc::from(bad_header)).expect_err("must reject header");
        assert!(err.to_string().contains("real_ip_header"));

        let bad_cidr = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    {
      "path": "/",
      "upstream": "u",
      "forwarded_for": true,
      "trusted_proxies": ["10.0.0.0/99"]
    }
  ]
}"#;
        let cfg: ConfigFile = serde_json::from_str(bad_cidr).expect("parse config");
        let err = compile_config(cfg, Arc::from(bad_cidr)).expect_err("must reject cidr");
        assert!(err.to_string().contains("trusted_proxies"));
    }

    #[test]
    fn compile_upstream_host_port_dns_and_max_connections() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    {
      "name": "u",
      "host": "localhost",
      "port": 19080,
      "keepalive": 8,
      "idle_ttl_ms": 1000,
      "dns_refresh_ms": 12345,
      "max_connections": 2
    }
  ],
  "plugins": [],
  "routes": [
    { "path": "/", "upstream": "u" }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let compiled = compile_config(cfg, Arc::from(raw)).expect("compile config");
        assert_eq!(compiled.upstreams.len(), 1);
        let upstream = &compiled.upstreams[0];
        assert_eq!(
            upstream.host.as_ref().map(|v| v.as_ref()),
            Some("localhost")
        );
        assert_eq!(upstream.port, 19080);
        assert_eq!(upstream.dns_refresh_ms, 12345);
        assert_eq!(upstream.max_connections, Some(2));
    }

    #[test]
    fn compile_http2_and_request_id_config() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "http2": {
    "max_concurrent_streams": 111,
    "max_active_streams": 222,
    "overflow_action": "rst_refused"
  },
  "request_id": {
    "header": "X-Custom-Request-Id",
    "format": "uuid_v7",
    "on_conflict": "override",
    "preserve_original": true,
    "trusted_proxies": ["10.0.0.0/8"]
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    { "path": "/", "upstream": "u" }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let compiled = compile_config(cfg, Arc::from(raw)).expect("compile config");
        assert_eq!(compiled.http2.max_concurrent_streams, 111);
        assert_eq!(compiled.http2.max_active_streams, 222);
        assert_eq!(compiled.request_id.header.as_ref(), "X-Custom-Request-Id");
        assert_eq!(compiled.request_id.trusted_proxies.len(), 1);
    }

    #[test]
    fn compile_response_header_mutations() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    {
      "path": "/",
      "upstream": "u",
      "response_headers": {
        "set": { "X-Powered-By": "Arc" },
        "add": { "X-Test": "1" },
        "remove": ["Server"]
      }
    }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let compiled = compile_config(cfg, Arc::from(raw)).expect("compile config");
        let muts = compiled.routes[0].response_header_muts.as_ref();
        assert_eq!(muts.len(), 3);

        let has_set = muts.iter().any(|m| match m {
            CompiledHeaderMutation::Set {
                name_lower, value, ..
            } => name_lower.as_ref() == b"x-powered-by" && value.as_ref() == b"Arc",
            _ => false,
        });
        let has_add = muts.iter().any(|m| match m {
            CompiledHeaderMutation::Add {
                name_lower, value, ..
            } => name_lower.as_ref() == b"x-test" && value.as_ref() == b"1",
            _ => false,
        });
        let has_remove = muts.iter().any(|m| match m {
            CompiledHeaderMutation::Remove { name_lower } => name_lower.as_ref() == b"server",
            _ => false,
        });
        assert!(has_set);
        assert!(has_add);
        assert!(has_remove);
    }

    fn minimal_json_config() -> String {
        r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    { "path": "/", "upstream": "u" }
  ]
}"#
        .to_string()
    }

    fn minimal_toml_config() -> String {
        r#"listen = "127.0.0.1:18080"
admin_listen = "127.0.0.1:19900"
workers = 1
require_upstream_mtls = false
plugins = []

[io_uring]
entries = 256
accept_multishot = false
tick_ms = 10
sqpoll = false
sqpoll_idle_ms = 0
iopoll = false

[buffers]
buf_size = 8192
buf_count = 64

[timeouts_ms]
cli_read = 1000
up_conn = 1000
up_write = 1000
up_read = 1000
cli_write = 1000

[[upstreams]]
name = "u"
addr = "127.0.0.1:19080"
keepalive = 8
idle_ttl_ms = 1000

[[routes]]
path = "/"
upstream = "u"
"#
        .to_string()
    }

    fn minimal_yaml_config() -> String {
        r#"listen: "127.0.0.1:18080"
admin_listen: "127.0.0.1:19900"
workers: 1
require_upstream_mtls: false
io_uring:
  entries: 256
  accept_multishot: false
  tick_ms: 10
  sqpoll: false
  sqpoll_idle_ms: 0
  iopoll: false
buffers:
  buf_size: 8192
  buf_count: 64
timeouts_ms:
  cli_read: 1000
  up_conn: 1000
  up_write: 1000
  up_read: 1000
  cli_write: 1000
upstreams:
  - name: "u"
    addr: "127.0.0.1:19080"
    keepalive: 8
    idle_ttl_ms: 1000
plugins: []
routes:
  - path: "/"
    upstream: "u"
"#
        .to_string()
    }

    #[test]
    fn io_uring_entries_and_upstream_keepalive_use_defaults_when_omitted() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    { "path": "/", "upstream": "u" }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        assert_eq!(cfg.io_uring.entries, 1024);
        assert_eq!(cfg.upstreams[0].keepalive, 32);

        let compiled = compile_config(cfg, Arc::from(raw)).expect("compile config");
        assert_eq!(compiled.upstreams[0].keepalive, 32);
    }

    #[test]
    fn compile_route_timeout_and_mirror_from_config() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "prod", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 },
    { "name": "shadow", "addr": "127.0.0.1:19081", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "defaults": {
    "timeout": "60s",
    "mirror_policy": {
      "max_queue_bytes": 1048576,
      "on_upstream_error": "discard",
      "isolation": "strict"
    }
  },
  "routes": [
    {
      "path": "/api",
      "upstream": "prod",
      "timeout": {
        "connect": "2s",
        "response_header": "10s",
        "per_try": "10s",
        "total": "30s"
      },
      "mirror": "shadow"
    }
  ]
}"#;

        let cfg = ConfigManager::compile_raw_json(raw).expect("compile route policy config");
        assert_eq!(cfg.routes.len(), 1);
        let route = &cfg.routes[0];

        let timeout = route
            .timeout_tier
            .as_ref()
            .expect("timeout tier should be compiled");
        assert_eq!(timeout.connect_ms, 2000);
        assert_eq!(timeout.total_ms, 30_000);

        let mirror_policy = route
            .mirror_policy
            .as_ref()
            .expect("mirror policy should be compiled");
        assert_eq!(mirror_policy.max_queue_bytes, 1_048_576);
        assert_eq!(route.mirror_targets.len(), 1);
        assert_eq!(route.mirror_targets[0].upstream_id, 1);
    }

    #[test]
    fn load_from_path_supports_json_toml_yaml() {
        let base = temp_path("multi_format");
        create_dir_all(&base).expect("create temp dir");

        let json_p = base.join("arc.json");
        let toml_p = base.join("arc.toml");
        let yaml_p = base.join("arc.yaml");
        write(&json_p, minimal_json_config()).expect("write json");
        write(&toml_p, minimal_toml_config()).expect("write toml");
        write(&yaml_p, minimal_yaml_config()).expect("write yaml");

        let j = ConfigManager::load_from_path(&json_p).expect("load json");
        let t = ConfigManager::load_from_path(&toml_p).expect("load toml");
        let y = ConfigManager::load_from_path(&yaml_p).expect("load yaml");

        assert_eq!(j.listen, t.listen);
        assert_eq!(j.listen, y.listen);
        assert_eq!(j.routes.len(), 1);
        assert_eq!(t.routes.len(), 1);
        assert_eq!(y.routes.len(), 1);

        assert!(serde_json::from_str::<JsonValue>(j.raw_json.as_ref()).is_ok());
        assert!(serde_json::from_str::<JsonValue>(t.raw_json.as_ref()).is_ok());
        assert!(serde_json::from_str::<JsonValue>(y.raw_json.as_ref()).is_ok());

        let _ = remove_file(json_p);
        let _ = remove_file(toml_p);
        let _ = remove_file(yaml_p);
    }

    #[test]
    fn check_from_path_aggregates_multiple_errors() {
        let base = temp_path("check_aggregate");
        create_dir_all(&base).expect("create temp dir");
        let p = base.join("bad.json");
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 0,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "not-an-ip:abc", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    { "path": "/", "upstream": "u" }
  ],
  "downstream_tls": {
    "enable_h2": true,
    "certificates": [
      {
        "sni": "example.com",
        "cert_pem": "/tmp/arc_missing_cert.pem",
        "key_pem": "/tmp/arc_missing_key.pem"
      }
    ],
    "sni_routes": []
  }
}"#;

        write(&p, raw).expect("write bad config");
        let report = ConfigManager::check_from_path(&p).expect("check from path");
        let joined = report.errors.join("\n");
        assert!(joined.contains("workers must be > 0"));
        assert!(joined.contains("invalid upstream addr"));
        assert!(joined.contains("downstream tls cert_pem not found/readable"));
        assert!(joined.contains("downstream tls key_pem not found/readable"));

        let _ = remove_file(p);
    }

    #[test]
    fn compile_rejects_same_path_priority_specificity_conflict() {
        let raw = r#"{
  "listen": "127.0.0.1:18080",
  "admin_listen": "127.0.0.1:19900",
  "workers": 1,
  "require_upstream_mtls": false,
  "io_uring": {
    "entries": 256,
    "accept_multishot": false,
    "tick_ms": 10,
    "sqpoll": false,
    "sqpoll_idle_ms": 0,
    "iopoll": false
  },
  "buffers": { "buf_size": 8192, "buf_count": 64 },
  "timeouts_ms": {
    "cli_read": 1000,
    "up_conn": 1000,
    "up_write": 1000,
    "up_read": 1000,
    "cli_write": 1000
  },
  "upstreams": [
    { "name": "u", "addr": "127.0.0.1:19080", "keepalive": 8, "idle_ttl_ms": 1000 }
  ],
  "plugins": [],
  "routes": [
    { "path": "/api", "upstream": "u", "priority": 5, "matchers": [] },
    { "path": "/api", "upstream": "u", "priority": 5, "matchers": [] }
  ]
}"#;

        let cfg: ConfigFile = serde_json::from_str(raw).expect("parse config");
        let err = compile_config(cfg, Arc::from(raw)).expect_err("must reject conflict");
        assert!(err
            .to_string()
            .contains("ambiguous routes with same path/priority/specificity"));
    }

    #[test]
    fn load_from_path_rejects_unsupported_extension() {
        let base = temp_path("bad_ext");
        create_dir_all(&base).expect("create temp dir");
        let p = base.join("arc.conf");
        write(&p, minimal_json_config()).expect("write file");

        let err = ConfigManager::load_from_path(&p).expect_err("must reject unsupported extension");
        let msg = err.to_string();
        assert!(msg.contains("unsupported config file extension"));

        let _ = remove_file(p);
    }
}
