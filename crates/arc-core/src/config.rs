use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

/// Top-level Arc configuration.
///
/// This is **Schema-first**: derive JSON Schema and use it to drive IDE completion.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArcConfig {
    /// Node-level runtime settings.
    pub node: NodeConfig,

    /// Listening endpoints.
    pub listeners: Vec<ListenerConfig>,

    /// Named upstream groups.
    pub upstreams: Vec<UpstreamConfig>,

    /// Routing rules.
    pub routes: Vec<RouteConfig>,

    /// Plugins (WASM + Rhai) registry and per-route attachment.
    #[serde(default)]
    pub plugins: PluginsConfig,

    /// Built-in observability.
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Node-local control plane.
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
}

/// Runtime / capacity settings.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Human-readable node id.
    #[serde(default = "default_node_id")]
    pub id: String,

    /// Worker threads (data plane). If 0, auto = num_cpu.
    #[serde(default)]
    pub workers: usize,

    #[serde(default)]
    pub max_connections: u64,

    /// Global read timeout for downstream connections.
    #[serde(with = "humantime_serde", default = "default_read_timeout")]
    #[schemars(with = "String")]
    pub read_timeout: Duration,

    /// Global write timeout for downstream connections.
    #[serde(with = "humantime_serde", default = "default_write_timeout")]
    #[schemars(with = "String")]
    pub write_timeout: Duration,

    /// Global idle timeout for keep-alive connections.
    #[serde(with = "humantime_serde", default = "default_idle_timeout")]
    #[schemars(with = "String")]
    pub idle_timeout: Duration,
}

fn default_node_id() -> String {
    "arc-node".to_string()
}
fn default_read_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_write_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

/// Listener kind.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListenerKind {
    /// HTTP/1.1 and HTTP/2 over cleartext (H2C optional).
    Http,
    /// HTTPS with HTTP/1.1 and HTTP/2 (ALPN), dynamic certs.
    Https,
    /// HTTP/3 over QUIC.
    H3,
    /// Raw TCP L4 proxy / LB.
    Tcp,
    /// Raw UDP L4 proxy / LB.
    Udp,
}

/// Socket-level settings (SO_REUSEPORT / TFO / keepalive / DSCP).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct SocketOptions {
    #[serde(default)]
    pub so_reuseport: bool,
    #[serde(default)]
    pub tcp_fastopen_backlog: Option<usize>,
    #[serde(default)]
    pub dscp: Option<u8>,
    #[serde(default)]
    pub keepalive: Option<TcpKeepaliveConfig>,
}

/// Keepalive configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TcpKeepaliveConfig {
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub idle: Duration,
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub interval: Duration,
    pub count: u32,
}

/// Listener configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub kind: ListenerKind,
    /// Bind address, e.g. "0.0.0.0:443".
    pub bind: String,

    #[serde(default)]
    pub socket: SocketOptions,

    /// TLS settings for Https/H3.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// TLS configuration for server-side endpoints.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// If set, use ACME to obtain/renew certs for these hostnames.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,

    /// Static certificates loaded on boot.
    #[serde(default)]
    pub certificates: Vec<CertificateEntry>,

    /// Enforce TLS versions.
    #[serde(default)]
    pub min_version: Option<TlsVersion>,
    #[serde(default)]
    pub max_version: Option<TlsVersion>,

    /// Cipher suites preference (OpenSSL/BoringSSL only).
    #[serde(default)]
    pub cipher_suites: Vec<String>,

    /// Enable session resumption.
    #[serde(default = "default_true")]
    pub session_resumption: bool,
}

fn default_true() -> bool {
    true
}

/// A certificate entry.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateEntry {
    /// SNI hostname (exact or wildcard like "*.example.com").
    pub sni: String,
    /// Path to PEM cert chain.
    pub cert_pem: String,
    /// Path to PEM private key.
    pub key_pem: String,
}

/// TLS version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// ACME configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub email: Option<String>,

    #[serde(default = "default_lets_encrypt_directory")]
    pub directory_url: String,

    /// Optional custom CA bundle (PEM) for the ACME endpoint.
    #[serde(default)]
    pub directory_ca_pem: Option<String>,

    /// Account key configuration (encrypted at rest).
    pub account_key: AcmeAccountKey,

    /// Domains to manage.
    pub domains: Vec<String>,

    /// Challenge strategy / preference.
    pub challenge: AcmeChallenge,

    /// Renew before expiry.
    #[serde(with = "humantime_serde", default = "default_renew_before")]
    #[schemars(with = "String")]
    pub renew_before: Duration,
}

fn default_lets_encrypt_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_renew_before() -> Duration {
    Duration::from_secs(60 * 60 * 24 * 30) // 30 days
}

/// Account key algorithm.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AcmeAccountKeyAlgorithm {
    Ed25519,
    Rsa2048,
}

/// Passphrase source for decrypting account key on boot.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AcmePassphraseSource {
    Env { name: String },
    File { path: String },
}

/// ACME account key config (encrypted key file on disk).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcmeAccountKey {
    pub algorithm: AcmeAccountKeyAlgorithm,
    pub encrypted_key_path: String,
    pub passphrase: AcmePassphraseSource,
}

/// ACME challenge types.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AcmeChallenge {
    /// HTTP-01 challenge served by Arc.
    Http01 {
        /// The listener name that serves http-01, usually port 80.
        listener: String,
    },
    /// TLS-ALPN-01 challenge served by Arc (ALPN acme-tls/1).
    TlsAlpn01 {
        /// The TLS listener name, usually port 443.
        listener: String,
    },
    /// DNS-01 challenge via provider integration.
    Dns01 {
        provider: DnsProvider,
    },
}

/// DNS provider integrations.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum DnsProvider {
    /// RFC2136 dynamic update.
    Rfc2136 {
        server: String,
        key_name: String,
        key_value: String,
        algorithm: String,
    },
    /// Cloudflare API.
    Cloudflare {
        api_token: String,
    },
    /// Route53.
    Route53 {
        access_key_id: String,
        secret_access_key: String,
        region: String,
    },
    /// Generic webhook.
    Webhook {
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    /// External hook command (present/cleanup).
    Hook {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
    },
}

/// Upstream configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,

    /// How endpoints are discovered.
    pub discovery: UpstreamDiscovery,

    #[serde(default)]
    pub lb: LoadBalancing,

    #[serde(default)]
    pub health: HealthCheckConfig,

    #[serde(default)]
    pub pool: ConnectionPoolConfig,

    #[serde(default)]
    pub timeouts: UpstreamTimeouts,
}

// ---- 下面保持你原来的内容不变（UpstreamDiscovery / LB / Routing / Plugins / Observability / ControlPlane / load_from_path 等） ----

/// Upstream discovery.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamDiscovery {
    /// Static list.
    Static { endpoints: Vec<EndpointConfig> },
    /// DNS-based (async polling, TTL-respecting).
    Dns {
        hostname: String,
        port: u16,
        /// Respect DNS TTL.
        #[serde(default = "default_true")]
        respect_ttl: bool,
        /// If TTL is missing/0, use this fallback.
        #[serde(with = "humantime_serde", default = "default_dns_poll")]
        #[schemars(with = "String")]
        fallback_poll: Duration,
    },
}

fn default_dns_poll() -> Duration {
    Duration::from_secs(10)
}

/// Endpoint config.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Load balancing algorithms.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "algorithm", rename_all = "snake_case")]
pub enum LoadBalancing {
    #[serde(rename_all = "snake_case")]
    RoundRobin,
    WeightedRoundRobin,
    LeastRequests,
    ConsistentHash {
        #[serde(default = "default_hash_key")]
        key: HashKey,
        #[serde(default = "default_virtual_nodes")]
        virtual_nodes: u32,
    },
    PeakEwma {
        #[serde(with = "humantime_serde", default = "default_ewma_decay")]
        #[schemars(with = "String")]
        decay: Duration,
    },
}

impl Default for LoadBalancing {
    fn default() -> Self {
        LoadBalancing::PeakEwma { decay: default_ewma_decay() }
    }
}

fn default_virtual_nodes() -> u32 {
    256
}
fn default_ewma_decay() -> Duration {
    Duration::from_secs(10)
}

/// Hash key source.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum HashKey {
    ClientIp,
    Header { name: String },
    Cookie { name: String },
}

impl Default for HashKey {
    fn default() -> Self {
        HashKey::ClientIp
    }
}

fn default_hash_key() -> HashKey {
    HashKey::ClientIp
}

/// Health checks.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Active checks.
    #[serde(default)]
    pub active: Option<ActiveHealthCheck>,
    /// Passive checks (outlier detection).
    #[serde(default)]
    pub passive: Option<PassiveHealthCheck>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveHealthCheck {
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub interval: Duration,
    #[serde(default = "default_active_path")]
    pub path: String,
    #[serde(default = "default_failures")]
    pub fail_after: u32,
    #[serde(default = "default_successes")]
    pub pass_after: u32,
}

fn default_active_path() -> String {
    "/health".to_string()
}
fn default_failures() -> u32 {
    3
}
fn default_successes() -> u32 {
    2
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PassiveHealthCheck {
    #[serde(default = "default_error_rate")]
    pub error_rate_threshold: f64,
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub window: Duration,
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub ejection_time: Duration,
}

fn default_error_rate() -> f64 {
    0.2
}

/// Connection pool settings.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPoolConfig {
    #[serde(default = "default_max_idle")]
    pub max_idle: usize,
    #[serde(with = "humantime_serde", default = "default_idle_ttl")]
    #[schemars(with = "String")]
    pub idle_ttl: Duration,
    #[serde(with = "humantime_serde", default = "default_conn_ttl")]
    #[schemars(with = "String")]
    pub max_lifetime: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_idle: default_max_idle(),
            idle_ttl: default_idle_ttl(),
            max_lifetime: default_conn_ttl(),
        }
    }
}

fn default_max_idle() -> usize {
    1024
}
fn default_idle_ttl() -> Duration {
    Duration::from_secs(30)
}
fn default_conn_ttl() -> Duration {
    Duration::from_secs(300)
}

/// Upstream timeouts.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTimeouts {
    #[serde(with = "humantime_serde", default = "default_connect_timeout")]
    #[schemars(with = "String")]
    pub connect: Duration,
    #[serde(with = "humantime_serde", default = "default_write_timeout")]
    #[schemars(with = "String")]
    pub write: Duration,
    #[serde(with = "humantime_serde", default = "default_ttfb_timeout")]
    #[schemars(with = "String")]
    pub ttfb: Duration,
    #[serde(with = "humantime_serde", default = "default_read_timeout")]
    #[schemars(with = "String")]
    pub read: Duration,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect: default_connect_timeout(),
            write: default_write_timeout(),
            ttfb: default_ttfb_timeout(),
            read: default_read_timeout(),
        }
    }
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_ttfb_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Routing rule.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub r#match: RouteMatch,
    pub action: RouteAction,

    /// Optional per-route rate limiting.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,

    /// Optional mirroring.
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,

    /// Optional weighted split (A/B, canary).
    #[serde(default)]
    pub split: Option<TrafficSplitConfig>,

    /// Plugins attached to this route.
    #[serde(default)]
    pub plugins: Vec<RoutePluginRef>,
}

/// Route match dimensions.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    /// Host / SNI match.
    #[serde(default)]
    pub host: Vec<String>,

    /// HTTP methods (GET/POST/...). Empty = any.
    #[serde(default)]
    pub methods: Vec<String>,

    /// Path pattern, e.g. "/api/{id}" or "/api/{*rest}".
    pub path: String,

    /// Header predicates.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,

    /// Cookie predicates.
    #[serde(default)]
    pub cookies: Vec<CookieMatch>,

    /// Query predicates.
    #[serde(default)]
    pub query: Vec<QueryMatch>,

    #[serde(default)]
    pub expr: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HeaderMatch {
    Exists { name: String },
    Contains { name: String, value: String },
    Regex { name: String, pattern: String },
    Equals { name: String, value: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CookieMatch {
    Equals { name: String, value: String },
    Regex { name: String, pattern: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum QueryMatch {
    Exists { name: String },
    Equals { name: String, value: String },
    Regex { name: String, pattern: String },
}

/// Route action.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteAction {
    /// Which upstream to route to.
    pub upstream: String,

    /// Optional URL rewrite.
    #[serde(default)]
    pub rewrite: Option<RewriteRule>,

    /// Header mutations.
    #[serde(default)]
    pub headers: Vec<HeaderMutation>,

    /// Redirect short-circuit.
    #[serde(default)]
    pub redirect: Option<RedirectAction>,

    /// Retry strategy.
    #[serde(default)]
    pub retry: RetryPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteRule {
    pub pattern: String,
    pub replace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HeaderMutation {
    Add { name: String, value: String },
    Set { name: String, value: String },
    Remove { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedirectAction {
    pub status: u16,
    pub location: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    #[serde(default = "default_retries")]
    pub max_retries: u32,
    #[serde(with = "humantime_serde", default = "default_backoff")]
    #[schemars(with = "String")]
    pub backoff: Duration,
    #[serde(default = "default_idempotent_only")]
    pub idempotent_only: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: default_retries(),
            backoff: default_backoff(),
            idempotent_only: default_idempotent_only(),
        }
    }
}

fn default_retries() -> u32 {
    1
}
fn default_backoff() -> Duration {
    Duration::from_millis(50)
}
fn default_idempotent_only() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests per second.
    pub qps: u64,
    /// Burst size.
    pub burst: u64,
    /// Keying strategy.
    #[serde(default)]
    pub key: RateLimitKey,
    /// Response status code.
    #[serde(default = "default_rl_status")]
    pub status: u16,
}

fn default_rl_status() -> u16 {
    429
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum RateLimitKey {
    ClientIp,
    Header { name: String },
    Route,
}

impl Default for RateLimitKey {
    fn default() -> Self {
        RateLimitKey::ClientIp
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    pub upstream: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrafficSplitConfig {
    pub choices: Vec<TrafficChoice>,
    /// Stable key for deterministic split.
    #[serde(default)]
    pub key: HashKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrafficChoice {
    pub upstream: String,
    pub weight: u32,
}

/// Plugin registry.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginsConfig {
    #[serde(default)]
    pub wasm: Vec<WasmPluginConfig>,
    #[serde(default)]
    pub rhai: Vec<RhaiScriptConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WasmPluginConfig {
    pub name: String,
    pub file: String,
    /// CPU time budget per invocation.
    #[serde(with = "humantime_serde", default = "default_wasm_budget")]
    #[schemars(with = "String")]
    pub budget: Duration,
}

fn default_wasm_budget() -> Duration {
    Duration::from_millis(2)
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RhaiScriptConfig {
    pub name: String,
    pub inline: String,
    /// Max operations.
    #[serde(default = "default_rhai_ops")]
    pub max_ops: u64,
}

fn default_rhai_ops() -> u64 {
    50_000
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutePluginRef {
    pub name: String,
    #[serde(default)]
    pub stage: PluginStage,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PluginStage {
    L4,
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Log,
}

impl Default for PluginStage {
    fn default() -> Self {
        PluginStage::RequestHeaders
    }
}

/// Observability config.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: String,
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    #[serde(default)]
    pub tracing: Option<OtlpConfig>,

    #[serde(default)]
    pub access_log: AccessLogConfig,
}

fn default_metrics_bind() -> String {
    "127.0.0.1:9090".to_string()
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_bind: default_metrics_bind(),
            metrics_enabled: true,
            tracing: None,
            access_log: AccessLogConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    pub endpoint: String,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Sample rate in [0,1].
    #[serde(default = "default_sample")]
    pub sample: f64,
    /// Disable logging for these route names.
    #[serde(default)]
    pub disabled_routes: Vec<String>,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample: default_sample(),
            disabled_routes: vec![],
        }
    }
}

fn default_sample() -> f64 {
    1.0
}

/// Node-local control plane.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    #[serde(default = "default_control_bind")]
    pub bind: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub auth_token: Option<String>,
}

fn default_control_bind() -> String {
    "127.0.0.1:9900".to_string()
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            bind: default_control_bind(),
            enabled: true,
            auth_token: None,
        }
    }
}

/// Load ArcConfig from YAML/JSON.
pub fn load_from_path(path: impl AsRef<Path>) -> anyhow::Result<ArcConfig> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    let cfg = match ext {
        "yaml" | "yml" => serde_yaml::from_slice(&bytes)?,
        "json" => serde_json::from_slice(&bytes)?,
        _ => {
            serde_yaml::from_slice(&bytes)
                .or_else(|_| serde_json::from_slice(&bytes))?
        }
    };
    Ok(cfg)
}