use serde::Deserialize;
use std::time::Duration;

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_xdp_syn_threshold_multiplier() -> f64 {
    5.0
}

fn default_xdp_defense_multiplier() -> f64 {
    2.0
}

fn default_xdp_sigma_multiplier() -> f64 {
    3.0
}

fn default_xdp_warmup_secs() -> u64 {
    60
}

fn default_blacklist_capacity() -> u32 {
    1_000_000
}

fn default_whitelist_capacity() -> u32 {
    65_536
}

fn default_zerocopy_threshold_bytes() -> usize {
    4096
}

fn default_xdp_pin_base() -> String {
    crate::XDP_PIN_BASE.to_string()
}

fn default_auto_block_enabled() -> bool {
    true
}

fn default_auto_block_threshold() -> u32 {
    100
}

fn default_auto_block_window_secs() -> u64 {
    10
}

fn default_auto_block_ttl_secs() -> u64 {
    600
}

fn default_auto_block_reason() -> String {
    "manual".to_string()
}

fn default_cookie_rotation_interval() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_slowloris_headers_timeout() -> u64 {
    10
}

fn default_slowloris_min_recv_rate_bps() -> u64 {
    100
}

fn default_slowloris_max_incomplete_conns_per_ip() -> u32 {
    1000
}

fn deserialize_duration_secs_or_humantime<'de, D>(de: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Duration;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "duration as seconds (number) or humantime string (e.g. \"1h\")"
            )
        }

        fn visit_u64<E>(self, v: u64) -> Result<Duration, E>
        where
            E: Error,
        {
            Ok(Duration::from_secs(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Duration, E>
        where
            E: Error,
        {
            if v < 0 {
                return Err(E::custom("duration must be >= 0"));
            }
            Ok(Duration::from_secs(v as u64))
        }

        fn visit_str<E>(self, s: &str) -> Result<Duration, E>
        where
            E: Error,
        {
            humantime::parse_duration(s).map_err(|e| E::custom(format!("invalid duration: {e}")))
        }

        fn visit_string<E>(self, s: String) -> Result<Duration, E>
        where
            E: Error,
        {
            self.visit_str(&s)
        }
    }

    de.deserialize_any(V)
}

/// Top-level “side-channel” parsed config: only xdp + l7_protection.
///
/// serde 默认会忽略未知字段，因此可以对 raw_json 安全解析。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ArcSecurityConfig {
    #[serde(default)]
    pub xdp: XdpUserConfig,
    #[serde(default)]
    pub l7_protection: L7ProtectionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct XdpUserConfig {
    /// 是否启用 XDP（默认 false）。
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// 绑定网卡名；None => auto-detect（默认）。
    #[serde(default)]
    pub interface: Option<String>,

    #[serde(default = "default_xdp_pin_base")]
    pub pin_base: String,

    #[serde(default)]
    pub syn_proxy: SynProxyConfig,

    #[serde(default)]
    pub defense: XdpDefenseConfig,

    #[serde(default)]
    pub maps: XdpMapsConfig,

    /// L7 rate-limit -> XDP auto block policy.
    #[serde(default)]
    pub auto_block: AutoBlockConfig,

    #[serde(default = "default_zerocopy_threshold_bytes")]
    pub zerocopy_threshold_bytes: usize,
}

impl Default for XdpUserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            pin_base: default_xdp_pin_base(),
            syn_proxy: SynProxyConfig::default(),
            defense: XdpDefenseConfig::default(),
            maps: XdpMapsConfig::default(),
            auto_block: AutoBlockConfig::default(),
            zerocopy_threshold_bytes: default_zerocopy_threshold_bytes(),
        }
    }
}

/// Auto block config: when L7 per-route limiter rejects too many requests from an IP in a window,
/// user-space will write the IP into XDP blacklist map with TTL.
#[derive(Debug, Deserialize, Clone)]
pub struct AutoBlockConfig {
    /// Enable/disable auto block loop.
    #[serde(default = "default_auto_block_enabled")]
    pub enabled: bool,

    /// Trigger threshold in one rolling window.
    #[serde(default = "default_auto_block_threshold")]
    pub threshold: u32,

    /// Rolling window size in seconds.
    #[serde(default = "default_auto_block_window_secs")]
    pub window_secs: u64,

    /// Block TTL in seconds.
    #[serde(default = "default_auto_block_ttl_secs")]
    pub ttl_secs: u64,

    /// Block reason string:
    /// "manual" | "syn_flood" | "ack_flood" | "rst_invalid" | "udp_rate_limit".
    #[serde(default = "default_auto_block_reason")]
    pub reason: String,

    /// Static bypass list (ip or cidr string, e.g. "10.0.0.1", "10.0.0.0/24", "2001:db8::/64").
    #[serde(default)]
    pub whitelist: Vec<String>,
}

impl Default for AutoBlockConfig {
    fn default() -> Self {
        Self {
            enabled: default_auto_block_enabled(),
            threshold: default_auto_block_threshold(),
            window_secs: default_auto_block_window_secs(),
            ttl_secs: default_auto_block_ttl_secs(),
            reason: default_auto_block_reason(),
            whitelist: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SynProxyConfig {
    /// 是否启用 SYN proxy（默认 false）。
    #[serde(default = "default_false")]
    pub enabled: bool,

    #[serde(
        default = "default_cookie_rotation_interval",
        deserialize_with = "deserialize_duration_secs_or_humantime"
    )]
    pub cookie_rotation_interval: Duration,
}

impl Default for SynProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cookie_rotation_interval: default_cookie_rotation_interval(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct XdpDefenseConfig {
    /// 正常模式阈值倍数（默认 5.0）。
    #[serde(default = "default_xdp_syn_threshold_multiplier")]
    pub syn_threshold_multiplier: f64,

    /// 防御模式阈值倍数（默认 2.0）。
    #[serde(default = "default_xdp_defense_multiplier")]
    pub defense_multiplier: f64,

    /// 触发防御的 σ 倍数（默认 3.0）。
    #[serde(default = "default_xdp_sigma_multiplier")]
    pub sigma_multiplier: f64,

    /// 启动预热秒数（默认 60 秒），期间不触发防御。
    #[serde(default = "default_xdp_warmup_secs")]
    pub warmup_secs: u64,
}

impl Default for XdpDefenseConfig {
    fn default() -> Self {
        Self {
            syn_threshold_multiplier: default_xdp_syn_threshold_multiplier(),
            defense_multiplier: default_xdp_defense_multiplier(),
            sigma_multiplier: default_xdp_sigma_multiplier(),
            warmup_secs: default_xdp_warmup_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct XdpMapsConfig {
    /// 黑名单容量（默认 1_000_000）。
    #[serde(default = "default_blacklist_capacity")]
    pub blacklist_capacity: u32,

    /// 白名单容量（默认 65_536）。
    #[serde(default = "default_whitelist_capacity")]
    pub whitelist_capacity: u32,
}

impl Default for XdpMapsConfig {
    fn default() -> Self {
        Self {
            blacklist_capacity: default_blacklist_capacity(),
            whitelist_capacity: default_whitelist_capacity(),
        }
    }
}

/// L7 protection config node.
#[derive(Debug, Deserialize, Clone)]
pub struct L7ProtectionConfig {
    #[serde(default)]
    pub slowloris: SlowlorisConfig,
}

impl Default for L7ProtectionConfig {
    fn default() -> Self {
        Self {
            slowloris: SlowlorisConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SlowlorisConfig {
    /// 是否启用（默认 true）。
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// 请求头接收超时（秒，默认 10）。
    #[serde(default = "default_slowloris_headers_timeout")]
    pub headers_timeout_secs: u64,

    /// 最低接收速率（bytes/s，默认 100）。
    #[serde(default = "default_slowloris_min_recv_rate_bps")]
    pub min_recv_rate_bps: u64,

    /// 单 IP 未完成连接数上限（默认 1000）。
    #[serde(default = "default_slowloris_max_incomplete_conns_per_ip")]
    pub max_incomplete_conns_per_ip: u32,
}

impl Default for SlowlorisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            headers_timeout_secs: default_slowloris_headers_timeout(),
            min_recv_rate_bps: default_slowloris_min_recv_rate_bps(),
            max_incomplete_conns_per_ip: default_slowloris_max_incomplete_conns_per_ip(),
        }
    }
}

/// Parse only (xdp, l7_protection) from Arc SharedConfig raw_json.
///
/// 如果 raw_json 不是 JSON 或字段不合法：返回 Default（并由调用方决定是否 warn）。
pub fn parse_security_config_best_effort(raw_json: &str) -> ArcSecurityConfig {
    match serde_json::from_str::<ArcSecurityConfig>(raw_json) {
        Ok(v) => v,
        Err(_) => ArcSecurityConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_security_config_returns_default_on_invalid_json() {
        let cfg = parse_security_config_best_effort("{invalid-json}");
        assert!(!cfg.xdp.enabled);
        assert_eq!(cfg.xdp.pin_base, crate::XDP_PIN_BASE);
        assert!(cfg.l7_protection.slowloris.enabled);
    }

    #[test]
    fn parse_security_config_reads_xdp_and_l7_fields() {
        let raw = r#"{
          "xdp": {
            "enabled": true,
            "interface": "eth0",
            "pin_base": "/sys/fs/bpf/arc-node-a",
            "zerocopy_threshold_bytes": 8192,
            "auto_block": {
              "enabled": true,
              "threshold": 77,
              "window_secs": 12,
              "ttl_secs": 345,
              "reason": "syn_flood",
              "whitelist": ["10.0.0.1", "10.0.0.0/24"]
            },
            "syn_proxy": {
              "enabled": true,
              "cookie_rotation_interval": "30m"
            }
          },
          "l7_protection": {
            "slowloris": {
              "enabled": true,
              "headers_timeout_secs": 9,
              "min_recv_rate_bps": 222,
              "max_incomplete_conns_per_ip": 33
            }
          }
        }"#;
        let cfg = parse_security_config_best_effort(raw);
        assert!(cfg.xdp.enabled);
        assert_eq!(cfg.xdp.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.xdp.pin_base, "/sys/fs/bpf/arc-node-a");
        assert_eq!(cfg.xdp.zerocopy_threshold_bytes, 8192);
        assert_eq!(cfg.xdp.auto_block.threshold, 77);
        assert_eq!(cfg.xdp.auto_block.window_secs, 12);
        assert_eq!(cfg.xdp.auto_block.ttl_secs, 345);
        assert_eq!(cfg.xdp.auto_block.reason, "syn_flood");
        assert_eq!(cfg.xdp.auto_block.whitelist.len(), 2);
        assert_eq!(
            cfg.xdp.syn_proxy.cookie_rotation_interval,
            Duration::from_secs(1800)
        );
        assert_eq!(cfg.l7_protection.slowloris.headers_timeout_secs, 9);
        assert_eq!(cfg.l7_protection.slowloris.min_recv_rate_bps, 222);
        assert_eq!(cfg.l7_protection.slowloris.max_incomplete_conns_per_ip, 33);
    }

    #[test]
    fn parse_security_config_duration_accepts_numeric_seconds() {
        let raw = r#"{
          "xdp": {
            "syn_proxy": {
              "cookie_rotation_interval": 600
            }
          }
        }"#;
        let cfg = parse_security_config_best_effort(raw);
        assert_eq!(
            cfg.xdp.syn_proxy.cookie_rotation_interval,
            Duration::from_secs(600)
        );
    }
}
