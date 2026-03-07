use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Built-in default timeout for connecting to an upstream.
///
/// This is a request-level cap (not a per-syscall socket timeout).
pub const BUILTIN_TIMEOUT_CONNECT: Duration = Duration::from_secs(3);

/// Built-in default timeout for receiving the first byte of the upstream response header (TTFB).
pub const BUILTIN_TIMEOUT_RESPONSE_HEADER: Duration = Duration::from_secs(30);

/// Built-in default timeout upper bound for a single try (one attempt, including retries).
pub const BUILTIN_TIMEOUT_PER_TRY: Duration = Duration::from_secs(30);

/// Built-in default absolute timeout cap for the whole request.
pub const BUILTIN_TIMEOUT_TOTAL: Duration = Duration::from_secs(60);

const SMART_TOTAL_SLACK: Duration = Duration::from_secs(5);

/// Minimum duration floor used to avoid zero-duration corner cases.
const MIN_NONZERO_DURATION: Duration = Duration::from_millis(1);

fn default_deadline_header() -> String {
    "X-Request-Deadline".to_string()
}

/// Configuration for deadline propagation.
///
/// Deadline propagation is **disabled by default**.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeadlinePropagationConfig {
    /// Whether deadline propagation is enabled.
    ///
    /// Default: false.
    #[serde(default)]
    pub enabled: Option<bool>,

    #[serde(default)]
    pub header: Option<String>,
}

/// Per-route / default overrides for request timeout tiering.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TimeoutTierOverrides {
    /// Upstream connect timeout (TCP connect + optional TLS handshake).
    ///
    /// Unit: duration string (e.g. `3s`, `250ms`).
    #[serde(default, with = "humantime_serde::option")]
    pub connect: Option<Duration>,

    /// Upstream response header TTFB timeout (time to first byte of response headers).
    #[serde(default, with = "humantime_serde::option")]
    pub response_header: Option<Duration>,

    /// Single try (one attempt) timeout cap.
    #[serde(default, with = "humantime_serde::option")]
    pub per_try: Option<Duration>,

    /// Whole request absolute timeout cap.
    #[serde(default, with = "humantime_serde::option")]
    pub total: Option<Duration>,

    /// Optional deadline propagation behavior.
    ///
    /// If omitted, inherits from higher-level defaults (and ultimately disabled).
    #[serde(default)]
    pub deadline_propagation: Option<DeadlinePropagationConfig>,
}

/// `timeout` can be either a single duration (smart-expanded) or a structured object with explicit fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TimeoutTierConfig {
    /// Shorthand: `timeout: 30s`
    ///
    /// This expands into a full tiered policy using Arc's smart defaults.
    Scalar(#[serde(with = "humantime_serde")] Duration),

    /// Full / partial override object.
    Object(TimeoutTierOverrides),
}

/// Effective, fully-resolved timeout tiering policy.
#[derive(Clone, Debug)]
pub struct EffectiveTimeoutTier {
    pub connect: Duration,
    pub response_header: Duration,
    pub per_try: Duration,
    pub total: Duration,
    pub deadline_propagation: EffectiveDeadlinePropagation,
}

/// Effective deadline propagation policy.
#[derive(Clone, Debug)]
pub struct EffectiveDeadlinePropagation {
    pub enabled: bool,
    pub header: String,
}

impl Default for EffectiveDeadlinePropagation {
    fn default() -> Self {
        Self {
            enabled: false,
            header: default_deadline_header(),
        }
    }
}

impl Default for EffectiveTimeoutTier {
    fn default() -> Self {
        Self {
            connect: BUILTIN_TIMEOUT_CONNECT,
            response_header: BUILTIN_TIMEOUT_RESPONSE_HEADER,
            per_try: BUILTIN_TIMEOUT_PER_TRY,
            total: BUILTIN_TIMEOUT_TOTAL,
            deadline_propagation: EffectiveDeadlinePropagation::default(),
        }
    }
}

impl TimeoutTierConfig {
    /// Resolve a timeout tiering policy with precedence:
    /// `route override` > `global defaults` > `built-in defaults`.
    pub fn resolve(
        route: Option<&TimeoutTierConfig>,
        defaults: Option<&TimeoutTierConfig>,
    ) -> EffectiveTimeoutTier {
        let mut eff = EffectiveTimeoutTier::default();

        if let Some(d) = defaults {
            eff = apply_timeout_config(eff, d);
        }
        if let Some(r) = route {
            eff = apply_timeout_config(eff, r);
        }

        // Do not auto-correct here; validation is strict and returns an ERROR.
        eff
    }
}

fn apply_timeout_config(
    mut base: EffectiveTimeoutTier,
    cfg: &TimeoutTierConfig,
) -> EffectiveTimeoutTier {
    match cfg {
        TimeoutTierConfig::Scalar(total) => {
            // Scalar override expands connect/ttfb/per_try/total, but keeps deadline propagation
            // from inherited defaults so global propagation config still applies.
            let dp = base.deadline_propagation.clone();
            let mut derived = derive_from_total(*total);
            derived.deadline_propagation = dp;
            derived
        }
        TimeoutTierConfig::Object(o) => {
            if let Some(v) = o.connect {
                base.connect = v;
            }
            if let Some(v) = o.response_header {
                base.response_header = v;
            }
            if let Some(v) = o.per_try {
                base.per_try = v;
            }
            if let Some(v) = o.total {
                base.total = v;
            }

            if let Some(dp) = o.deadline_propagation.as_ref() {
                if let Some(enabled) = dp.enabled {
                    base.deadline_propagation.enabled = enabled;
                }
                if let Some(header) = dp.header.as_ref() {
                    base.deadline_propagation.header = header.clone();
                }
            }

            base
        }
    }
}

fn clamp_nonzero(d: Duration) -> Duration {
    if d.is_zero() {
        MIN_NONZERO_DURATION
    } else {
        d
    }
}

pub fn derive_from_total(total: Duration) -> EffectiveTimeoutTier {
    let total = clamp_nonzero(total);

    // Connect keeps built-in default (3s), clamped to total.
    let connect = BUILTIN_TIMEOUT_CONNECT.min(total);

    // response_header/per_try become total - slack (5s) if possible, else total.
    let base = if total > SMART_TOTAL_SLACK {
        total - SMART_TOTAL_SLACK
    } else {
        total
    };

    let response_header = clamp_nonzero(base);
    let per_try = clamp_nonzero(base);

    EffectiveTimeoutTier {
        connect,
        response_header,
        per_try,
        total,
        deadline_propagation: EffectiveDeadlinePropagation::default(),
    }
}

/// Validation error for a resolved timeout tier.
#[derive(Clone, Debug)]
pub struct TimeoutTierValidationError {
    pub path: String,
    pub message: String,
}

impl fmt::Display for TimeoutTierValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep formatting close to the spec. Caller should prefix with "Error:" when printing.
        write!(f, "{}\n{}", self.path, self.message)
    }
}

impl std::error::Error for TimeoutTierValidationError {}

impl EffectiveTimeoutTier {
    /// Validate the policy against invariants and retry attempts.
    ///
    /// `retry_attempts` is the total number of tries (including the first attempt).
    pub fn validate(
        &self,
        retry_attempts: u32,
        path: impl Into<String>,
    ) -> Result<(), TimeoutTierValidationError> {
        let path = path.into();

        let connect = clamp_nonzero(self.connect);
        let response_header = clamp_nonzero(self.response_header);
        let per_try = clamp_nonzero(self.per_try);
        let total = clamp_nonzero(self.total);

        if connect > total {
            return Err(TimeoutTierValidationError {
                path,
                message: format!(
                    "  connect({}) 超过 total({})\n  这意味着请求在建立上游连接之前就会触发 total 超时\n  建议：将 total 调整为 ≥ {}，或将 connect 调整为 ≤ {}",
                    humantime::format_duration(connect),
                    humantime::format_duration(total),
                    humantime::format_duration(connect),
                    humantime::format_duration(total),
                ),
            });
        }

        if per_try > total {
            return Err(TimeoutTierValidationError {
                path,
                message: format!(
                    "  per_try({}) 超过 total({})\n  这意味着每次尝试都会被 total 兜底提前打断\n  建议：将 total 调整为 ≥ {}，或将 per_try 调整为 ≤ {}",
                    humantime::format_duration(per_try),
                    humantime::format_duration(total),
                    humantime::format_duration(per_try),
                    humantime::format_duration(total),
                ),
            });
        }

        if response_header > per_try {
            return Err(TimeoutTierValidationError {
                path,
                message: format!(
                    "  response_header({}) 超过 per_try({})\n  这意味着 response_header 超时永远不会先于 per_try 触发\n  建议：将 response_header 调整为 ≤ {}，或将 per_try 调整为 ≥ {}",
                    humantime::format_duration(response_header),
                    humantime::format_duration(per_try),
                    humantime::format_duration(per_try),
                    humantime::format_duration(response_header),
                ),
            });
        }

        if connect > per_try {
            return Err(TimeoutTierValidationError {
                path,
                message: format!(
                    "  connect({}) 超过 per_try({})\n  这意味着上游连接还没建立，本次尝试就会先触发 per_try 超时\n  建议：将 connect 调整为 ≤ {}，或将 per_try 调整为 ≥ {}",
                    humantime::format_duration(connect),
                    humantime::format_duration(per_try),
                    humantime::format_duration(per_try),
                    humantime::format_duration(connect),
                ),
            });
        }

        let attempts = retry_attempts.max(1);
        let per_try_total = match per_try.checked_mul(attempts) {
            Some(v) => v,
            None => {
                return Err(TimeoutTierValidationError {
                    path,
                    message: format!(
                        "  per_try({}) × retry.attempts({}) 溢出\n  建议：缩小 per_try 或 retry.attempts",
                        humantime::format_duration(per_try),
                        attempts,
                    ),
                });
            }
        };

        if per_try_total > total {
            let suggested_per_try = div_duration_floor(total, attempts);
            return Err(TimeoutTierValidationError {
                path,
                message: format!(
                    "  per_try({}) × retry.attempts({}) = {}，超过 total({})\n  这意味着后几次重试永远不会被执行\n  建议：将 total 调整为 ≥ {}，或将 per_try 调整为 ≤ {}",
                    humantime::format_duration(per_try),
                    attempts,
                    humantime::format_duration(per_try_total),
                    humantime::format_duration(total),
                    humantime::format_duration(per_try_total),
                    humantime::format_duration(suggested_per_try),
                ),
            });
        }

        Ok(())
    }
}

fn div_duration_floor(d: Duration, n: u32) -> Duration {
    let n = n.max(1) as u128;
    let nanos = d.as_nanos();
    let q = nanos / n;

    // Duration::from_nanos expects u64, clamp if needed.
    if q > u64::MAX as u128 {
        Duration::from_nanos(u64::MAX)
    } else if q == 0 {
        MIN_NONZERO_DURATION
    } else {
        Duration::from_nanos(q as u64)
    }
}

pub fn parse_deadline_budget(value: &str) -> Option<Duration> {
    let s = value.trim();
    if s.is_empty() {
        return None;
    }

    let all_digits = s.as_bytes().iter().all(|b| b.is_ascii_digit());
    if all_digits {
        let ms = s.parse::<u64>().ok()?;
        return Some(Duration::from_millis(ms));
    }

    humantime::parse_duration(s).ok()
}

/// Format an outbound deadline propagation header value as integer milliseconds.
pub fn format_deadline_budget_ms(d: Duration) -> String {
    // Clamp to u64 millis.
    let ms128 = d.as_millis();
    let ms = if ms128 > u64::MAX as u128 {
        u64::MAX
    } else {
        ms128 as u64
    };
    ms.to_string()
}

pub fn compute_effective_total(
    route_total: Duration,
    client_budget: Option<Duration>,
    dp: &EffectiveDeadlinePropagation,
) -> Duration {
    let route_total = clamp_nonzero(route_total);
    if !dp.enabled {
        return route_total;
    }

    match client_budget {
        Some(b) => clamp_nonzero(route_total.min(clamp_nonzero(b))),
        None => route_total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_expand_matches_spec_example() {
        let t = derive_from_total(Duration::from_secs(30));
        assert_eq!(t.connect, Duration::from_secs(3));
        assert_eq!(t.response_header, Duration::from_secs(25));
        assert_eq!(t.per_try, Duration::from_secs(25));
        assert_eq!(t.total, Duration::from_secs(30));
    }

    #[test]
    fn validate_retry_budget_error_message_contains_key_lines() {
        let eff = EffectiveTimeoutTier {
            connect: Duration::from_secs(3),
            response_header: Duration::from_secs(10),
            per_try: Duration::from_secs(10),
            total: Duration::from_secs(30),
            deadline_propagation: EffectiveDeadlinePropagation::default(),
        };

        let res = eff.validate(5, "routes[3].policy.timeout");
        match res {
            Ok(()) => panic!("expected validation error"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("routes[3].policy.timeout"));
                assert!(msg.contains("per_try("));
                assert!(msg.contains("retry.attempts(5)"));
                assert!(msg.contains("超过 total("));
                assert!(msg.contains("建议"));
            }
        }
    }

    #[test]
    fn parse_deadline_budget_accepts_ms_and_humantime() {
        let a = parse_deadline_budget("1500");
        assert_eq!(a, Some(Duration::from_millis(1500)));

        let b = parse_deadline_budget("1.5s");
        assert_eq!(b, Some(Duration::from_millis(1500)));

        let c = parse_deadline_budget("   ");
        assert_eq!(c, None);
    }
}
