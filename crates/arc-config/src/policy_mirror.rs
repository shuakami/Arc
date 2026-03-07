use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Built-in default mirror timeout (per mirror target, independent from route timeout policy).
pub const BUILTIN_MIRROR_TIMEOUT: Duration = Duration::from_secs(3);

/// Built-in default mirror queue memory cap.
///
/// Spec example uses 50MB.
pub const BUILTIN_MIRROR_MAX_QUEUE_BYTES: usize = 50 * 1024 * 1024;

fn default_sample() -> f64 {
    1.0
}

fn default_mirror_timeout() -> Duration {
    BUILTIN_MIRROR_TIMEOUT
}

fn default_max_queue_bytes() -> usize {
    BUILTIN_MIRROR_MAX_QUEUE_BYTES
}

/// Mirror can be configured as a single upstream string or a list of detailed targets.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MirrorConfig {
    /// Shorthand: `mirror: api-shadow`
    Single(String),

    /// Full: `mirror: [{ ... }, { ... }]`
    Multi(Vec<MirrorTargetConfig>),
}

/// Mirror policy shared by all mirror targets of a route.
///
/// This controls memory cap and failure handling, and enforces isolation requirements.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorPolicyConfig {
    /// Global in-memory queue cap in bytes.
    ///
    /// Default: 50MB.
    #[serde(default = "default_max_queue_bytes")]
    pub max_queue_bytes: usize,

    /// When shadow upstream errors, how to handle it.
    ///
    /// Spec: `discard` (no retry, no propagation).
    #[serde(default)]
    pub on_upstream_error: MirrorOnUpstreamError,

    /// Isolation level.
    ///
    /// Spec: `strict` (independent conn pool + independent timeout + no error propagation).
    #[serde(default)]
    pub isolation: MirrorIsolation,
}

impl Default for MirrorPolicyConfig {
    fn default() -> Self {
        Self {
            max_queue_bytes: default_max_queue_bytes(),
            on_upstream_error: MirrorOnUpstreamError::default(),
            isolation: MirrorIsolation::default(),
        }
    }
}

/// Mirror upstream error handling policy.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorOnUpstreamError {
    /// Discard silently (no retry).
    Discard,
}

impl Default for MirrorOnUpstreamError {
    fn default() -> Self {
        MirrorOnUpstreamError::Discard
    }
}

/// Mirror isolation policy.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorIsolation {
    /// Strict isolation: independent connection pool, independent timeouts, fully fire-and-forget.
    Strict,
}

impl Default for MirrorIsolation {
    fn default() -> Self {
        MirrorIsolation::Strict
    }
}

/// A single mirror target.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorTargetConfig {
    /// Target upstream name.
    pub upstream: String,

    /// Sampling rate (0.0 - 1.0).
    ///
    /// Default: 1.0.
    #[serde(default = "default_sample")]
    pub sample: f64,

    /// Mirror timeout (independent from route policy).
    ///
    /// Default: 3s.
    #[serde(default = "default_mirror_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// Optional request transform.
    #[serde(default)]
    pub transform: MirrorTransformConfig,

    /// Optional production vs shadow response compare.
    #[serde(default)]
    pub compare: MirrorCompareConfig,
}

/// Request transformation for mirror.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MirrorTransformConfig {
    /// Header injection/removal.
    #[serde(default)]
    pub headers: MirrorHeadersTransformConfig,

    /// Optional path rewrite template.
    ///
    /// Supports variables like `$path`, `$route.name`.
    #[serde(default)]
    pub path: Option<String>,
}

/// Header transformation for mirror.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MirrorHeadersTransformConfig {
    /// Headers to set/override (string values).
    #[serde(default)]
    pub set: BTreeMap<String, String>,

    /// Headers to remove (case-insensitive match recommended by runtime).
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Compare production vs shadow responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorCompareConfig {
    /// Whether comparison is enabled.
    ///
    /// Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Headers to ignore (case-insensitive).
    #[serde(default)]
    pub ignore_headers: Vec<String>,

    /// JSONPath fields to ignore in body (best-effort subset supported by runtime).
    #[serde(default)]
    pub ignore_body_fields: Vec<String>,

    /// On diff action.
    ///
    /// Spec: only `log` is implemented.
    #[serde(default)]
    pub on_diff: MirrorOnDiff,
}

impl Default for MirrorCompareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ignore_headers: Vec::new(),
            ignore_body_fields: Vec::new(),
            on_diff: MirrorOnDiff::default(),
        }
    }
}

/// What to do when a diff is detected.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorOnDiff {
    /// Only write structured log (no alert, no block).
    Log,
}

impl Default for MirrorOnDiff {
    fn default() -> Self {
        MirrorOnDiff::Log
    }
}

/// Validation error for mirror configuration.
#[derive(Clone, Debug)]
pub struct MirrorValidationError {
    pub path: String,
    pub message: String,
}

impl fmt::Display for MirrorValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.path, self.message)
    }
}

impl std::error::Error for MirrorValidationError {}

impl MirrorPolicyConfig {
    /// Strongly validate mirror policy.
    pub fn validate(&self, path: impl Into<String>) -> Result<(), MirrorValidationError> {
        let path = path.into();

        if self.max_queue_bytes == 0 {
            return Err(MirrorValidationError {
                path,
                message: "  mirror_policy.max_queue_bytes 不能为 0\n  建议：设置为一个合理的内存上限，例如 50MB".to_string(),
            });
        }

        // Currently only strict isolation is supported (spec requirement).
        match self.isolation {
            MirrorIsolation::Strict => {}
        }

        // Currently only discard is supported (spec requirement).
        match self.on_upstream_error {
            MirrorOnUpstreamError::Discard => {}
        }

        Ok(())
    }
}

impl MirrorConfig {
    /// Strongly validate mirror config + policy.
    ///
    /// `policy` is allowed to be omitted; runtime should apply defaults.
    pub fn validate(
        &self,
        policy: Option<&MirrorPolicyConfig>,
        base_path: impl Into<String>,
    ) -> Result<(), MirrorValidationError> {
        let base_path = base_path.into();

        if let Some(p) = policy {
            p.validate(format!("{base_path}.mirror_policy"))?;
        }

        match self {
            MirrorConfig::Single(up) => {
                if up.trim().is_empty() {
                    return Err(MirrorValidationError {
                        path: format!("{base_path}.mirror"),
                        message: "  mirror 不能为空字符串".to_string(),
                    });
                }
            }
            MirrorConfig::Multi(list) => {
                if list.is_empty() {
                    return Err(MirrorValidationError {
                        path: format!("{base_path}.mirror"),
                        message: "  mirror 目标列表不能为空".to_string(),
                    });
                }
                for (i, t) in list.iter().enumerate() {
                    t.validate(format!("{base_path}.mirror[{i}]"))?;
                }
            }
        }

        Ok(())
    }
}

impl MirrorTargetConfig {
    /// Strongly validate a mirror target.
    pub fn validate(&self, path: impl Into<String>) -> Result<(), MirrorValidationError> {
        let path = path.into();

        if self.upstream.trim().is_empty() {
            return Err(MirrorValidationError {
                path,
                message: "  upstream 不能为空字符串".to_string(),
            });
        }

        if !self.sample.is_finite() || self.sample < 0.0 || self.sample > 1.0 {
            return Err(MirrorValidationError {
                path,
                message: format!("  sample({}) 不合法，必须在 0.0-1.0 之间", self.sample),
            });
        }

        if self.timeout.is_zero() {
            return Err(MirrorValidationError {
                path,
                message: "  timeout 不能为 0\n  建议：设置为例如 3s".to_string(),
            });
        }

        // compare.on_diff currently only supports log.
        match self.compare.on_diff {
            MirrorOnDiff::Log => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_single_validate_ok() {
        let mirror = MirrorConfig::Single("shadow-upstream".to_string());
        let policy = MirrorPolicyConfig::default();
        mirror
            .validate(Some(&policy), "routes[0]")
            .expect("single mirror should be valid");
    }

    #[test]
    fn mirror_target_rejects_invalid_sample() {
        let target = MirrorTargetConfig {
            upstream: "shadow-upstream".to_string(),
            sample: 1.5,
            timeout: Duration::from_secs(3),
            transform: Default::default(),
            compare: Default::default(),
        };
        let err = target
            .validate("routes[0].mirror[0]")
            .expect_err("sample > 1.0 must fail");
        assert!(err.to_string().contains("sample"));
    }
}
