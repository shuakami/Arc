use arc_common::{ArcError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Built-in default min_size (bytes).
pub const BUILTIN_COMPRESSION_MIN_SIZE: usize = 1024;

fn default_true() -> bool {
    true
}

fn default_algorithms() -> Vec<CompressionAlgorithm> {
    vec![
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Br,
        CompressionAlgorithm::Gzip,
    ]
}

fn default_zstd_level() -> i32 {
    3
}

fn default_gzip_level() -> i32 {
    6
}

fn default_brotli_level() -> i32 {
    5
}

fn default_cpu_high() -> f64 {
    0.80
}

fn default_cpu_low() -> f64 {
    0.30
}

fn default_check_interval() -> Duration {
    Duration::from_secs(5)
}

fn default_cooldown() -> Duration {
    Duration::from_secs(30)
}

/// Compression algorithm enum for config.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAlgorithm {
    /// zstd
    Zstd,
    /// brotli
    Br,
    /// gzip
    Gzip,
}

/// MIME types config (append-only semantics).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionMimeTypesConfig {
    #[serde(default)]
    pub include: Vec<String>,

    /// Extra exclude patterns appended to built-in exclude list.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Adaptive compression config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionAdaptiveConfig {
    /// Whether adaptive control is enabled.
    ///
    /// Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// CPU high threshold, in [0.0, 1.0].
    ///
    /// Default: 0.80.
    #[serde(default = "default_cpu_high")]
    pub cpu_high_threshold: f64,

    /// CPU low threshold, in [0.0, 1.0].
    ///
    /// Default: 0.30.
    #[serde(default = "default_cpu_low")]
    pub cpu_low_threshold: f64,

    /// Check interval (anti-oscillation).
    ///
    /// Default: 5s.
    #[serde(with = "humantime_serde", default = "default_check_interval")]
    pub check_interval: Duration,

    /// Cooldown after an adjustment (anti-oscillation).
    ///
    /// Default: 30s.
    #[serde(with = "humantime_serde", default = "default_cooldown")]
    pub cooldown: Duration,
}

impl Default for CompressionAdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_high_threshold: default_cpu_high(),
            cpu_low_threshold: default_cpu_low(),
            check_interval: default_check_interval(),
            cooldown: default_cooldown(),
        }
    }
}

/// Global compression config (user config model).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    /// Enable compression globally.
    ///
    /// Default: true (smart default).
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_min_size")]
    pub min_size: usize,

    /// Supported algorithms in priority order.
    ///
    /// Default: [zstd, br, gzip].
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<CompressionAlgorithm>,

    /// Base zstd level.
    ///
    /// Default: 3. Range: 1..=5
    #[serde(default = "default_zstd_level")]
    pub zstd_level: i32,

    /// Base gzip level.
    ///
    /// Default: 6. Range: 1..=9
    #[serde(default = "default_gzip_level")]
    pub gzip_level: i32,

    /// Base brotli level.
    ///
    /// Default: 5. Range: 4..=6
    #[serde(default = "default_brotli_level")]
    pub brotli_level: i32,

    /// MIME types include/exclude (append-only).
    #[serde(default)]
    pub mime_types: CompressionMimeTypesConfig,

    /// Adaptive control config.
    #[serde(default)]
    pub adaptive: CompressionAdaptiveConfig,
}

fn default_min_size() -> usize {
    BUILTIN_COMPRESSION_MIN_SIZE
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size: default_min_size(),
            algorithms: default_algorithms(),
            zstd_level: default_zstd_level(),
            gzip_level: default_gzip_level(),
            brotli_level: default_brotli_level(),
            mime_types: CompressionMimeTypesConfig::default(),
            adaptive: CompressionAdaptiveConfig::default(),
        }
    }
}

/// Per-route compression overrides (user config model).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCompressionConfig {
    /// Override enable on this route.
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Force a single algorithm (must still be accepted by client).
    #[serde(default)]
    pub algorithm: Option<CompressionAlgorithm>,

    #[serde(default)]
    pub level: Option<i32>,

    /// Override min_size in bytes.
    #[serde(default)]
    pub min_size: Option<usize>,

    /// SSE: flush per event.
    #[serde(default)]
    pub flush_per_event: bool,
}

/// Effective global compression policy (resolved).
#[derive(Clone, Debug)]
pub struct EffectiveCompressionGlobal {
    pub enabled: bool,
    pub min_size: usize,
    pub algorithms: Vec<CompressionAlgorithm>,
    pub zstd_level: i32,
    pub gzip_level: i32,
    pub brotli_level: i32,
    pub mime_types: CompressionMimeTypesConfig,
    pub adaptive: CompressionAdaptiveConfig,
}

/// Effective per-route policy (resolved).
#[derive(Clone, Debug)]
pub struct EffectiveCompressionRoute {
    pub enabled: bool,
    pub min_size: usize,
    pub algorithm: Option<CompressionAlgorithm>,
    pub level: Option<i32>,
    pub flush_per_event: bool,
}

impl CompressionConfig {
    /// Resolve and validate global config.
    pub fn resolve(&self) -> Result<EffectiveCompressionGlobal> {
        validate_global(self)?;
        Ok(EffectiveCompressionGlobal {
            enabled: self.enabled,
            min_size: self.min_size,
            algorithms: self.algorithms.clone(),
            zstd_level: self.zstd_level,
            gzip_level: self.gzip_level,
            brotli_level: self.brotli_level,
            mime_types: self.mime_types.clone(),
            adaptive: self.adaptive.clone(),
        })
    }

    /// Resolve per-route effective policy with precedence:
    /// route override > global.
    pub fn resolve_route(
        global: &EffectiveCompressionGlobal,
        route: Option<&RouteCompressionConfig>,
    ) -> Result<EffectiveCompressionRoute> {
        let enabled = route.and_then(|r| r.enabled).unwrap_or(global.enabled);

        let min_size = route.and_then(|r| r.min_size).unwrap_or(global.min_size);

        let algorithm = route.and_then(|r| r.algorithm);

        let level = route.and_then(|r| r.level);

        let flush_per_event = route.map(|r| r.flush_per_event).unwrap_or(false);

        let eff = EffectiveCompressionRoute {
            enabled,
            min_size,
            algorithm,
            level,
            flush_per_event,
        };

        validate_effective(global, &eff)?;
        Ok(eff)
    }
}

fn validate_global(c: &CompressionConfig) -> Result<()> {
    if c.min_size == 0 {
        return Err(ArcError::config(
            "compression.min_size must be > 0".to_string(),
        ));
    }

    if c.algorithms.is_empty() {
        return Err(ArcError::config(
            "compression.algorithms must be non-empty".to_string(),
        ));
    }

    // no duplicates
    let mut seen: HashSet<CompressionAlgorithm> = HashSet::new();
    for a in &c.algorithms {
        if !seen.insert(*a) {
            return Err(ArcError::config(format!(
                "compression.algorithms has duplicate: {a:?}"
            )));
        }
    }

    if !(1..=5).contains(&c.zstd_level) {
        return Err(ArcError::config(
            "compression.zstd_level must be within [1, 5]".to_string(),
        ));
    }
    if !(1..=9).contains(&c.gzip_level) {
        return Err(ArcError::config(
            "compression.gzip_level must be within [1, 9]".to_string(),
        ));
    }
    if !(4..=6).contains(&c.brotli_level) {
        return Err(ArcError::config(
            "compression.brotli_level must be within [4, 6]".to_string(),
        ));
    }

    validate_adaptive(&c.adaptive)?;
    Ok(())
}

fn validate_adaptive(a: &CompressionAdaptiveConfig) -> Result<()> {
    if !(0.0..=1.0).contains(&a.cpu_high_threshold) {
        return Err(ArcError::config(
            "compression.adaptive.cpu_high_threshold must be within [0.0, 1.0]".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&a.cpu_low_threshold) {
        return Err(ArcError::config(
            "compression.adaptive.cpu_low_threshold must be within [0.0, 1.0]".to_string(),
        ));
    }
    if a.cpu_low_threshold >= a.cpu_high_threshold {
        return Err(ArcError::config(
            "compression.adaptive.cpu_low_threshold must be < cpu_high_threshold".to_string(),
        ));
    }
    if a.check_interval == Duration::from_secs(0) {
        return Err(ArcError::config(
            "compression.adaptive.check_interval must be > 0".to_string(),
        ));
    }
    if a.cooldown == Duration::from_secs(0) {
        return Err(ArcError::config(
            "compression.adaptive.cooldown must be > 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_effective(
    global: &EffectiveCompressionGlobal,
    r: &EffectiveCompressionRoute,
) -> Result<()> {
    if r.min_size == 0 {
        return Err(ArcError::config(
            "routes[].compression.min_size must be > 0".to_string(),
        ));
    }

    // If route fixed algorithm, ensure it's globally enabled (still allows forcing even if global algorithms exclude it?)
    // Spec says route can force; but "Arc支持算法列表" should include it.
    if let Some(a) = r.algorithm {
        if !global.algorithms.contains(&a) {
            return Err(ArcError::config(format!(
                "routes[].compression.algorithm={a:?} is not in global compression.algorithms"
            )));
        }
    }

    // validate level range if both algorithm+level exist, or if level exists without algorithm
    if let Some(lv) = r.level {
        let alg = r.algorithm.unwrap_or_else(|| {
            // If algorithm not specified, level applies to negotiated algorithm at runtime.
            // We validate by allowing union of safe ranges.
            CompressionAlgorithm::Zstd
        });

        validate_level_for_alg(alg, lv, r.algorithm.is_some())?;
    }

    Ok(())
}

fn validate_level_for_alg(alg: CompressionAlgorithm, lv: i32, strict: bool) -> Result<()> {
    // strict=true means algorithm is fixed and we can validate precisely.
    // strict=false means algorithm is negotiated; we accept any value that falls into at least one safe range.
    if strict {
        match alg {
            CompressionAlgorithm::Zstd => {
                if !(1..=5).contains(&lv) {
                    return Err(ArcError::config(
                        "routes[].compression.level for zstd must be within [1, 5]".to_string(),
                    ));
                }
            }
            CompressionAlgorithm::Gzip => {
                if !(1..=9).contains(&lv) {
                    return Err(ArcError::config(
                        "routes[].compression.level for gzip must be within [1, 9]".to_string(),
                    ));
                }
            }
            CompressionAlgorithm::Br => {
                if !(4..=6).contains(&lv) {
                    return Err(ArcError::config(
                        "routes[].compression.level for br must be within [4, 6]".to_string(),
                    ));
                }
            }
        }
        return Ok(());
    }

    // Non-strict: allow a safe superset.
    if (1..=9).contains(&lv) || (4..=6).contains(&lv) {
        Ok(())
    } else {
        Err(ArcError::config(
            "routes[].compression.level must be within a safe range (zstd:1-5, gzip:1-9, br:4-6)"
                .to_string(),
        ))
    }
}
