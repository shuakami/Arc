use crate::{config::ArcConfig, router::Router, upstream::UpstreamRegistry};
use arc_swap::ArcSwap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
pub struct CompiledConfig {
    /// Unique generation id.
    pub generation: Uuid,

    /// Original config (kept for control plane introspection; not used on the hot path).
    pub raw: ArcConfig,

    /// Router (host/method/path radix + high-dimensional predicates).
    pub router: Router,

    /// Upstream registry (discovery + LB + health).
    pub upstreams: UpstreamRegistry,
}

impl CompiledConfig {
    /// Compile an ArcConfig into an in-memory config ready for RCU swap.
    pub fn compile(cfg: ArcConfig) -> anyhow::Result<Self> {
        let router = Router::build(&cfg.routes)?;
        let upstreams = UpstreamRegistry::build(&cfg.upstreams)?;

        Ok(Self {
            generation: Uuid::new_v4(),
            raw: cfg,
            router,
            upstreams,
        })
    }
}

/// Shared configuration handle (RCU style).
#[derive(Debug)]
pub struct SharedConfig {
    inner: ArcSwap<CompiledConfig>,
}

impl SharedConfig {
    /// Create from compiled config.
    pub fn new(initial: CompiledConfig) -> Self {
        Self {
            inner: ArcSwap::from_pointee(initial),
        }
    }

    /// Load the current config.
    #[inline]
    pub fn load(&self) -> Arc<CompiledConfig> {
        self.inner.load_full()
    }

    /// Atomically swap config.
    #[inline]
    pub fn swap(&self, next: Arc<CompiledConfig>) {
        self.inner.store(next);
    }
}
