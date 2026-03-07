// Arc is a large system; we keep docs strict at the public API boundary,
// and allow internal modules to evolve without blocking builds.
#![allow(missing_docs)]

pub mod config;
pub mod compiled;
pub mod router;
pub mod upstream;
pub mod rate_limit;
pub mod mutations;
pub mod trace;
pub mod telemetry;
pub mod control;
pub mod plugins;
pub mod policy_mirror;
pub mod policy_timeout;

pub use compiled::{CompiledConfig, SharedConfig};
