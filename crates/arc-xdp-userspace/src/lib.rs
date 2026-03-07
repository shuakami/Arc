#![cfg(target_os = "linux")]
#![allow(dead_code, unused_variables, unused_mut, unused_assignments)]

pub mod bpf;
pub mod config;
pub mod l7;
pub mod manager;
pub mod system_tuner;
pub mod zerocopy;

pub use crate::config::{ArcSecurityConfig, L7ProtectionConfig, XdpUserConfig};
pub use crate::l7::{L7Protection, SlowlorisGuard};
pub use crate::manager::{
    BlacklistManager, L7LinkHandle, StatsSnapshot, ThresholdSnapshot, WhitelistManager, XdpManager,
    XdpManagerState, XdpMode, XdpStatusSnapshot,
};
pub use crate::system_tuner::{SystemStatusSnapshot, SystemTuner, TuneMode, TuneResult};
pub use crate::zerocopy::ZeroCopyResponder;

/// XDP pinned objects base directory default.
pub const XDP_PIN_BASE: &str = "/sys/fs/bpf/arc";
