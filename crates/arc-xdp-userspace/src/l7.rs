use crate::config::L7ProtectionConfig;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

/// L7 metrics (暴露给上层 metrics collector)。
#[derive(Debug, Default)]
pub struct L7Metrics {
    pub slowloris_dropped_total: AtomicU64,
}

/// L7Protection top-level object.
#[derive(Debug)]
pub struct L7Protection {
    pub slowloris: SlowlorisGuard,
    pub metrics: L7Metrics,
}

impl L7Protection {
    /// Build from config.
    pub fn new(cfg: &L7ProtectionConfig) -> Self {
        Self {
            slowloris: SlowlorisGuard::new(cfg),
            metrics: L7Metrics::default(),
        }
    }
}

/// Decision for slowloris guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowlorisDecision {
    Allow,
    DropTimeout,
    DropMinRate,
    DropTooManyIncomplete,
}

/// Per-connection state for slowloris checks.
///
/// 调用方（Arc worker）把它存到 conn struct 里即可。
#[derive(Debug, Clone, Copy)]
pub struct SlowlorisConnState {
    pub started_ns: u64,
    pub bytes_in_headers: u64,
}

#[derive(Debug)]
struct IpBucketCounter {
    mask: u64,
    buckets: Vec<AtomicU32>,
}

impl IpBucketCounter {
    fn new(bucket_pow2: usize) -> Self {
        let n = bucket_pow2.max(1024).next_power_of_two();
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(AtomicU32::new(0));
        }
        Self {
            mask: (n as u64).saturating_sub(1),
            buckets: v,
        }
    }

    #[inline]
    fn hash64(key: u64) -> u64 {
        // very small mixer (splitmix64-like)
        let mut x = key.wrapping_add(0x9E3779B97F4A7C15);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
        x ^ (x >> 31)
    }

    #[inline]
    fn idx(&self, key: u64) -> usize {
        (Self::hash64(key) & self.mask) as usize
    }

    #[inline]
    fn inc(&self, key: u64) -> u32 {
        let i = self.idx(key);
        self.buckets[i]
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    #[inline]
    fn dec(&self, key: u64) {
        let i = self.idx(key);
        // saturating decrement via CAS loop
        let b = &self.buckets[i];
        let mut cur = b.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return;
            }
            match b.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return,
                Err(v) => cur = v,
            }
        }
    }

    #[inline]
    fn get(&self, key: u64) -> u32 {
        let i = self.idx(key);
        self.buckets[i].load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct SlowlorisGuard {
    enabled: bool,
    headers_timeout_ns: u64,
    min_recv_rate_bps: u64,
    max_incomplete_per_ip: u32,

    incomplete: IpBucketCounter,
}

impl SlowlorisGuard {
    pub fn new(cfg: &L7ProtectionConfig) -> Self {
        let c = &cfg.slowloris;
        Self {
            enabled: c.enabled,
            headers_timeout_ns: c.headers_timeout_secs.saturating_mul(1_000_000_000).max(1),
            min_recv_rate_bps: c.min_recv_rate_bps.max(1),
            max_incomplete_per_ip: c.max_incomplete_conns_per_ip.max(1),
            // 262k buckets: collisions acceptable; memory ~ 1MB
            incomplete: IpBucketCounter::new(262_144),
        }
    }

    /// Called when a new connection starts, before request headers complete.
    ///
    /// 返回：是否允许继续接入（超过 incomplete 上限则拒绝）。
    #[inline]
    pub fn on_conn_start(&self, ip_key_hash: u64) -> SlowlorisDecision {
        if !self.enabled {
            return SlowlorisDecision::Allow;
        }
        let cur = self.incomplete.inc(ip_key_hash);
        if cur > self.max_incomplete_per_ip {
            // rollback the increment to avoid permanent inflation on rejects
            self.incomplete.dec(ip_key_hash);
            SlowlorisDecision::DropTooManyIncomplete
        } else {
            SlowlorisDecision::Allow
        }
    }

    /// Called when a connection completes headers or closes (cleanup).
    #[inline]
    pub fn on_conn_end(&self, ip_key_hash: u64) {
        if !self.enabled {
            return;
        }
        self.incomplete.dec(ip_key_hash);
    }

    /// Initialize per-connection state.
    #[inline]
    pub fn init_conn_state(&self, now_ns: u64) -> SlowlorisConnState {
        SlowlorisConnState {
            started_ns: now_ns,
            bytes_in_headers: 0,
        }
    }

    #[inline]
    pub fn on_header_bytes(
        &self,
        now_ns: u64,
        state: &mut SlowlorisConnState,
        added: u32,
    ) -> SlowlorisDecision {
        if !self.enabled {
            return SlowlorisDecision::Allow;
        }

        state.bytes_in_headers = state.bytes_in_headers.saturating_add(added as u64);

        let elapsed = now_ns.saturating_sub(state.started_ns);
        if elapsed > self.headers_timeout_ns {
            return SlowlorisDecision::DropTimeout;
        }

        // min recv rate check: bytes / seconds >= min_bps
        // Avoid float: bytes * 1e9 / elapsed_ns
        let elapsed_ns = elapsed.max(1);
        let rate = (state.bytes_in_headers as u128)
            .saturating_mul(1_000_000_000u128)
            .checked_div(elapsed_ns as u128)
            .unwrap_or(0) as u64;

        if rate < self.min_recv_rate_bps {
            SlowlorisDecision::DropMinRate
        } else {
            SlowlorisDecision::Allow
        }
    }

    #[inline]
    pub fn headers_timeout_ns(&self) -> u64 {
        self.headers_timeout_ns
    }
}

/// Utility: convert Duration to seconds (u32 clamp).
#[inline]
pub fn duration_to_u32_secs(d: Duration) -> u32 {
    d.as_secs().min(u64::from(u32::MAX)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> L7ProtectionConfig {
        L7ProtectionConfig::default()
    }

    #[test]
    fn slowloris_guard_enforces_incomplete_connection_cap() {
        let mut c = cfg();
        c.slowloris.enabled = true;
        c.slowloris.max_incomplete_conns_per_ip = 1;
        let g = SlowlorisGuard::new(&c);
        let ip = 42u64;

        assert_eq!(g.on_conn_start(ip), SlowlorisDecision::Allow);
        assert_eq!(
            g.on_conn_start(ip),
            SlowlorisDecision::DropTooManyIncomplete
        );
        // second attempt should rollback its own increment
        assert_eq!(g.incomplete.get(ip), 1);
        g.on_conn_end(ip);
        assert_eq!(g.incomplete.get(ip), 0);
    }

    #[test]
    fn slowloris_guard_checks_timeout_and_min_rate() {
        let mut c = cfg();
        c.slowloris.enabled = true;
        c.slowloris.headers_timeout_secs = 1;
        c.slowloris.min_recv_rate_bps = 100;
        let g = SlowlorisGuard::new(&c);

        let mut st = g.init_conn_state(0);
        assert_eq!(
            g.on_header_bytes(2_000_000_000, &mut st, 1),
            SlowlorisDecision::DropTimeout
        );

        let mut st2 = g.init_conn_state(0);
        assert_eq!(
            g.on_header_bytes(500_000_000, &mut st2, 1),
            SlowlorisDecision::DropMinRate
        );

        let mut st3 = g.init_conn_state(0);
        assert_eq!(
            g.on_header_bytes(500_000_000, &mut st3, 100),
            SlowlorisDecision::Allow
        );
    }

    #[test]
    fn duration_to_u32_secs_clamps_at_u32_max() {
        assert_eq!(duration_to_u32_secs(Duration::from_secs(7)), 7);
        assert_eq!(
            duration_to_u32_secs(Duration::from_secs(u64::MAX)),
            u32::MAX
        );
    }
}
