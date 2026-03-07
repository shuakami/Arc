use ahash::AHasher;
use once_cell::sync::OnceCell;
use std::{
    cell::RefCell,
    collections::HashMap,
    hash::{Hash, Hasher},
    time::Instant,
};

#[derive(Debug, Clone)]
pub struct RateLimiter {
    qps: u64,
    burst: u64,
}

impl RateLimiter {
    pub fn new(qps: u64, burst: u64) -> Self {
        Self { qps, burst }
    }

    /// Check if an event is allowed for a given key.
    ///
    /// Returns `Ok(())` if allowed, otherwise returns `Err(retry_after_ms)`.
    pub fn check<K: Hash>(&self, key: &K) -> Result<(), u64> {
        let now_us = now_us();
        let id = hash64(key);

        BUCKETS.with(|m| {
            let mut m = m.borrow_mut();
            let b = m.entry(id).or_insert_with(|| Bucket {
                tokens: self.burst,
                last_us: now_us,
            });
            b.refill(now_us, self.qps, self.burst);
            if b.tokens > 0 {
                b.tokens -= 1;
                Ok(())
            } else {
                // retry-after: time until next token
                let ms = if self.qps == 0 {
                    1_000
                } else {
                    // 1 token every 1e6/qps us
                    let us_per_token = 1_000_000u64 / self.qps.max(1);
                    (us_per_token / 1_000).max(1)
                };
                Err(ms)
            }
        })
    }
}

thread_local! {
    static BUCKETS: RefCell<HashMap<u64, Bucket>> = RefCell::new(HashMap::new());
}

#[derive(Debug)]
struct Bucket {
    tokens: u64,
    last_us: u64,
}

impl Bucket {
    #[inline]
    fn refill(&mut self, now_us: u64, qps: u64, burst: u64) {
        if qps == 0 {
            self.tokens = burst;
            self.last_us = now_us;
            return;
        }
        let dt = now_us.saturating_sub(self.last_us);
        if dt == 0 {
            return;
        }
        // tokens += dt * qps / 1e6
        let add = (dt.saturating_mul(qps)) / 1_000_000u64;
        if add > 0 {
            self.tokens = (self.tokens + add).min(burst);
            self.last_us = now_us;
        }
    }
}

fn start() -> Instant {
    static START: OnceCell<Instant> = OnceCell::new();
    *START.get_or_init(Instant::now)
}

#[inline]
fn now_us() -> u64 {
    start().elapsed().as_micros() as u64
}

#[inline]
fn hash64<K: Hash>(k: &K) -> u64 {
    let mut h = AHasher::default();
    k.hash(&mut h);
    h.finish()
}
