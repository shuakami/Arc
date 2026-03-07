//

use std::time::Duration;

/// Convert `Duration` into nanoseconds (u64), saturating on overflow.
#[inline]
pub fn dur_to_ns_saturating(d: Duration) -> u64 {
    let n = d.as_nanos();
    if n > u64::MAX as u128 {
        u64::MAX
    } else {
        n as u64
    }
}

/// A compact runtime timeout policy in nanoseconds.
#[derive(Clone, Copy, Debug)]
pub struct TimeoutTierNs {
    pub connect_ns: u64,
    pub response_header_ns: u64,
    pub per_try_ns: u64,
    pub total_ns: u64,
}

impl TimeoutTierNs {
    /// Create from `Duration` values.
    #[inline]
    pub fn new(
        connect: Duration,
        response_header: Duration,
        per_try: Duration,
        total: Duration,
    ) -> Self {
        Self {
            connect_ns: dur_to_ns_saturating(connect).max(1),
            response_header_ns: dur_to_ns_saturating(response_header).max(1),
            per_try_ns: dur_to_ns_saturating(per_try).max(1),
            total_ns: dur_to_ns_saturating(total).max(1),
        }
    }
}

/// Per-request timeout state (monotonic nanos).
///
/// The worker should keep one instance per in-flight request (per keepalive request).
#[derive(Clone, Copy, Debug)]
pub struct RequestTimeoutState {
    req_started_ns: u64,
    total_deadline_ns: u64,

    try_started_ns: u64,
    try_deadline_ns: u64,
}

impl RequestTimeoutState {
    /// Start a new request. Caller must pass `effective_total_ns` already including deadline propagation min().
    #[inline]
    pub fn start(now_ns: u64, effective_total_ns: u64) -> Self {
        let total_deadline_ns = now_ns.saturating_add(effective_total_ns.max(1));
        Self {
            req_started_ns: now_ns,
            total_deadline_ns,
            try_started_ns: now_ns,
            try_deadline_ns: now_ns, // set by start_try()
        }
    }

    /// Start (or restart) a try/attempt.
    #[inline]
    pub fn start_try(&mut self, now_ns: u64, per_try_ns: u64) {
        self.try_started_ns = now_ns;
        self.try_deadline_ns = now_ns.saturating_add(per_try_ns.max(1));
    }

    /// Absolute total deadline (request-level safety valve).
    #[inline]
    pub fn total_deadline_ns(&self) -> u64 {
        self.total_deadline_ns
    }

    /// Deadline for current try.
    #[inline]
    pub fn try_deadline_ns(&self) -> u64 {
        self.try_deadline_ns
    }

    /// Remaining total budget in ns (0 if already expired).
    #[inline]
    pub fn remaining_total_ns(&self, now_ns: u64) -> u64 {
        self.total_deadline_ns.saturating_sub(now_ns)
    }

    /// Remaining try budget in ns (0 if already expired).
    #[inline]
    pub fn remaining_try_ns(&self, now_ns: u64) -> u64 {
        self.try_deadline_ns.saturating_sub(now_ns)
    }

    /// Compute deadline for upstream connect stage.
    ///
    /// Effective deadline = min(now + connect, try_deadline, total_deadline).
    #[inline]
    pub fn deadline_for_connect(&self, now_ns: u64, connect_ns: u64) -> u64 {
        let _ = now_ns;
        let stage = self.try_started_ns.saturating_add(connect_ns.max(1));
        stage.min(self.try_deadline_ns).min(self.total_deadline_ns)
    }

    #[inline]
    pub fn deadline_for_response_header(
        &self,
        now_ns: u64,
        response_header_ns: u64,
        resp_started: bool,
    ) -> u64 {
        if resp_started {
            return self.try_deadline_ns.min(self.total_deadline_ns);
        }
        let _ = now_ns;
        let stage = self
            .try_started_ns
            .saturating_add(response_header_ns.max(1));
        stage.min(self.try_deadline_ns).min(self.total_deadline_ns)
    }

    /// Compute deadline for a generic async IO operation with an upper-bound `op_timeout_ns`.
    ///
    /// Effective deadline = min(now + op_timeout, try_deadline, total_deadline).
    #[inline]
    pub fn deadline_for_io(&self, now_ns: u64, op_timeout_ns: u64) -> u64 {
        let stage = now_ns.saturating_add(op_timeout_ns.max(1));
        stage.min(self.try_deadline_ns).min(self.total_deadline_ns)
    }

    /// Returns true if total deadline has expired.
    #[inline]
    pub fn total_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.total_deadline_ns
    }

    /// Returns true if try deadline has expired.
    #[inline]
    pub fn try_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.try_deadline_ns
    }

    /// Request start timestamp (monotonic nanos).
    #[inline]
    pub fn req_started_ns(&self) -> u64 {
        self.req_started_ns
    }

    /// Current try start timestamp (monotonic nanos).
    #[inline]
    pub fn try_started_ns(&self) -> u64 {
        self.try_started_ns
    }
}
