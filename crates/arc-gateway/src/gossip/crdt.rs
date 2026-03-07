use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct GCounter {
    per_node: HashMap<Arc<str>, u64>,
}

impl GCounter {
    /// Create an empty counter.
    pub fn new() -> Self {
        Self {
            per_node: HashMap::new(),
        }
    }

    /// Increment the component for `node_id` by `delta` (saturating).
    pub fn inc(&mut self, node_id: Arc<str>, delta: u64) {
        let e = self.per_node.entry(node_id).or_insert(0);
        *e = e.saturating_add(delta);
    }

    /// Set the component for `node_id` to `value` if it is greater than current.
    ///
    /// Returns `true` if the local state changed.
    pub fn merge_component_max(&mut self, node_id: Arc<str>, value: u64) -> bool {
        let e = self.per_node.entry(node_id).or_insert(0);
        if value > *e {
            *e = value;
            true
        } else {
            false
        }
    }

    /// Merge another counter into this one.
    ///
    /// Returns `true` if the local state changed.
    pub fn merge(&mut self, other: &GCounter) -> bool {
        let mut changed = false;
        for (k, v) in other.per_node.iter() {
            let e = self.per_node.entry(k.clone()).or_insert(0);
            if *v > *e {
                *e = *v;
                changed = true;
            }
        }
        changed
    }

    /// Total value (sum of all node components, saturating).
    pub fn value(&self) -> u64 {
        let mut sum = 0u64;
        for v in self.per_node.values() {
            sum = sum.saturating_add(*v);
        }
        sum
    }

    /// Snapshot the internal per-node components (for TCP full sync).
    pub fn snapshot(&self) -> HashMap<Arc<str>, u64> {
        self.per_node.clone()
    }
}

#[derive(Debug, Clone)]
pub struct LwwRegister<T> {
    pub ts: u64,
    pub node_id: Arc<str>,
    pub value: T,
}

impl<T> LwwRegister<T> {
    /// Create a new register.
    pub fn new(ts: u64, node_id: Arc<str>, value: T) -> Self {
        Self { ts, node_id, value }
    }

    /// Compare two LWW timestamps with deterministic tie-break.
    #[inline]
    pub fn wins(&self, other_ts: u64, other_node: &str) -> bool {
        if other_ts > self.ts {
            return true;
        }
        if other_ts < self.ts {
            return false;
        }
        other_node > self.node_id.as_ref()
    }
}

impl<T: Clone> LwwRegister<T> {
    /// Merge another LWW register into this one.
    ///
    /// Returns `true` if local state changed.
    pub fn merge(&mut self, other: &LwwRegister<T>) -> bool {
        if self.wins(other.ts, other.node_id.as_ref()) {
            self.ts = other.ts;
            self.node_id = other.node_id.clone();
            self.value = other.value.clone();
            return true;
        }
        false
    }
}
