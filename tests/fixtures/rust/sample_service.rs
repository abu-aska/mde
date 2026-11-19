//! Service fixture exercising Rust CST round-trips, pragmas, and zones.

use std::collections::BTreeMap;

/// Plain-language doc comment explaining rate bucket state.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Bucket {
    pub capacity: u64,
    pub tokens: u64,
}

impl Bucket {
    /// Create a full bucket.
    pub fn new(capacity: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
        }
    }

    // Sibling comment above consume MUST stay byte-identical.
    #[inline]
    pub fn consume(&mut self, cost: u64) -> bool {
        if self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

/// @formal-proof data-eido-skip
pub fn monotonic_bound(tokens: u64, capacity: u64) -> bool {
    tokens <= capacity
}

pub fn merge_counts(a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    let mut out = a.clone();
    for (k, v) in b {
        *out.entry(k.clone()).or_insert(0) += v;
    }
    out
}

pub fn raw_ptr_peek(slice: &[u8]) -> Option<u8> {
    if slice.is_empty() {
        return None;
    }
    let ptr = slice.as_ptr();
    // Explicit unsafe block for G2.2 dynamic-site tracking.
    Some(unsafe { *ptr })
}
