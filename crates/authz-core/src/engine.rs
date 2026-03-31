//! Pluggable policy engine trait.

use std::future::Future;
use std::pin::Pin;

use crate::decision::PolicyDecision;
use crate::error::Result;
use crate::query::PolicyQuery;

/// Cache performance counters exposed by policy engines that cache decisions.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    hits: u64,
    misses: u64,
}

impl CacheStats {
    /// Create a new `CacheStats` snapshot.
    pub fn new(hits: u64, misses: u64) -> Self {
        Self { hits, misses }
    }

    /// Total cache hits since creation.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Total cache misses since creation.
    pub fn misses(&self) -> u64 {
        self.misses
    }
}

/// Trait for evaluating authorization queries against a policy store.
///
/// Async because I/O implementations (e.g., AWS Verified Permissions)
/// need it. Pure implementations use `Box::pin(std::future::ready(...))`.
///
/// Defined in this pure crate, implemented in I/O crates.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a policy query and return a decision.
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>;

    /// Return cache performance counters, if the engine supports caching.
    ///
    /// Defaults to `None` for engines without caching.
    fn cache_stats(&self) -> Option<CacheStats> {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cache_stats_new_stores_values() {
        let stats = CacheStats::new(42, 7);
        assert_eq!(stats.hits(), 42);
        assert_eq!(stats.misses(), 7);
    }

    #[test]
    fn cache_stats_zero_values() {
        let stats = CacheStats::new(0, 0);
        assert_eq!(stats.hits(), 0);
        assert_eq!(stats.misses(), 0);
    }

    #[test]
    fn cache_stats_large_values() {
        let stats = CacheStats::new(u64::MAX, u64::MAX);
        assert_eq!(stats.hits(), u64::MAX);
        assert_eq!(stats.misses(), u64::MAX);
    }

    #[test]
    fn cache_stats_clone() {
        let stats = CacheStats::new(10, 20);
        let cloned = stats;
        assert_eq!(cloned.hits(), 10);
        assert_eq!(cloned.misses(), 20);
    }
}
