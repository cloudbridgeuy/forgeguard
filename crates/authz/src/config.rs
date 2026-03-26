//! Configuration for the Verified Permissions policy engine.

use std::time::Duration;

/// Default cache TTL: 60 seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// Default maximum cache entries.
const DEFAULT_CACHE_MAX_ENTRIES: usize = 10_000;

/// Configuration for the [`crate::VpPolicyEngine`].
///
/// Private fields, constructor with sensible defaults, builder methods.
pub struct VpEngineConfig {
    policy_store_id: String,
    cache_ttl: Duration,
    cache_max_entries: usize,
}

impl VpEngineConfig {
    /// Create a new configuration with the given policy store ID and default
    /// cache settings (60s TTL, 10,000 max entries).
    pub fn new(policy_store_id: impl Into<String>) -> Self {
        Self {
            policy_store_id: policy_store_id.into(),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
        }
    }

    /// Override the cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Override the maximum number of cache entries.
    pub fn with_cache_max_entries(mut self, max: usize) -> Self {
        self.cache_max_entries = max;
        self
    }

    /// Borrow the policy store ID.
    pub fn policy_store_id(&self) -> &str {
        &self.policy_store_id
    }

    /// Get the cache TTL.
    pub fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// Get the maximum number of cache entries.
    pub fn cache_max_entries(&self) -> usize {
        self.cache_max_entries
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = VpEngineConfig::new("ps-12345");
        assert_eq!(config.policy_store_id(), "ps-12345");
        assert_eq!(config.cache_ttl(), Duration::from_secs(60));
        assert_eq!(config.cache_max_entries(), 10_000);
    }

    #[test]
    fn builder_overrides_ttl() {
        let config = VpEngineConfig::new("ps-12345").with_cache_ttl(Duration::from_secs(120));
        assert_eq!(config.cache_ttl(), Duration::from_secs(120));
    }

    #[test]
    fn builder_overrides_max_entries() {
        let config = VpEngineConfig::new("ps-12345").with_cache_max_entries(500);
        assert_eq!(config.cache_max_entries(), 500);
    }

    #[test]
    fn builder_chains() {
        let config = VpEngineConfig::new("ps-99999")
            .with_cache_ttl(Duration::from_secs(30))
            .with_cache_max_entries(1_000);
        assert_eq!(config.policy_store_id(), "ps-99999");
        assert_eq!(config.cache_ttl(), Duration::from_secs(30));
        assert_eq!(config.cache_max_entries(), 1_000);
    }
}
