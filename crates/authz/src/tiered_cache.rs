//! Two-tier authorization cache: L1 (in-memory LRU) + L2 (optional Redis).
//!
//! L2 failures are transparent — the cache degrades to L1-only without
//! affecting request flow. Redis writes are fire-and-forget.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use forgeguard_authz_core::PolicyDecision;

use crate::cache::{AuthzCache, CacheKey};

/// A two-tier authorization decision cache.
///
/// - **L1:** In-memory LRU with TTL (`AuthzCache`).
/// - **L2:** Optional Redis with SETEX TTL (shared across instances).
///
/// Lookup order: L1 hit → return. L1 miss → L2 GET → if hit, backfill L1, return.
/// On insert: write L1 + fire-and-forget SETEX to L2.
pub struct TieredCache {
    l1: AuthzCache,
    l2: Option<redis::aio::ConnectionManager>,
    ttl: Duration,
    l2_hits: AtomicU64,
    l2_misses: AtomicU64,
    l2_errors: AtomicU64,
}

impl TieredCache {
    /// Create a tiered cache.
    ///
    /// If `l2` is `None`, this behaves identically to a plain `AuthzCache`.
    pub fn new(l1: AuthzCache, l2: Option<redis::aio::ConnectionManager>, ttl: Duration) -> Self {
        Self {
            l1,
            l2,
            ttl,
            l2_hits: AtomicU64::new(0),
            l2_misses: AtomicU64::new(0),
            l2_errors: AtomicU64::new(0),
        }
    }

    /// Look up a cached decision. L1 first, then L2.
    pub async fn get(&self, key: &CacheKey) -> Option<PolicyDecision> {
        // L1 check (sync, fast)
        if let Some(decision) = self.l1.get(key) {
            return Some(decision);
        }

        // L2 check (async, may fail)
        let Some(conn) = &self.l2 else {
            return None;
        };

        let redis_key = self.redis_key(key);
        let mut conn = conn.clone();

        match redis::cmd("GET")
            .arg(&redis_key)
            .query_async::<Option<String>>(&mut conn)
            .await
        {
            Ok(Some(json)) => match serde_json::from_str::<PolicyDecision>(&json) {
                Ok(decision) => {
                    self.l2_hits.fetch_add(1, Ordering::Relaxed);
                    // Backfill L1
                    self.l1.insert(key.clone(), decision.clone());
                    Some(decision)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "L2 cache: failed to deserialize decision");
                    self.l2_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
            },
            Ok(None) => {
                self.l2_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "L2 cache: Redis GET failed — degrading to L1");
                self.l2_errors.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a decision into both tiers.
    ///
    /// L1 insert is synchronous. L2 insert is fire-and-forget (errors logged, not propagated).
    pub fn insert(&self, key: &CacheKey, decision: &PolicyDecision) {
        self.l1.insert(key.clone(), decision.clone());

        let Some(conn) = &self.l2 else {
            return;
        };

        let redis_key = self.redis_key(key);
        let ttl_secs = self.ttl.as_secs().max(1) as i64;
        let mut conn = conn.clone();

        // Serialize outside the spawn to catch errors early.
        let json = match serde_json::to_string(decision) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "L2 cache: failed to serialize decision");
                return;
            }
        };

        tokio::spawn(async move {
            let result: std::result::Result<(), redis::RedisError> = redis::cmd("SETEX")
                .arg(&redis_key)
                .arg(ttl_secs)
                .arg(&json)
                .query_async(&mut conn)
                .await;

            if let Err(e) = result {
                tracing::debug!(error = %e, "L2 cache: Redis SETEX failed");
            }
        });
    }

    /// L1 cache hits.
    pub fn l1_hits(&self) -> u64 {
        self.l1.cache_hits()
    }

    /// L1 cache misses (before L2 lookup).
    pub fn l1_misses(&self) -> u64 {
        self.l1.cache_misses()
    }

    /// L2 cache hits.
    pub fn l2_hits(&self) -> u64 {
        self.l2_hits.load(Ordering::Relaxed)
    }

    /// L2 cache misses.
    pub fn l2_misses(&self) -> u64 {
        self.l2_misses.load(Ordering::Relaxed)
    }

    /// L2 errors (connection failures, deserialization errors).
    pub fn l2_errors(&self) -> u64 {
        self.l2_errors.load(Ordering::Relaxed)
    }

    /// Whether L2 (Redis) is configured.
    pub fn has_l2(&self) -> bool {
        self.l2.is_some()
    }

    /// Build the Redis key for a cache entry.
    fn redis_key(&self, key: &CacheKey) -> String {
        format!("forgeguard:authz:cache:{}", key.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use forgeguard_authz_core::{DenyReason, PolicyContext, PolicyDecision, PolicyQuery};
    use forgeguard_core::{PrincipalRef, QualifiedAction, UserId};

    use super::*;
    use crate::cache::build_cache_key;

    fn make_query(action_str: &str) -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("test-user").unwrap());
        let action = QualifiedAction::parse(action_str).unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    fn make_l1_only_cache() -> TieredCache {
        let l1 = AuthzCache::new(Duration::from_secs(60), 100);
        TieredCache::new(l1, None, Duration::from_secs(60))
    }

    #[tokio::test]
    async fn l1_only_miss() {
        let cache = make_l1_only_cache();
        let key = build_cache_key(&make_query("todo:list:read"));
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn l1_only_hit_after_insert() {
        let cache = make_l1_only_cache();
        let key = build_cache_key(&make_query("todo:list:read"));
        cache.insert(&key, &PolicyDecision::Allow);
        let result = cache.get(&key).await;
        assert!(result.is_some());
        assert!(result.unwrap().is_allowed());
    }

    #[tokio::test]
    async fn l1_only_deny_round_trip() {
        let cache = make_l1_only_cache();
        let key = build_cache_key(&make_query("admin:user:delete"));
        let deny = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        cache.insert(&key, &deny);
        let result = cache.get(&key).await.unwrap();
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn has_l2_false_when_no_redis() {
        let cache = make_l1_only_cache();
        assert!(!cache.has_l2());
    }

    #[tokio::test]
    async fn l2_counters_zero_without_redis() {
        let cache = make_l1_only_cache();
        assert_eq!(cache.l2_hits(), 0);
        assert_eq!(cache.l2_misses(), 0);
        assert_eq!(cache.l2_errors(), 0);
    }
}
