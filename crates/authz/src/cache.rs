//! LRU decision cache with TTL-based expiry and observable metrics.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use forgeguard_authz_core::PolicyDecision;
use forgeguard_authz_core::PolicyQuery;
use forgeguard_core::PrincipalRef;
use lru::LruCache;

// ---------------------------------------------------------------------------
// CacheKey
// ---------------------------------------------------------------------------

/// A deterministic cache key derived from a [`PolicyQuery`].
///
/// Wraps a `String` built from the query's principal, action, resource, and
/// tenant components. Two queries that produce the same key are considered
/// equivalent for caching purposes.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CacheKey(String);

impl CacheKey {
    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Build a deterministic cache key from a [`PolicyQuery`].
///
/// Format: `{principal_entity_type}|{action}|{resource_or_none}|{tenant_or_none}`
///
/// Uses `Display` representations of the typed IDs so we don't need `Hash`
/// on every core type.
pub(crate) fn build_cache_key(query: &PolicyQuery) -> CacheKey {
    let principal_type = PrincipalRef::vp_entity_type();
    let action = query.action().to_string();

    let resource_part = query
        .resource()
        .map(forgeguard_core::ResourceRef::vp_entity_type)
        .unwrap_or_else(|| "none".to_string());

    let tenant_part = query
        .context()
        .tenant_id()
        .map(|t| t.as_str().to_string())
        .unwrap_or_else(|| "none".to_string());

    CacheKey(format!(
        "{principal_type}|{action}|{resource_part}|{tenant_part}"
    ))
}

// ---------------------------------------------------------------------------
// CachedDecision
// ---------------------------------------------------------------------------

/// A cached policy decision with its insertion timestamp.
struct CachedDecision {
    decision: PolicyDecision,
    inserted_at: Instant,
}

// ---------------------------------------------------------------------------
// AuthzCache
// ---------------------------------------------------------------------------

/// An LRU authorization decision cache with TTL-based expiry.
///
/// Thread-safe via `Mutex` (LRU mutates on read, so `RwLock` offers no benefit).
/// Observable via atomic hit/miss counters.
pub struct AuthzCache {
    inner: Mutex<LruCache<CacheKey, CachedDecision>>,
    ttl: Duration,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl AuthzCache {
    /// Create a new cache with the given TTL and maximum number of entries.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        // NonZeroUsize requires at least 1; clamp to 1 if 0 is passed.
        let cap = NonZeroUsize::new(max_entries.max(1))
            .unwrap_or_else(|| NonZeroUsize::new(1).unwrap_or(NonZeroUsize::MIN));
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached decision. Returns `None` if absent or expired.
    pub fn get(&self, key: &CacheKey) -> Option<PolicyDecision> {
        let mut guard = self.inner.lock().ok()?;
        match guard.get(key) {
            Some(cached) if cached.inserted_at.elapsed() < self.ttl => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(cached.decision.clone())
            }
            Some(_) => {
                // Expired — remove it.
                guard.pop(key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a decision into the cache.
    pub fn insert(&self, key: CacheKey, decision: PolicyDecision) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.put(
                key,
                CachedDecision {
                    decision,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    /// Total cache hits since creation.
    pub fn cache_hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Total cache misses since creation.
    pub fn cache_misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::thread;

    use forgeguard_authz_core::{DenyReason, PolicyContext};
    use forgeguard_core::{QualifiedAction, UserId};

    use super::*;

    fn make_query(action_str: &str) -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("test-user").unwrap());
        let action = QualifiedAction::parse(action_str).unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    #[test]
    fn cache_miss_on_empty_cache() {
        let cache = AuthzCache::new(Duration::from_secs(60), 100);
        let query = make_query("todo:read:list");
        let key = build_cache_key(&query);

        assert!(cache.get(&key).is_none());
        assert_eq!(cache.cache_misses(), 1);
        assert_eq!(cache.cache_hits(), 0);
    }

    #[test]
    fn cache_hit_after_insert() {
        let cache = AuthzCache::new(Duration::from_secs(60), 100);
        let query = make_query("todo:read:list");
        let key = build_cache_key(&query);

        cache.insert(key.clone(), PolicyDecision::Allow);
        let result = cache.get(&key);

        assert!(result.is_some());
        assert!(result.unwrap().is_allowed());
        assert_eq!(cache.cache_hits(), 1);
        assert_eq!(cache.cache_misses(), 0);
    }

    #[test]
    fn cache_returns_deny_decision() {
        let cache = AuthzCache::new(Duration::from_secs(60), 100);
        let query = make_query("admin:delete:user");
        let key = build_cache_key(&query);

        let deny = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        cache.insert(key.clone(), deny);
        let result = cache.get(&key).unwrap();

        assert!(result.is_denied());
    }

    #[test]
    fn ttl_expiry() {
        let cache = AuthzCache::new(Duration::from_millis(50), 100);
        let query = make_query("todo:read:list");
        let key = build_cache_key(&query);

        cache.insert(key.clone(), PolicyDecision::Allow);
        assert!(cache.get(&key).is_some());
        assert_eq!(cache.cache_hits(), 1);

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(100));

        assert!(cache.get(&key).is_none());
        assert_eq!(cache.cache_misses(), 1);
        assert_eq!(cache.cache_hits(), 1);
    }

    #[test]
    fn lru_eviction() {
        let cache = AuthzCache::new(Duration::from_secs(60), 2);

        let q1 = make_query("todo:read:list");
        let k1 = build_cache_key(&q1);
        let q2 = make_query("todo:write:list");
        let k2 = build_cache_key(&q2);
        let q3 = make_query("todo:delete:list");
        let k3 = build_cache_key(&q3);

        cache.insert(k1.clone(), PolicyDecision::Allow);
        cache.insert(k2.clone(), PolicyDecision::Allow);
        // k1 is LRU — inserting k3 should evict k1
        cache.insert(k3.clone(), PolicyDecision::Allow);

        assert!(cache.get(&k1).is_none()); // evicted
        assert!(cache.get(&k2).is_some()); // still present
        assert!(cache.get(&k3).is_some()); // still present
    }

    #[test]
    fn counter_accuracy() {
        let cache = AuthzCache::new(Duration::from_secs(60), 100);
        let query = make_query("todo:read:list");
        let key = build_cache_key(&query);

        // 3 misses
        cache.get(&key);
        cache.get(&key);
        cache.get(&key);

        cache.insert(key.clone(), PolicyDecision::Allow);

        // 2 hits
        cache.get(&key);
        cache.get(&key);

        assert_eq!(cache.cache_misses(), 3);
        assert_eq!(cache.cache_hits(), 2);
    }

    #[test]
    fn deterministic_cache_key() {
        let q1 = make_query("todo:read:list");
        let q2 = make_query("todo:read:list");
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_actions_produce_different_keys() {
        let q1 = make_query("todo:read:list");
        let q2 = make_query("todo:write:list");
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_ne!(k1, k2);
    }
}
