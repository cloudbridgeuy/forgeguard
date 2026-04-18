//! LRU decision cache with TTL-based expiry and observable metrics.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use forgeguard_authz_core::PolicyDecision;
use forgeguard_authz_core::PolicyQuery;
use lru::LruCache;

// ---------------------------------------------------------------------------
// CacheKey
// ---------------------------------------------------------------------------

/// A deterministic cache key derived from a [`PolicyQuery`].
///
/// Wraps a `String` built from the query's principal, action, resource,
/// tenant, and group components. Two queries that produce the same key are
/// considered equivalent for caching purposes.
#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CacheKey(String);

impl CacheKey {
    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Build a deterministic cache key from a [`PolicyQuery`].
///
/// Format: `{principal_kind}|{principal_user_id}|{action}|{resource_or_none}|{tenant_or_none}|{sorted_groups}`
///
/// `principal_kind` is `"user"` or `"machine"`, preventing collisions between
/// a Machine and a User principal that happen to share the same user ID.
///
/// Groups are sorted alphabetically and comma-separated. Two queries
/// with the same user/action/resource but different groups produce
/// different keys, preventing stale cache hits.
///
/// Uses `Display` representations of the typed IDs so we don't need `Hash`
/// on every core type.
pub fn build_cache_key(query: &PolicyQuery) -> CacheKey {
    use forgeguard_core::PrincipalKind;

    let kind_part = match query.principal().kind() {
        PrincipalKind::User => "user",
        PrincipalKind::Machine => "machine",
    };
    let principal_id = query.principal().user_id().as_str();
    let action = query.action().to_string();

    let resource_part = query
        .resource()
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| "none".to_string());

    let tenant_part = query
        .context()
        .tenant_id()
        .map(|t| t.as_str().to_string())
        .unwrap_or_else(|| "none".to_string());

    let groups = query.context().groups();
    let groups_part = if groups.is_empty() {
        String::new()
    } else {
        let mut sorted: Vec<&str> = groups
            .iter()
            .map(forgeguard_core::GroupName::as_str)
            .collect();
        sorted.sort_unstable();
        sorted.join(",")
    };

    CacheKey(format!(
        "{kind_part}|{principal_id}|{action}|{resource_part}|{tenant_part}|{groups_part}"
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
    use forgeguard_core::{GroupName, PrincipalRef, QualifiedAction, UserId};

    use super::*;

    fn make_query(action_str: &str) -> PolicyQuery {
        make_query_for_user("test-user", action_str)
    }

    fn make_query_for_user(user: &str, action_str: &str) -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new(user).unwrap());
        let action = QualifiedAction::parse(action_str).unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    fn make_query_with_groups(user: &str, action_str: &str, groups: Vec<&str>) -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new(user).unwrap());
        let action = QualifiedAction::parse(action_str).unwrap();
        let group_names: Vec<GroupName> = groups
            .into_iter()
            .map(|g| GroupName::new(g).unwrap())
            .collect();
        let context = PolicyContext::new().with_groups(group_names);
        PolicyQuery::new(principal, action, None, context)
    }

    #[test]
    fn cache_miss_on_empty_cache() {
        let cache = AuthzCache::new(Duration::from_secs(60), 100);
        let query = make_query("todo:list:read");
        let key = build_cache_key(&query);

        assert!(cache.get(&key).is_none());
        assert_eq!(cache.cache_misses(), 1);
        assert_eq!(cache.cache_hits(), 0);
    }

    #[test]
    fn cache_hit_after_insert() {
        let cache = AuthzCache::new(Duration::from_secs(60), 100);
        let query = make_query("todo:list:read");
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
        let query = make_query("admin:user:delete");
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
        let query = make_query("todo:list:read");
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

        let q1 = make_query("todo:list:read");
        let k1 = build_cache_key(&q1);
        let q2 = make_query("todo:list:write");
        let k2 = build_cache_key(&q2);
        let q3 = make_query("todo:list:delete");
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
        let query = make_query("todo:list:read");
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
    fn same_user_same_action_produces_same_key() {
        let q1 = make_query_for_user("alice", "todo:list:read");
        let q2 = make_query_for_user("alice", "todo:list:read");
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_users_same_action_produces_different_keys() {
        let q1 = make_query_for_user("alice", "todo:list:read");
        let q2 = make_query_for_user("bob", "todo:list:read");
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn same_user_different_action_produces_different_keys() {
        let q1 = make_query_for_user("alice", "todo:list:read");
        let q2 = make_query_for_user("alice", "todo:list:write");
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_groups_produce_different_keys() {
        let q1 = make_query_with_groups("alice", "todo:list:read", vec!["admin"]);
        let q2 = make_query_with_groups("alice", "todo:list:read", vec!["viewer"]);
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn same_groups_different_order_produce_same_key() {
        let q1 = make_query_with_groups("alice", "todo:list:read", vec!["admin", "viewer"]);
        let q2 = make_query_with_groups("alice", "todo:list:read", vec!["viewer", "admin"]);
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn no_groups_vs_some_groups_produce_different_keys() {
        let q1 = make_query_for_user("alice", "todo:list:read");
        let q2 = make_query_with_groups("alice", "todo:list:read", vec!["admin"]);
        let k1 = build_cache_key(&q1);
        let k2 = build_cache_key(&q2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn same_user_id_different_principal_kind_produces_different_keys() {
        use forgeguard_core::PrincipalRef;

        let user_id = UserId::new("shared-id").unwrap();
        let user_principal = PrincipalRef::new(user_id.clone());
        let machine_principal = PrincipalRef::machine(user_id);
        let action = QualifiedAction::parse("todo:list:read").unwrap();

        let q_user = PolicyQuery::new(user_principal, action.clone(), None, PolicyContext::new());
        let q_machine = PolicyQuery::new(machine_principal, action, None, PolicyContext::new());

        let k_user = build_cache_key(&q_user);
        let k_machine = build_cache_key(&q_machine);

        assert_ne!(k_user, k_machine);
        assert!(k_user.as_str().starts_with("user|shared-id|"));
        assert!(k_machine.as_str().starts_with("machine|shared-id|"));
    }

    #[test]
    fn cache_key_groups_segment_is_sorted_csv() {
        let q = make_query_with_groups("alice", "todo:list:read", vec!["beta", "alpha"]);
        let key = build_cache_key(&q);
        assert!(key.as_str().ends_with("|alpha,beta"));
    }
}
