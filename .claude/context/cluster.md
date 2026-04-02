# Cluster Mode

## Overview

Cluster mode enables multiple proxy instances to coordinate via Redis. V1 implements **shared authz caching** — subsequent slices (V2-V5) add membership, health monitoring, leader election, and split-brain detection. See GitHub issue #31 for the full roadmap.

## TieredCache Architecture

Authorization decisions are cached in a two-tier structure:

- **L1:** In-memory LRU with TTL (`AuthzCache`, unchanged from standalone mode)
- **L2:** Optional Redis with SETEX TTL (shared across all instances)

Lookup order: L1 hit -> return. L1 miss -> L2 GET -> if hit, backfill L1, return. L1+L2 miss -> call VP -> insert both tiers.

On insert: L1 is synchronous, L2 is fire-and-forget via `tokio::spawn`. Redis writes never block request flow.

### Safe Degradation

Redis down -> all instances continue serving with L1-only (current standalone behavior). Startup logs warn but don't fail. This applies to both Redis-unreachable-at-startup and Redis-drops-mid-flight.

### FCIS Split

- **Pure (`authz-core`):** `PolicyDecision` and `DenyReason` have `Serialize`/`Deserialize` derives. `CacheStats` carries optional L2 counters. No Redis dependency.
- **I/O (`authz`):** `TieredCache` wraps `AuthzCache` + `Option<ConnectionManager>`. Redis I/O lives here.
- **Binary (`proxy`):** Creates `ConnectionManager`, builds `TieredCache`, injects into `VpPolicyEngine`.

## Configuration

```toml
[cluster]
redis_url = "redis://127.0.0.1:6379"    # required — parsed as url::Url
instance_id = "proxy-1"                  # default: random UUID
priority = 3                             # default: 1 (for leader election, V4)
heartbeat_interval_secs = 5              # default: 5 (for membership, V2)
min_quorum = 2                           # default: 1 (for split-brain, V5)
listen_cluster_addr = "10.0.1.1:8080"    # optional (for health monitoring, V3)
```

The `[cluster]` section is optional. Without it, the proxy behaves identically to pre-cluster builds.

Fields beyond `redis_url` are forward-declared for V2-V5. Only `redis_url` is consumed by V1.

### Config Types

- **Raw:** `RawClusterConfig` in `crates/http/src/config_raw.rs` — TOML deserialization
- **Validated:** `ClusterConfig` in `crates/http/src/config.rs` — `redis_url` parsed as `Url`, `listen_cluster_addr` as `SocketAddr`

## Redis Key Layout

| Key Pattern | Type | TTL | Purpose |
|---|---|---|---|
| `forgeguard:authz:cache:{cache_key}` | String (JSON) | `cache_ttl_secs` | Serialized `PolicyDecision` |

The `{cache_key}` is the same deterministic string used for L1 keys: `{user_id}|{action}|{resource}|{tenant}|{sorted_groups}`.

## Health Endpoint

`GET /.well-known/forgeguard/health` includes L2 stats when Redis is configured:

```json
{
  "status": "ok",
  "cache_hits": 150,
  "cache_misses": 42,
  "l2_cache_hits": 30,
  "l2_cache_misses": 12,
  "l2_cache_errors": 0
}
```

## Key Files

| File | What |
|---|---|
| `crates/authz/src/tiered_cache.rs` | `TieredCache` — L1+L2 cache implementation |
| `crates/authz/src/engine.rs` | `VpPolicyEngine` — accepts `TieredCache`, async cache lookup |
| `crates/authz/src/cache.rs` | `AuthzCache`, `CacheKey`, `build_cache_key` — L1 internals |
| `crates/authz-core/src/decision.rs` | `PolicyDecision`, `DenyReason` — serde derives |
| `crates/authz-core/src/engine.rs` | `CacheStats` — L2 counter fields |
| `crates/http/src/config_raw.rs` | `RawClusterConfig` |
| `crates/http/src/config.rs` | `ClusterConfig` |
| `crates/proxy/src/main.rs` | Redis `ConnectionManager` creation, `TieredCache` wiring |

## Future Slices (V2-V5)

V2 (membership), V3 (health monitoring), V4 (leader election), and V5 (split-brain detection) build on the Redis connection and `[cluster]` config established here. They will add `ClusterState`, a background cluster loop, and peer health checks. See issue #31 for details.
