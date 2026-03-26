---
shaping: true
---

# forgeguard_authz — Shaping

**GitHub Issue:** [#11 — forgeguard_authz — Verified Permissions client with caching](https://github.com/cloudbridgeuy/forgeguard/issues/11)
**Labels:** io, layer-2, authz
**Blocked by:** #7 (done), #9 (done)
**Unblocks:** #13 (`forgeguard_proxy`)
**Integration tests require:** #15 (Verified Permissions Policy Store — not yet done)

---

## Frame

### Source

> Implement `PolicyEngine` for AWS Verified Permissions. Takes a `PolicyQuery` (from `authz_core`), calls Verified Permissions `IsAuthorized`, caches the result, and returns a `PolicyDecision`.

### Problem

The proxy needs to evaluate authorization decisions. The pure `PolicyEngine` trait exists in `authz_core`, but there's no concrete implementation that calls AWS Verified Permissions. This crate is the I/O shell that translates `PolicyQuery` into VP API calls and caches decisions.

### Outcome

A `forgeguard_authz` crate that implements `PolicyEngine` for AWS Verified Permissions with LRU + TTL decision caching. Dependencies: `aws-sdk-verifiedpermissions`, `tokio`, `forgeguard_core`, `forgeguard_authz_core`.

---

## Requirements (R)

| ID  | Requirement                                                                                    | Status    |
| --- | ---------------------------------------------------------------------------------------------- | --------- |
| R0  | Evaluate `PolicyQuery` → `PolicyDecision` via AWS Verified Permissions                         | Core goal |
| R1  | Implement `PolicyEngine` trait from `authz_core`                                               | Must-have |
| R2  | Translate core types (FGRN, QualifiedAction) to VP entity IDs and action types                 | Must-have |
| R3  | LRU decision cache with configurable TTL and max entries                                       | Must-have |
| R4  | Cache key: `(user, action, resource, tenant)` tuple                                            | Must-have |
| R5  | Observable cache metrics (hit/miss counters)                                                   | Must-have |
| R6  | VP errors produce `PolicyDecision::Deny { reason: EvaluationError }`, not panics               | Must-have |
| R7  | No `http` crate dependency                                                                     | Must-have |
| R8  | Crate-level `Error` and `Result<T>` types                                                      | Must-have |

---

## Shape A: Issue-as-spec

| Part   | Mechanism                                                                                                                                                                       | Flag |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--: |
| **A1** | **VpPolicyEngine** — holds `aws_sdk_verifiedpermissions::Client`, `policy_store_id: String`, `project_id: ProjectId`, `cache: AuthzCache`. Implements `PolicyEngine`. The `evaluate()` orchestration: check cache → call VP → on VP SDK error (network, throttle, malformed), return `PolicyDecision::Deny { reason: EvaluationError(msg) }` — never propagate VP failures as `Err`, always convert to a deny decision. On VP success, delegate to A3. Store result in cache. | |
| **A2** | **Query translation** — Pure function: `fn build_vp_request(query: &PolicyQuery, policy_store_id: &str) -> IsAuthorizedInput`. Maps: principal → entity type `"iam::user"` + entity ID from `PrincipalRef::to_fgrn()`. Action → `QualifiedAction::vp_action_type()` + `vp_action_id()`. Resource → `cedar_entity_type()` + `to_fgrn()`. | |
| **A3** | **Response translation** — Pure function: `fn translate_vp_response(response: &IsAuthorizedOutput) -> PolicyDecision`. VP ALLOW → `PolicyDecision::Allow`. VP DENY → `PolicyDecision::Deny { reason: NoMatchingPolicy }`. | |
| **A4** | **AuthzCache** — `Mutex<LruCache<CacheKey, CachedDecision>>`. `CacheKey`: hash of `(user_fgrn, action, resource_fgrn, tenant_id)`. `CachedDecision`: `(PolicyDecision, Instant)`. Configurable TTL (default 60s) and max entries (default 10_000). | |
| **A5** | **Cache metrics** — `AtomicU64` counters for hits and misses. Exposed via `cache_hits()` and `cache_misses()` methods. No external metrics dependency — the proxy or metrics layer reads these. | |
| **A6** | **VpEngineConfig** — `policy_store_id: String`, `cache_ttl: Duration`, `cache_max_entries: usize`. Private fields, constructor with defaults. | |
| **A7** | **Error enum** — `Core(forgeguard_authz_core::Error)`, `VerifiedPermissions(String)`, `PolicyStoreNotFound(String)`. | |

### FCIS Split

- **Pure (unit-testable):** A2 — query translation, A3 — response translation, A4 — cache logic (lookup, insert, eviction, TTL expiry). These are the interesting parts to test.
- **I/O (integration-testable):** A1 — the `evaluate()` orchestration that checks cache → calls VP → stores result. The VP client is the only I/O.

### Resolved Decisions

**A2 — FGRN as VP entity ID:** Already built into `forgeguard_core`. `Fgrn::as_vp_entity_id()` returns the display string. `QualifiedAction` provides `vp_action_type()` and `vp_action_id()`. The translation functions are thin wrappers around these existing methods.

**A4 — Mutex vs RwLock for cache:** `Mutex` is correct. LRU caches mutate on read (updating access order), so `RwLock` provides no benefit — every `get` is also a write. `Mutex` is simpler and avoids the false sense of safety that `RwLock` would give.

**A4 — LRU crate:** Use the `lru` crate (well-maintained, minimal). Needs to be added to workspace `Cargo.toml`.

**A4 — CacheKey hashing:** Hash the tuple `(user_fgrn_string, action_string, resource_fgrn_string, tenant_id_string)`. Using string representations avoids needing `Hash` on all core types. The strings are already computed by `Display` impls.

**A1 — Constructor:** `VpPolicyEngine::new(client, config, project_id)` where `client` is injected (testable). No internal client construction — the caller provides the AWS SDK client so we don't own AWS config loading.

---

## Rabbit Holes

| Risk | Mitigation |
| ---- | ---------- |
| VP SDK API shape unknown at design time | Spike: verify `IsAuthorized` request/response types before implementation. The SDK is code-generated — check exact field names and required params. |
| Batch authorization (`BatchIsAuthorized`) | Out of scope. Single-request `IsAuthorized` only. Batch is a future optimization. |
| Context/entity attributes in VP requests | Out of scope for MVP. `PolicyQuery` carries `PolicyContext` with attributes, but we don't forward them to VP yet. Add when needed. |
| Cache invalidation on policy changes | Not handled. TTL-based expiry only. External cache flush (e.g., via admin API) is a future feature. |
| `aws-sdk-verifiedpermissions` compile time | Known issue with AWS SDKs. Accept it. Feature-gate the VP dependency if compile time becomes unbearable. |

---

## Fit Check: R × A

| Req | Requirement                                                     | Status    |  A  |
| --- | --------------------------------------------------------------- | --------- | :-: |
| R0  | Evaluate PolicyQuery → PolicyDecision via VP                    | Core goal | A1,A2,A3 |
| R1  | Implement `PolicyEngine` trait                                  | Must-have | A1 |
| R2  | Translate core types to VP entity IDs                           | Must-have | A2 |
| R3  | LRU cache with TTL and max entries                              | Must-have | A4 |
| R4  | Cache key: (user, action, resource, tenant)                     | Must-have | A4 |
| R5  | Observable cache metrics                                        | Must-have | A5 |
| R6  | VP errors → Deny with EvaluationError                           | Must-have | A1,A3 |
| R7  | No `http` crate dependency                                      | Must-have | ✅ |
| R8  | Crate-level Error/Result                                        | Must-have | A7 |

All requirements covered. No gaps.

---

## File Sketch

```
crates/authz/src/
├── lib.rs              — pub exports, #![deny(...)]
├── error.rs            — Error enum, Result alias
├── config.rs           — VpEngineConfig (A6)
├── cache.rs            — AuthzCache, CacheKey, CachedDecision, metrics (A4, A5)
├── translate.rs        — build_vp_request, translate_vp_response (A2, A3)
└── engine.rs           — VpPolicyEngine + PolicyEngine impl (A1)
```

Estimated ~350 lines total. Well under the 1000-line limit.
