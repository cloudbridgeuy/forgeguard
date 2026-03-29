# forgeguard_authz

**Classification:** I/O crate

Authorization I/O shell implementing `PolicyEngine` (from `forgeguard_authz_core`) via AWS Verified Permissions.

## What it owns

- `VpPolicyEngine` — concrete `PolicyEngine` that calls the VP `IsAuthorized` API
- `AuthzCache` — LRU decision cache with TTL expiry and hit/miss counters
- `VpEngineConfig` — configuration (policy store ID, cache TTL, max entries)
- `build_vp_entities()` — builds user-in-group entity hierarchy passed inline to `IsAuthorized`
- Query/response translation between core types and VP SDK types

## Dependencies

- `forgeguard_core` — typed IDs (FGRN, ProjectId, TenantId, etc.)
- `forgeguard_authz_core` — `PolicyEngine` trait, `PolicyQuery`, `PolicyDecision`
- `aws-sdk-verifiedpermissions` — VP SDK client
- `lru` — LRU cache implementation

## Architecture

```
PolicyQuery ──► build_vp_request() ──► VP IsAuthorized API
                      │                        │
                      ▼                        │
              build_vp_entities()               │
              (user → group hierarchy)          │
                                               ▼
PolicyDecision ◄── translate_vp_decision() ◄── VP Decision
       │
       ▼
  AuthzCache (LRU + TTL)
```

The engine checks the cache first. On miss, it calls VP, translates the response,
caches the result, and returns. VP SDK errors are converted to
`PolicyDecision::Deny { reason: EvaluationError }` — never propagated as `Err`.

## Design notes

- **Inline entities only.** `build_vp_entities()` constructs the user-in-group
  hierarchy and passes it directly to `IsAuthorized`. No entity store is used.
- **`IsAuthorized` only.** The engine calls `IsAuthorized`, not
  `IsAuthorizedWithToken`. Token validation is handled upstream by the authn layer.
- **Group-aware cache keys.** The cache key includes sorted group names so that
  the same principal with different group memberships produces distinct cache entries.
