# forgeguard_authz

**Classification:** I/O crate

Authorization I/O shell implementing `PolicyEngine` (from `forgeguard_authz_core`) via AWS Verified Permissions.

## What it owns

- `VpPolicyEngine` — concrete `PolicyEngine` that calls the VP `IsAuthorized` API
- `AuthzCache` — LRU decision cache with TTL expiry and hit/miss counters
- `VpEngineConfig` — configuration (policy store ID, cache TTL, max entries)
- Query/response translation between core types and VP SDK types

## Dependencies

- `forgeguard_core` — typed IDs (FGRN, ProjectId, TenantId, etc.)
- `forgeguard_authz_core` — `PolicyEngine` trait, `PolicyQuery`, `PolicyDecision`
- `aws-sdk-verifiedpermissions` — VP SDK client
- `lru` — LRU cache implementation

## Architecture

```
PolicyQuery ──► build_vp_request() ──► VP IsAuthorized API
                                              │
                                              ▼
PolicyDecision ◄── translate_vp_decision() ◄── VP Decision
       │
       ▼
  AuthzCache (LRU + TTL)
```

The engine checks the cache first. On miss, it calls VP, translates the response,
caches the result, and returns. VP SDK errors are converted to
`PolicyDecision::Deny { reason: EvaluationError }` — never propagated as `Err`.
