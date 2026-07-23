# Feature Flag System

Feature flags live across three crates, following the Functional Core / Imperative Shell split.

## Architecture

```
forgeguard_core (pure)          forgeguard_http (pure)           forgeguard_proxy (I/O shell)
├── FlagName                    ├── ProxyConfig.features()       ├── ForgeGuardProxy.flag_config
├── FlagValue (Bool/String/Num) ├── RouteMapping.feature_gate    ├── request_filter steps 4-6
├── FlagType                    ├── check_feature_gates()        ├── debug endpoint (--debug)
├── FlagOverride                ├── FlagDebugQuery::parse()      └── inject X-Fg-Features
├── FlagDefinition              └── evaluate_debug()
├── FlagConfig
├── ResolvedFlags
├── ResolutionReason
├── ResolvedFlag
├── DetailedResolvedFlags
├── evaluate_flags()
└── evaluate_flags_detailed()
```

## Evaluation Order

`resolve_single_flag` applies rules in this order (first match wins):

1. **Kill switch** — if `flag.enabled == false`, return default immediately.
2. **Override scan** — iterate `flag.overrides` in config order. Each override has optional `tenant`, `user`, and `group` fields. `None` is a wildcard. All specified fields must match. First matching override wins.
3. **Rollout bucket** — if `rollout_percentage` is set, compute `deterministic_bucket(flag_name, tenant, user)` via XXHash64. Bucket < threshold means included.
4. **Default** — return `flag.default`.

Config authors control override priority through ordering (first match wins, no implicit specificity ranking).

## Override Matching

An override matches when ALL specified dimensions match:

- `tenant: None` → matches any tenant (wildcard)
- `user: None` → matches any user (wildcard)
- `group: None` → matches any groups (wildcard)
- `group: Some("admin")` → matches if user belongs to the "admin" group

## Debug Endpoint

`GET /.well-known/forgeguard/flags?user_id=X&tenant_id=Y&groups=admin,ops`

- Gated behind `--debug` CLI flag / `FORGEGUARD_DEBUG` env var
- Returns `DetailedResolvedFlags` — every flag with its `ResolutionReason`
- `user_id` is required; `tenant_id` and `groups` are optional
- Returns 400 for invalid query params

## Resolution Reasons

The `ResolutionReason` enum explains why a flag resolved to its value:

- `KillSwitch` — flag disabled
- `Override { tenant, user, group }` — which override matched
- `Rollout { bucket, threshold }` — user fell within rollout
- `RolloutExcluded { bucket, threshold }` — user fell outside rollout
- `Default` — no rule matched

## Proxy Integration

In `request_filter`, feature flags are evaluated at step 4 (after identity resolution, before route matching):

- Step 4: `evaluate_flags(config, tenant_id, user_id, groups)` → `ResolvedFlags`
- Step 6: If route has `feature_gate` and flag is not enabled → 404 `{"error": "Not Found"}`
- `upstream_request_filter`: `X-Fg-Features` header injected with JSON of all resolved flags

## TOML Configuration

```toml
[features.flags."todo:ai-suggestions"]
type = "boolean"
default = false
enabled = true
rollout_percentage = 25

[[features.flags."todo:ai-suggestions".overrides]]
tenant = "acme"
group = "admin"
value = true
```

## Key Files

| File | Purpose |
|------|---------|
| `crates/core/src/features/mod.rs` | All flag types and evaluation logic |
| `crates/core/src/features/tests.rs` | Unit tests (group overrides, detailed evaluation, rollout) |
| `crates/http/src/debug.rs` | Debug endpoint query parsing and response builder |
| `crates/http/src/validate.rs` | `check_feature_gates()` — startup validation |
| `crates/proxy/src/proxy.rs` | Proxy lifecycle integration (steps 4-6, debug endpoint) |
