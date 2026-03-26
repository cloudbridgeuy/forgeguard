# forgeguard_http

HTTP adapter types for ForgeGuard. All HTTP-specific logic lives here, separated
from the Pingora runtime so that config validation, route inspection, and other
utility operations compile and run cross-platform (including macOS).

## Classification

**I/O crate** (minimal) — the only I/O is `load_config()` reading a TOML file.
Everything else is pure.

## Capabilities

1. **Route matching** — `(method, path)` to `(action, resource)` via `matchit` radix tries.
2. **Public route matching** — bypass auth for configured paths (anonymous or opportunistic).
3. **Config parsing** — `forgeguard.toml` to validated `ProxyConfig` (two-phase Parse Don't Validate).
4. **Config validation** — duplicate routes, feature gate references, policy/group references.
5. **Credential extraction** — `Authorization: Bearer` and `X-API-Key` from headers.
6. **Header injection** — `X-ForgeGuard-*` identity headers for upstream.
7. **Authn-authz glue** — `build_query` bridges `Identity` into `PolicyQuery`.

## Dependencies

- `forgeguard_core` — shared primitives
- `forgeguard_authn_core` — `Credential`, `Identity`
- `forgeguard_authz_core` — `PolicyQuery`, `PolicyContext`
- `matchit` — radix trie routing
- `toml`, `serde`, `serde_json` — config parsing
- `url` — URL validation
- `thiserror` — error types
- `tracing` — structured logging

No `tokio`, no `reqwest`, no AWS SDKs.
