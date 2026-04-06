# Control Plane

The control plane (`forgeguard_control_plane`) is an Axum HTTP service that serves per-organization proxy configuration. BYOC connected proxies and the SaaS proxy poll this endpoint to fetch routes, flags, and upstream config.

## Architecture

```
File (orgs.json)               Control Plane (Axum)           BYOC Proxy
     |                              |                              |
     +-- load at startup -->  OrgConfigStore (in-memory)           |
                                    |                              |
                              GET /api/v1/organizations/{org_id}/proxy-config
                                    |                              |
                              Bearer fgt_... auth                  |
                              ETag / 304 caching                   |
                                    |                              |
                                    +--- JSON response ----------->|
```

## OrgStore Trait

The store is trait-based to support multiple backends:

```rust
pub(crate) trait OrgStore: Send + Sync {
    fn get(&self, org_id: &OrganizationId) -> Option<&OrgEntry>;
}
```

| Implementation | Backend | Used by |
|---------------|---------|---------|
| `OrgConfigStore` | In-memory HashMap | File-backed dev mode, tests |
| (future) | S3-backed | Production SaaS |

The handler uses `Arc<dyn OrgStore>` — backends are swappable without touching handler code.

## Handler Pipeline

The proxy-config handler is a **linear fail-fast pipeline**. Each step either passes control forward or short-circuits to an error response:

```
Request → extract_bearer_token → lookup_org → validate_token_for_org → check_if_none_match → respond
              ↓ 401                ↓ 404            ↓ 403                  ↓ 304              ↓ 200
```

All decision functions (`extract_bearer_token`, `token_matches_org`) are pure — unit tested in `auth.rs`. The handler is the imperative shell that orchestrates them.

## Config File Format

JSON file mapping `org_id` to config + bearer token:

```json
{
  "organizations": {
    "org-acme": {
      "token": "fgt_<secret>",
      "config": {
        "organization_id": "org-acme",
        "cognito_pool_id": "...",
        "cognito_jwks_url": "...",
        "policy_store_id": "...",
        "project_id": "...",
        "upstream_url": "...",
        "default_policy": "deny",
        "routes": [...],
        "public_routes": [...],
        "features": {}
      }
    }
  }
}
```

**Validation at load time (Parse Don't Validate):**
- `OrganizationId` validated via `forgeguard_core::OrganizationId::new()`
- Map key must match `config.organization_id`
- Token must be non-empty and start with `fgt_` prefix
- ETag precomputed as xxHash64 of canonical JSON (deterministic, uses `BTreeMap` for `features`)

## Auth

Simple bearer token scheme (`Authorization: Bearer fgt_...`). Each org has its own token stored in the config file. Token-to-org scoping prevents cross-org config leakage (403 Forbidden).

`BearerToken` enum uses Make Impossible States Impossible — `Valid(&str)`, `Missing`, `Invalid`.

**Not yet implemented:** Cognito JWT auth (#41), Ed25519 signature auth (#29 + #41).

## Testing

**25 tests total:**
- 10 store tests (`store.rs`) — parsing, validation, ETag determinism
- 8 auth tests (`auth.rs`) — token extraction, matching
- 7 handler integration tests (`handlers.rs`) — full HTTP pipeline via `tower::ServiceExt::oneshot`

Integration tests use `OrgConfigStore::from_entries()` to build in-memory stores programmatically — no files, no network.

## Running

```sh
# Quick start with test config
cargo run -p forgeguard_control_plane -- --config examples/control-plane/orgs.test.json

# Dogfooding: proxy in front of control plane
cargo run -p forgeguard_proxy -- run --config examples/control-plane/proxy.toml
```

See `crates/control-plane/README.md` for full usage instructions and curl examples.

## Module Structure

```
crates/control-plane/src/
  main.rs       — entry point, tracing, server startup (shell)
  cli.rs        — clap CLI: --config, --listen, --log-level
  config.rs     — OrgProxyConfig, RouteEntry, PublicRouteEntry (serde DTOs)
  store.rs      — OrgStore trait, OrgConfigStore, build/load/etag (core + shell)
  auth.rs       — extract_bearer_token, token_matches_org (pure core)
  handlers.rs   — health_handler, proxy_config_handler (shell) + integration tests
  error.rs      — Error enum, Result alias
```

## What's NOT Here Yet

- CORS middleware (no browser clients — deferred to #40 dashboard)
- Cognito/Ed25519 auth (deferred to #41)
- DynamoDB/S3 backend (deferred to later slices)
- Lambda deployment (deferred to #45)
- Hot-reload of config file
