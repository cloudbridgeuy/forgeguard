# Control Plane

The control plane (`forgeguard_control_plane`) is an Axum HTTP service that serves per-organization proxy configuration. BYOC connected proxies and the SaaS proxy poll this endpoint to fetch routes, flags, and upstream config. Authentication is handled by the `forgeguard-axum` middleware layer.

## Architecture

```
File (orgs.json)               Control Plane (Axum)           BYOC Proxy
     |                              |                              |
     +-- load at startup -->  OrgConfigStore (in-memory)           |
                                    |                              |
                              forgeguard-axum middleware            |
                              (auth pipeline, identity resolution)  |
                                    |                              |
                              GET /api/v1/organizations/{org_id}/proxy-config
                                    |                              |
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

Auth is handled by the `forgeguard-axum` middleware before the handler runs. The handler is pure data retrieval:

```
Request → forgeguard_layer (auth) → ForgeGuardIdentity extractor → lookup_org → check_if_none_match → respond
                                                                      ↓ 404          ↓ 304              ↓ 200
```

The handler uses `ForgeGuardIdentity` to receive the resolved identity from the middleware. Org-scoping is a Cedar policy concern evaluated by the pipeline.

## Config File Format

JSON file mapping `org_id` to config:

```json
{
  "organizations": {
    "org-acme": {
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
- ETag precomputed as xxHash64 of canonical JSON (deterministic, uses `BTreeMap` for `features`)

## Auth

Auth is handled by the `forgeguard-axum` middleware, which runs the ForgeGuard auth pipeline (`evaluate_pipeline` from proxy-core) before requests reach handlers.

In dev mode, the control plane uses `DefaultPolicy::Passthrough` with an empty `IdentityChain` and `StaticPolicyEngine(Allow)` — all requests pass through without auth enforcement.

**Not yet implemented:** Cognito JWT auth (#41) for production auth.

## Testing

**12 tests total:**
- 8 store tests (`store.rs`) — parsing, validation, ETag determinism
- 4 handler integration tests (`handlers.rs`) — full HTTP pipeline via `tower::ServiceExt::oneshot` with `forgeguard-axum` middleware layer

Integration tests use `OrgConfigStore::from_entries()` to build in-memory stores programmatically — no files, no network.

## Running

```sh
# Quick start with test config
cargo run -p forgeguard_control_plane -- --config examples/control-plane/orgs.test.json
```

See `crates/control-plane/README.md` for full usage instructions and curl examples.

## Module Structure

```
crates/control-plane/src/
  main.rs       — entry point, tracing, ForgeGuard setup, server startup (shell)
  cli.rs        — clap CLI: --config, --listen, --log-level
  config.rs     — OrgProxyConfig, RouteEntry, PublicRouteEntry (serde DTOs)
  store.rs      — OrgStore trait, OrgConfigStore, build/load/etag (core + shell)
  handlers.rs   — health_handler, proxy_config_handler (shell) + integration tests
  error.rs      — Error enum, Result alias
```

## What's NOT Here Yet

- CORS middleware (no browser clients — deferred to #40 dashboard)
- Cognito JWT auth for production (deferred to #41)
- DynamoDB/S3 backend (deferred to later slices)
- Lambda deployment (deferred to #45)
- Hot-reload of config file
