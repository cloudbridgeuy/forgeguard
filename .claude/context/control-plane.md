# Control Plane

The control plane (`forgeguard_control_plane`) is an Axum HTTP service that serves per-organization proxy configuration. BYOC connected proxies and the SaaS proxy poll this endpoint to fetch routes, flags, and upstream config. Authentication is handled by the `forgeguard-axum` middleware layer.

## Architecture

```
File (orgs.json)               Control Plane (Axum)           BYOC Proxy
     |                              |                              |
     +-- load at startup -->  InMemoryOrgStore (async, RwLock)     |
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

The store is trait-based with async methods and generic handlers (no `dyn` dispatch):

```rust
pub(crate) trait OrgStore: Send + Sync {
    fn get(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<Option<OrgRecord>>> + Send;
}
```

| Implementation | Backend | Used by |
|---------------|---------|---------|
| `InMemoryOrgStore` | In-memory HashMap behind `tokio::sync::RwLock` | File-backed dev mode, tests |
| `DynamoOrgStore` | DynamoDB-backed | Production SaaS |

Runtime dispatch uses `AnyOrgStore`, a dispatch enum (`Memory` / `DynamoDb`) that implements `OrgStore` via static dispatch (the trait uses `impl Future` returns, making it not object-safe).

Handlers are generic over `S: OrgStore` and take `State<Arc<S>>`. This avoids `dyn` dispatch while still allowing backend substitution.

### OrgRecord

Each stored entry is an `OrgRecord` containing:
- `Organization` -- domain entity from `forgeguard_core` (org_id, name, status, timestamps)
- `OrgConfig` -- versioned proxy configuration (routes, upstream, default policy)
- `etag` -- precomputed xxHash64 of the serialized config

## Handler Pipeline

Auth is handled by the `forgeguard-axum` middleware before the handler runs. The handler is pure data retrieval:

```
Request -> forgeguard_layer (auth) -> ForgeGuardIdentity extractor -> lookup_org -> check_if_none_match -> respond
                                                                        | 404          | 304                | 200
```

The handler uses `ForgeGuardIdentity` to receive the resolved identity from the middleware. Org-scoping is a Cedar policy concern evaluated by the pipeline.

## Config File Format

JSON file mapping `org_id` to its org entry. Each entry has a `name` (display name) and a nested `config` object (`OrgConfig`) with a date-based `version` field:

```json
{
  "organizations": {
    "org-acme": {
      "name": "Acme Corp",
      "config": {
        "version": "2026-04-07",
        "project_id": "todo-demo",
        "upstream_url": "https://api.acme.com",
        "default_policy": "deny",
        "routes": [
          {"method": "GET", "path": "/api/todos", "action": "todo:list:read"}
        ],
        "public_routes": [
          {"method": "GET", "path": "/health", "auth_mode": "anonymous"}
        ],
        "features": {}
      }
    }
  }
}
```

**Validation at load time (Parse Don't Validate):**
- `OrganizationId` validated via `forgeguard_core::OrganizationId::new()`
- Each org entry is parsed into an `Organization` domain entity with `OrgStatus::Active`
- ETag precomputed as xxHash64 of canonical JSON (deterministic, uses `BTreeMap` for `features`)
- Unknown fields are ignored by serde for forward compatibility

## Auth

Auth is handled by the `forgeguard-axum` middleware, which runs the ForgeGuard auth pipeline (`evaluate_pipeline` from proxy-core) before requests reach handlers.

In dev mode, the control plane uses `DefaultPolicy::Passthrough` with an empty `IdentityChain` and `StaticPolicyEngine(Allow)` -- all requests pass through without auth enforcement.

**Not yet implemented:** Cognito JWT auth (#41) for production auth.

## Testing

- 8 store tests (`store.rs`) -- parsing, validation, ETag determinism, multiple orgs, unknown fields
- 4 handler integration tests (`handlers.rs`) -- full HTTP pipeline via `tower::ServiceExt::oneshot` with `forgeguard-axum` middleware layer

Store tests use `build_org_store()` with inline JSON to build `InMemoryOrgStore` instances. Tests that call `store.get()` use `#[tokio::test]` since the store is async.

## Running

```sh
# Quick start with test config (in-memory store)
cargo run -p forgeguard_control_plane -- --config examples/control-plane/orgs.test.json

# DynamoDB store
cargo run -p forgeguard_control_plane -- --store dynamodb --dynamodb-table forgeguard-orgs
```

### CLI Flags

| Flag | Env | Description |
|------|-----|-------------|
| `--store` | `FORGEGUARD_CP_STORE` | Store backend: `memory` (default) or `dynamodb` |
| `--config` | `FORGEGUARD_CP_CONFIG` | Path to org config JSON file (required when `--store=memory`) |
| `--dynamodb-table` | `FORGEGUARD_CP_DYNAMODB_TABLE` | DynamoDB table name (required when `--store=dynamodb`) |
| `--listen` | `FORGEGUARD_CP_LISTEN` | Listen address (default: `127.0.0.1:3001`) |
| `--log-level` | `FORGEGUARD_CP_LOG_LEVEL` | Log level filter (default: `info`) |

See `crates/control-plane/README.md` for full usage instructions and curl examples.

## Module Structure

```
crates/control-plane/src/
  main.rs          -- entry point, tracing, ForgeGuard setup, server startup (shell)
  cli.rs           -- clap CLI: --store, --config, --dynamodb-table, --listen, --log-level
  config.rs        -- OrgConfig (versioned), RouteEntry, PublicRouteEntry (serde DTOs)
  store.rs         -- OrgStore trait (async), InMemoryOrgStore, AnyOrgStore, OrgRecord, build/load/etag
  dynamo_store.rs  -- DynamoOrgStore (DynamoDB-backed OrgStore implementation)
  handlers.rs      -- health_handler, proxy_config_handler<S: OrgStore> (shell) + integration tests
  error.rs         -- Error enum, Result alias
```

## What's NOT Here Yet

- CORS middleware (no browser clients -- deferred to #40 dashboard)
- Cognito JWT auth for production (deferred to #41)
- Lambda deployment (deferred to #45)
- Hot-reload of config file
