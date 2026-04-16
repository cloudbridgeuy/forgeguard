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
- `Option<ConfiguredConfig>` -- the proxy config + its etag, paired so they cannot drift. `None` represents a Draft org (created but not yet configured)

#### ConfiguredConfig invariant

Config and etag travel as a pair. Two constructors enforce this:
- `ConfiguredConfig::compute(config)` -- computes the etag from the config bytes (used on create / update)
- `ConfiguredConfig::from_stored(config, etag)` -- reuses an etag that was persisted alongside the config (used when reading from DynamoDB)

This makes "config without etag" and "etag without config" unrepresentable — see [the Make Impossible States Impossible pattern](../../~/.claude/patterns/). Handlers that need both fields call `record.configured()` once instead of two separate getters.

### Lifecycle

An org is created `Draft` (no config) and stays `Draft` until the onboarding saga (#55) provisions Cognito / VP / signing keys and flips it to `Active`. Status is **independent** of whether config is attached:

| Created via | Status on creation | Config |
|-------------|-------------------|--------|
| `POST /api/v1/organizations` (no body `config`) | `Draft` | absent |
| `POST /api/v1/organizations` (with body `config`) | `Draft` | present |
| File loader entry without `"config"` | `Draft` | absent |
| File loader entry with `"config"` | `Active` | present (legacy: file-seeded orgs are pre-onboarded) |

`PUT /api/v1/organizations/{org_id}` with a `config` body attaches config to a Draft org but does **not** auto-promote to Active — that transition is the saga's responsibility.

`GET /api/v1/organizations/{org_id}/proxy-config` returns **409 Conflict** when `record.configured()` is `None`, with body `{"error":"organization '<id>' has no proxy config"}`. This is the proxy's signal that the org exists but is not yet ready to serve traffic.

## Handler Pipeline

Auth is handled by the `forgeguard-axum` middleware before the handler runs. The handler is pure data retrieval:

```
Request -> forgeguard_layer (auth) -> ForgeGuardIdentity extractor -> lookup_org -> check_if_none_match -> respond
                                                                        | 404          | 304                | 200
```

The handler uses `ForgeGuardIdentity` to receive the resolved identity from the middleware. Org-scoping is a Cedar policy concern evaluated by the pipeline.

## Config File Format

JSON file mapping `org_id` to its org entry. Each entry has a `name` (display name); the nested `config` object (`OrgConfig`) is **optional** — entries without `config` seed as Draft orgs:

```json
{
  "organizations": {
    "org-seeded-draft": {
      "name": "Seeded Draft"
    },
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
- Entries with `config` parse into `Organization` with `OrgStatus::Active`; entries without `config` parse with `OrgStatus::Draft`
- ETag precomputed as xxHash64 of canonical JSON (deterministic, uses `BTreeMap` for `features`)
- Unknown fields are ignored by serde for forward compatibility

## Auth

Auth is handled by the `forgeguard-axum` middleware, which runs the ForgeGuard auth pipeline (`evaluate_pipeline` from proxy-core) before requests reach handlers.

**Two modes** controlled by the `--jwks-url` / `FORGEGUARD_CP_JWKS_URL` flag:

| Mode | When | Behavior |
|------|------|----------|
| Dev (no auth) | `--jwks-url` omitted | All routes Anonymous, empty `IdentityChain`, `StaticPolicyEngine(Allow)` |
| Auth enabled | `--jwks-url` + `--issuer` provided | Only `/health` is Anonymous, all API routes require a valid Cognito JWT via `CognitoJwtResolver` |

When auth is enabled, the `IdentityChain` contains a `CognitoJwtResolver` constructed from the JWKS URL and issuer. Claims mapping: `sub` → user_id, `custom:org_id` → tenant_id, `cognito:groups` → groups. The optional `--audience` flag enables audience claim validation against the Cognito app client ID.

The `AuthConfig` struct (`app.rs`) validates the JWKS URL at construction time (Parse Don't Validate) and is `pub` so `fg-lambdas` can import it. The Lambda binary reads the same config from `FORGEGUARD_CP_JWKS_URL`, `FORGEGUARD_CP_ISSUER`, `FORGEGUARD_CP_AUDIENCE` env vars (injected by the CDK Lambda stack from Cognito stack outputs).

**Not yet implemented:** VP authorization (#41 V4), Ed25519 machine auth (#41 V3).

## Testing

- Store tests (`store.rs`) -- parsing, validation, ETag determinism, multiple orgs, unknown fields, key lifecycle, Draft round-trip, Draft → configured promotion
- Handler integration tests (`handlers/tests.rs`) -- full HTTP pipeline via `tower::ServiceExt::oneshot` with `forgeguard-axum` middleware layer, auth via `StaticApiKeyResolver` (`x-api-key: test-key`). Includes Draft creation, 409 on Draft proxy-config, PUT-promotes-Draft. Lives in a sibling file because `handlers/mod.rs` would exceed the 1000-line cap with its tests inline.
- Key handler integration tests (`handlers/keys.rs`) -- generate, revoke (incl. idempotent), list keys
- DynamoDB integration tests (`dynamo_store/tests.rs`) -- feature-gated behind `dynamodb-tests`, run via `cargo xtask control-plane test`. Includes Draft round-trip and Draft → configured promotion against a real DynamoDB backend.

Store tests use `build_org_store()` with inline JSON to build `InMemoryOrgStore` instances. Tests that call `store.get()` use `#[tokio::test]` since the store is async.

Handler tests use `StaticApiKeyResolver` with a known test key. All test requests include `x-api-key: test-key`. The `unauthenticated_request_returns_401` test verifies the auth boundary.

### DynamoDB Integration Tests

`cargo xtask control-plane test` manages the full lifecycle:
1. Detects docker or podman on PATH
2. Starts `amazon/dynamodb-local` on a random port (`-p 0:8000`)
3. Discovers the assigned port and sets `DYNAMODB_ENDPOINT`
4. Runs `cargo test -p forgeguard_control_plane --features dynamodb-tests`
5. Stops the container (guaranteed via RAII guard, even on failure)

DynamoDB key attribute names (`PK`, `SK`) are read from the shared schema file `infra/control-plane/schema/dynamodb.json` — the single source of truth consumed by both CDK and Rust via `include_str!`.

## Running

```sh
# Quick start with test config, no auth (dev mode)
cargo run -p forgeguard_control_plane -- --config examples/control-plane/orgs.test.json

# With Cognito auth (requires deployed Cognito stack)
cargo run -p forgeguard_control_plane -- --config examples/control-plane/orgs.test.json \
  --jwks-url "$JWKS_URL" --issuer "$ISSUER" --audience "$APP_CLIENT_ID"

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
| `--jwks-url` | `FORGEGUARD_CP_JWKS_URL` | JWKS URL for Cognito JWT auth. Omit for dev mode (no auth) |
| `--issuer` | `FORGEGUARD_CP_ISSUER` | JWT issuer URL. Required when `--jwks-url` is set |
| `--audience` | `FORGEGUARD_CP_AUDIENCE` | JWT audience (Cognito app client ID). Optional |

See `crates/control-plane/README.md` for full usage instructions and curl examples.

## Module Structure

```
crates/control-plane/src/
  lib.rs              -- library root: pub mod app + internal modules
  app.rs              -- public router builders: dynamodb_router(), memory_router()
  main.rs             -- binary entry point: CLI parsing, delegates to app:: (shell)
  cli.rs              -- clap CLI: --store, --config, --dynamodb-table, --listen, --log-level, --jwks-url, --issuer, --audience
  config.rs           -- OrgConfig (versioned), RouteEntry, PublicRouteEntry (serde DTOs)
  store.rs            -- OrgStore trait (async), InMemoryOrgStore, AnyOrgStore, OrgRecord, ConfiguredConfig, build/load/etag
  dynamo_store/       -- DynamoOrgStore (DynamoDB-backed OrgStore implementation)
  handlers/
    mod.rs            -- health, CRUD, proxy_config handlers
    tests.rs          -- handler integration tests (split from mod.rs to satisfy 1000-line cap)
    keys.rs           -- generate_key, list_keys, revoke_key handlers + tests
  signing_key.rs      -- SigningKeyEntry, KeyStatus, Ed25519 key generation
  error.rs            -- Error enum, Result alias
```

The crate is both lib+bin. `app.rs` exposes `dynamodb_router()` and `memory_router()` so `fg-lambdas` can import the Axum router and wrap it with `lambda_http`. All internal types stay `pub(crate)`.

### Test Fixtures

- `examples/control-plane/orgs.test.json` — multi-org config for local dev (`--store=memory`)
- `examples/control-plane/orgs.sample.json` — template with placeholder values

## Key Management

Three endpoints manage Ed25519 signing keys per organization. Keys are used for outbound request signing (see [request-signing.md](./request-signing.md)).

### Endpoints

| Method | Path | Description | Success |
|--------|------|-------------|---------|
| `POST` | `/api/v1/organizations/{org_id}/keys` | Generate a new Ed25519 signing key | 201 |
| `GET` | `/api/v1/organizations/{org_id}/keys` | List signing keys for an org | 200 |
| `DELETE` | `/api/v1/organizations/{org_id}/keys/{key_id}` | Revoke a signing key | 204 |

All endpoints return 404 if the organization does not exist, except DELETE which returns 204 regardless (idempotent).

### Generate Key (POST)

Returns the full keypair on creation. The private key is returned only once and is not stored by the control plane -- the caller must persist it.

```sh
curl -s -X POST \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys | jq .
```

Response (201):

```json
{
  "key_id": "key-...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "created_at": "2026-04-15T12:00:00+00:00"
}
```

### List Keys (GET)

Returns public metadata for all active keys. Never includes private keys.

```sh
curl -s \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys | jq .
```

Response (200):

```json
[
  {
    "key_id": "key-...",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "status": "active",
    "created_at": "2026-04-15T12:00:00+00:00"
  }
]
```

### Revoke Key (DELETE)

Idempotent -- returns 204 whether the key existed or not.

```sh
curl -s -X DELETE \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys/key-abc123
# 204 No Content
```

## What's NOT Here Yet

- CORS middleware (no browser clients -- deferred to #40 dashboard)
- Ed25519 machine authentication (#41 V3)
- VP authorization with PrincipalKind routing (#41 V4)
- Hot-reload of config file
