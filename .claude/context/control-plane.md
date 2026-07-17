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

The store is trait-based with `#[async_trait]` async methods, which makes the trait object-safe so the runtime can carry `Arc<dyn OrgStore>` without enum dispatch:

```rust
#[async_trait]
pub(crate) trait OrgStore: Send + Sync {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>>;
    // ... 15 more methods
}
```

| Implementation | Backend | Used by |
|---------------|---------|---------|
| `InMemoryOrgStore` | In-memory HashMap behind `tokio::sync::RwLock` | File-backed dev mode, tests |
| `DynamoOrgStore` | DynamoDB-backed | Production SaaS |

`app.rs` builds a single `Arc<dyn OrgStore>` at startup (memory or DynamoDB based on `--store`) and stores it on `AppState<V>`. There is no enum or wrapper — backend selection happens once at construction; every consumer downstream sees the same trait object.

### Handler state extraction

Handlers come in two shapes:

- **No VP needed** (org read, `list_keys`): take `State<Arc<dyn OrgStore>>` directly. `AppState<V>` exposes the store via a `FromRef<AppState<V>> for Arc<dyn OrgStore>` impl, so Axum derives the sub-state automatically.
- **VP needed** (group write handlers under `/groups`; key mutation handlers under `/keys`, which reach `state.model_events`): take `State<AppState<V>>` and reach `state.store` / `state.vp` / `state.model_events`. Only this group of handlers carries the `<V: VpClient>` parameter.

The rule when adding a new handler: never introduce `<S: OrgStore>` on a handler signature. If you find yourself wanting it, take `Arc<dyn OrgStore>` instead — it is the same dispatch under the hood with one fewer monomorphization. Per-handler generics over `S: OrgStore` are a removed pattern; do not reintroduce them.

### Test fixtures

Tests live under `handlers::tests::test_support` and `handlers::tests::active_support`:

- `empty_store() -> Arc<dyn OrgStore>` — default helper. Use when the test only needs trait methods.
- `empty_in_memory_store() -> Arc<InMemoryOrgStore>` — escape hatch when a test needs `InMemoryOrgStore::seed_membership(...)` (a `#[cfg(test)]` inherent method that is intentionally not on the trait). Tests that use this typically shadow with `let store_dyn: Arc<dyn OrgStore> = Arc::clone(&store) as _;` for the request layer.
- `FailingStore` — non-generic delegating wrapper over `Arc<dyn OrgStore>` that one-shot fails `delete_group` or `put_group` to drive F3' rollback paths. Adding methods to `OrgStore` requires updating `FailingStore` in lock-step.
- `test_app_for_store(store: Arc<dyn OrgStore>, vp: Arc<StubVpClient>)` — minimal router (group routes only) for the V3 Active-org failure-mode tests.

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

An org is created `Draft` (no config) and stays `Draft` until the onboarding saga (#55) provisions Cognito / VP / signing keys and flips it to `Active`, or an operator calls `POST .../activate` directly (see "Lifecycle Verbs (#113 V2)" below for the full `Draft`→`Active`⇄`Suspended`→`Deleting`→`Deleted` state machine and its three verb endpoints). Status is **independent** of whether config is attached:

| Created via | Status on creation | Config |
|-------------|-------------------|--------|
| `POST /api/v1/organizations` (no body `config`) | `Draft` | absent |
| `POST /api/v1/organizations` (with body `config`) | `Draft` | present |
| File loader entry (omitted `"status"`) | `Draft` | absent or present |
| File loader entry with `"status": "active"` | `Active` | absent or present |

The file loader respects the declared `status` field on `RawOrgEntry`, defaulting to `Draft` when omitted. The previous heuristic (`configured.is_some() → Active`) was dropped in V5 of issue #102 — the seed flow no longer pre-promotes orgs and a config-bearing entry no longer implies Active.

`PUT /api/v1/organizations/{org_id}` with a `config` body attaches config to a Draft org but does **not** auto-promote to Active — that transition is the saga's responsibility.

`GET /api/v1/organizations/{org_id}/proxy-config` returns **409 Conflict** when `record.configured()` is `None`, with body `{"error":"organization '<id>' has no proxy config"}`. This is the proxy's signal that the org exists but is not yet ready to serve traffic.

## Handler Pipeline

Auth is handled by the `forgeguard-axum` middleware before the handler runs. The handler is pure data retrieval:

```
Request -> forgeguard_layer (auth) -> ForgeGuardIdentity extractor -> lookup_org -> check_if_none_match -> respond
                                                                        | 404          | 304                | 200
```

The handler uses `ForgeGuardIdentity` to receive the resolved identity from the middleware. Org-scoping is a Cedar policy concern evaluated by the pipeline.

### Org CRUD is event-sourced (revision tokens, #113 V1)

`POST`/`PUT /api/v1/organizations/{org_id}` write through
`ModelEventStore::{create_org, update_org}` onto the org's event log
(`org.created`/`org.updated`), not through `OrgStore` (that trait now only
serves reads — `get`/`list`). Optimistic concurrency is revision-tokened, not
etag-conditioned:

1. `PUT` accepts an optional `X-Fg-If-Revision: <u64>` header, parsed by the
   pure `handlers/if_revision.rs`. An unparseable value is `400`.
2. Before any write, the handler compares the incoming payload to the stored
   one via `decide_upsert`/`org_semantic_view` (pure, key-order-insensitive,
   ignores `updated_at`). A semantically-identical `PUT` is a no-op: `200`
   with the current revision, no event appended, no revision check performed.
3. Otherwise the log append is conditioned on `X-Fg-If-Revision` (when
   present) matching the log's current revision. Mismatch → `412` with
   `{"error": "revision_mismatch", "current_revision", "expected_revision"}`
   and an `x-fg-revision` header carrying the current revision.
4. On success, `200`/`201` responses carry the new revision in both the
   `x-fg-revision` header and the JSON body's `revision` field.

`If-Match`/`ETag` no longer apply to org `PUT` — they're ignored if sent.
There is no `DELETE /api/v1/organizations/{org_id}`; org deletion isn't
supported on the log yet, so the route falls through to Axum's default `405`.
Groups and user-schema `PUT`/`DELETE` are unaffected — they still use
`ETag`/`If-Match` (see [optimistic-locking.md](./optimistic-locking.md),
superseded for org mutations only).

## Lifecycle Verbs (#113 V2)

`OrgStatus` was pruned to the real lifecycle it needed to express: `Draft` → `Active` ⇄ `Suspended` → `Deleting` → `Deleted` (the speculative `PendingProvisioning`/`Provisioning`/`Failed` variants from V1 never had a caller and were removed). Three verb endpoints drive the transitions through the event log, mirroring the `create_org`/`update_org` event-sourced pattern:

| Endpoint | From | To | Event kind |
|----------|------|----|------------|
| `POST /api/v1/organizations/{org_id}/activate` | `Draft` (or `Suspended`, as a restore) | `Active` | `org.activated` |
| `POST /api/v1/organizations/{org_id}/suspend` | `Active` | `Suspended` | `org.suspended` (narrowing) |
| `POST /api/v1/organizations/{org_id}/restore` | `Suspended` | `Active` | `org.restored` |

Each handler (`handlers/lifecycle.rs`): parses `org_id` (404 on malformed), 404s on unknown/`Deleted` org, then:

- **No-op rule**: if the org is already at the verb's target status, responds `200` with the current revision and appends nothing (e.g. `activate` on an already-`Active` org).
- **Invalid transition**: any other `from` status responds `409 {"error": "invalid_transition"}` (e.g. `suspend` on a `Draft` org) — no event appended.
- **Valid transition**: appends the verb's event kind via `ModelEventStore::transition_org`, conditioned on the handler's observed revision as `expected_revision`; a losing race surfaces as `409 transition_conflict` (RFC 7232-style, revision-tokened like org `PUT`/#113 V1, not `If-Match`/`ETag`).
- On success, `200` with the updated org and `X-Fg-Revision` header, same shape as `PUT /organizations/{org_id}`.

Authorization: `cp-organization-activate`/`-suspend`/`-restore` are `admin`-tier RBAC actions (`forgeguard.toml`), auto-collected into the Cedar schema.

With `activate` live, the V1 prod-QA workaround of hand-flipping an org's `status` attribute directly in DynamoDB is obsolete — use the endpoint instead.

### D10: consumer reads relaxed to non-`Deleted`

`GET .../events` and `GET .../signing-keys` originally gated on `OrgStatus::Active` (404 unknown/deleted, `409 org_state_conflict` otherwise). Since lifecycle verbs mean orgs now spend real time in `Draft`/`Suspended`/`Deleting`, and SDKs/external verifiers need to observe the event log and signing keys through those states (not just once `Active`), both gates were relaxed to: 404 for unknown/`Deleted`, `200` otherwise.

| Status | `GET .../events`, `GET .../signing-keys` (read, D10) | Principal/promotion/user-schema writes (unchanged) |
|--------|-------------------------------------------------------|-----------------------------------------------------|
| `Draft` | `200` | `409` |
| `Active` | `200` | `200`/`201` |
| `Suspended` | `200` | `409` |
| `Deleting` | `200` | `409` |
| `Deleted` | `404` | `404` |
| unknown | `404` | `404` |

Write-side gates (principal upsert, promotion tombstone, groups, user-schema) are unchanged — still `Active`-only, `409 org_state_conflict` otherwise. D10 is read-only in scope.

## Config File Format

JSON file mapping `org_id` to its org entry. Each entry has a `name` (display name); the nested `config` object (`OrgConfig`) and the `status` field are both **optional**. Status defaults to `"draft"`; entries that need to start `Active` must declare `"status": "active"` explicitly:

```json
{
  "organizations": {
    "org-seeded-draft": {
      "name": "Seeded Draft"
    },
    "org-acme": {
      "name": "Acme Corp",
      "status": "active",
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
- `OrgStatus` parsed from the entry's `status` field; defaults to `Draft` when the field is omitted (V5 of #102 dropped the V0 `configured.is_some() → Active` heuristic)
- ETag precomputed as xxHash64 of canonical JSON (deterministic, uses `BTreeMap` for `features`)
- Unknown fields are ignored by serde for forward compatibility

## Auth

Auth is handled by the `forgeguard-axum` middleware, which runs the ForgeGuard auth pipeline (`evaluate_pipeline` from proxy-core) before requests reach handlers.

**Two modes** controlled by the `--jwks-url` / `FORGEGUARD_CP_JWKS_URL` flag:

| Mode | When | Behavior |
|------|------|----------|
| Dev (no auth) | `--jwks-url` omitted | All routes Anonymous, empty `IdentityChain`, `StaticPolicyEngine(Allow)` |
| Auth enabled | `--jwks-url` + `--issuer` provided | Only `/health` is Anonymous; all API routes require a valid credential resolved by the `IdentityChain` |

When auth is enabled, the `IdentityChain` contains resolvers tried in order:

1. `CognitoJwtResolver` — Cognito JWT via `Authorization: Bearer`. Identity-only mapping: `sub` → user_id. Org context (`tenant_id`) and roles (`groups`) are NOT read from the JWT — they are resolved per-request from the `X-ForgeGuard-Org-Id` header + a DynamoDB membership lookup (see Phase 5b). The optional `--audience` flag enables audience claim validation against the Cognito app client ID.
2. `Ed25519SignatureResolver` — Ed25519 signed requests from BYOC proxies (see below).

The `AuthConfig` struct (`app.rs`) validates the JWKS URL at construction time (Parse Don't Validate) and is `pub` so `fg-lambdas` can import it. The Lambda binary reads the same config from `FORGEGUARD_CP_JWKS_URL`, `FORGEGUARD_CP_ISSUER`, `FORGEGUARD_CP_AUDIENCE` env vars (injected by the CDK Lambda stack from Cognito stack outputs).

### Ed25519 Machine Authentication (V3)

BYOC proxies authenticate to the control plane using Ed25519 signed requests. This is only active when `--store=dynamodb` AND `--jwks-url` (auth) are both configured.

**Signed request flow:**

```
BYOC Proxy                              Control Plane
──────────                              ─────────────
1. Build identity headers (X-ForgeGuard-*)
2. Sign canonical payload (Ed25519, private key)
3. Inject 4 protocol headers + identity headers (e.g., `X-ForgeGuard-Org-Id`)
                                        4. extract_credential (priority 3)
                                           → Credential::SignedRequest
                                        5. Ed25519SignatureResolver:
                                           a. Extract org_id from X-ForgeGuard-Org-Id
                                           b. Look up public key via DynamoSigningKeyStore
                                           c. Rebuild canonical payload, verify signature
                                           d. Check timestamp drift (≤ 5 min)
                                        6. Identity(user_id=key_id, tenant_id=org_id,
                                                    resolver="ed25519")
```

**Required headers from the proxy:**

| Header | Content |
|--------|---------|
| `X-ForgeGuard-Signature` | `v1:{base64(ed25519_sig)}` |
| `X-ForgeGuard-Timestamp` | Unix milliseconds |
| `X-ForgeGuard-Key-Id` | Key identifier (used for lookup and becomes user_id) |
| `X-ForgeGuard-Trace-Id` | Per-request UUID v7 |
| `X-ForgeGuard-Org-Id` | Organization identifier (identity header, becomes tenant_id) |

**Wiring in `app.rs`:** `dynamodb_router()` creates a `DynamoSigningKeyStore` (backed by the same DynamoDB table), wraps it in `Ed25519SignatureResolver`, and appends it to the `IdentityChain` after `CognitoJwtResolver`. Memory mode never gets the Ed25519 resolver.

**VP Authorization (V4):** When auth is enabled and a VP client is available (`--store=dynamodb` + `--jwks-url` + `--policy-store-id`), the policy engine is `VpPolicyEngine`. The Cedar project namespace is `forgeguard` (from `ProjectId::new("forgeguard")`). The tenant is read per request from `PolicyContext::tenant_id()` — populated from the `X-ForgeGuard-Org-Id` header during pipeline Phase 5b (membership enrichment) — so the engine is no longer bound to a static tenant at construction time. `DefaultPolicy::Deny` is used — unmatched routes are denied. See the Authorization section below for the route-to-action mapping and PrincipalKind routing.

`forgeguard_authz` (the `VpPolicyEngine` crate) is gated behind the control-plane's `vp` Cargo feature, default ON — nothing changes for existing deployments. Building with `--no-default-features` drops `forgeguard_authz` from the dependency graph; if a policy store ID is configured in that build, startup fails fast with an error instead of silently falling back to allow-all.

## Authorization

### Mode Selection

| Condition | Policy Engine | Default Policy |
|-----------|--------------|----------------|
| No `--jwks-url` (dev mode) | `StaticPolicyEngine(Allow)` | `Passthrough` |
| `--jwks-url` + `--store=memory` | `StaticPolicyEngine(Allow)` | `Deny` |
| `--jwks-url` + `--store=dynamodb` + `--policy-store-id` | `VpPolicyEngine` | `Deny` |

The Cedar namespace is `forgeguard` (from `ProjectId::new("forgeguard")`). The tenant is resolved per request from `PolicyContext::tenant_id()` (populated from `X-ForgeGuard-Org-Id` via pipeline Phase 5b), not fixed at engine construction.

### Route-to-Action Mapping

All API routes map to QualifiedActions in the `cp` namespace (no `DELETE
/api/v1/organizations/{org_id}` — removed in #113 V1, see above):

| Method | Path | Cedar Action |
|--------|------|-------------|
| `POST` | `/api/v1/organizations` | `cp:organization:create` |
| `GET` | `/api/v1/organizations` | `cp:organization:read` |
| `GET` | `/api/v1/organizations/{org_id}` | `cp:organization:read` |
| `PUT` | `/api/v1/organizations/{org_id}` | `cp:organization:update` |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | `cp:proxy-config:read` |
| `POST` | `/api/v1/organizations/{org_id}/keys` | `cp:key:generate` |
| `GET` | `/api/v1/organizations/{org_id}/keys` | `cp:key:read` |
| `DELETE` | `/api/v1/organizations/{org_id}/keys/{key_id}` | `cp:key:revoke` |
| `POST` | `/api/v1/organizations/{org_id}/keys/{key_id}/rotate` | `cp:key:rotate` |
| `PUT` | `/api/v1/organizations/{org_id}/principals/{native_id}` | `cp:principal:upsert` |
| `GET` | `/api/v1/organizations/{org_id}/events` | `cp:events:read` |

### PrincipalKind Routing

The Cedar principal entity type is set by `build_query()` based on `Identity::principal_kind()`:

- Cognito JWT → `PrincipalKind::User` → Cedar `forgeguard::user`
- Ed25519 signed request (BYOC proxy) → `PrincipalKind::Machine` → Cedar `forgeguard::Machine`

Machine principals carry an `org_id` attribute and have no group parents.

## Testing

- Store tests (`store.rs`) -- parsing, validation, ETag determinism, multiple orgs, unknown fields, key lifecycle, Draft round-trip, Draft → configured promotion
- Handler integration tests (`handlers/tests.rs`) -- full HTTP pipeline via `tower::ServiceExt::oneshot` with `forgeguard-axum` middleware layer, auth via `StaticApiKeyResolver` (`x-api-key: test-key`). Includes Draft creation, 409 on Draft proxy-config, PUT-promotes-Draft. Lives in a sibling file because `handlers/mod.rs` would exceed the 1000-line cap with its tests inline.
- Key handler integration tests (`handlers/keys.rs`) -- generate, revoke (incl. idempotent D6 no-op), rotate (incl. 404/409), list keys, `x-fg-revision` header/body assertions, event-log cursor assertions (`org.key_generated`/`org.key_revoked` narrowing)
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

DynamoDB key attribute names (`PK`, `SK`) are read from the shared schema file `infra/control-plane/schema/forgeguard-orgs.json` — the single source of truth consumed by both CDK and Rust via `include_str!`.

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
| `--policy-store-id` | `FORGEGUARD_CP_POLICY_STORE_ID` | Verified Permissions policy store ID. Required when `--jwks-url` is set |

See `crates/control-plane/README.md` for full usage instructions and curl examples.

## Module Structure

```
crates/control-plane/src/
  lib.rs              -- library root: pub mod app + internal modules
  app.rs              -- public router builders: dynamodb_router(), memory_router()
  main.rs             -- binary entry point: CLI parsing, delegates to app:: (shell)
  cli.rs              -- clap CLI: --store, --config, --dynamodb-table, --listen, --log-level, --jwks-url, --issuer, --audience
  config.rs           -- OrgConfig (versioned), RouteEntry, PublicRouteEntry (serde DTOs)
  store.rs            -- OrgStore trait (object-safe via #[async_trait]), InMemoryOrgStore, OrgRecord, ConfiguredConfig, build/load/etag
  dynamo_store/       -- DynamoOrgStore (DynamoDB-backed OrgStore implementation)
  handlers/
    mod.rs            -- health, CRUD, proxy_config handlers
    tests.rs          -- handler integration tests (split from mod.rs to satisfy 1000-line cap)
    keys.rs           -- generate_key, revoke_key, rotate_key (event-sourced via ModelEventStore) + list_keys (OrgStore read) handlers + tests
    principals/       -- upsert_principal handler (PUT .../principals/{native_id})
    events/           -- list_events_handler (GET .../events cursor replay + V2 consistency tokens)
    promotions/       -- tombstone_promotion_handler (DELETE) + list_promotions_handler (GET .../promoted-resources)
    min_revision.rs   -- pure X-Fg-Min-Revision parse + fresh/behind guard (V2, N11)
  signing_key.rs      -- SigningKeyEntry, KeyStatus, Ed25519 key generation
  signing_key_store.rs -- DynamoSigningKeyStore (implements SigningKeyStore from authn-core)
  event_log.rs        -- DynamoEventLog: transactional append (TransactWriteItems) + events_after/latest_revision (Query)
  principal_store.rs  -- PrincipalEventStore trait, DynamoPrincipalEventStore, InMemoryPrincipalEventStore, event signing-key mint
  error.rs            -- Error enum, Result alias
```

The crate is both lib+bin. `app.rs` exposes `dynamodb_router()` and `memory_router()` so `fg-lambdas` can import the Axum router and wrap it with `lambda_http`. All internal types stay `pub(crate)`.

### Test Fixtures

- `examples/control-plane/orgs.test.json` — multi-org config for local dev (`--store=memory`)
- `examples/control-plane/orgs.sample.json` — template with placeholder values

## Key Management

Four endpoints manage Ed25519 request-signing keys per organization. The private key is used by the BYOC proxy for outbound request signing (see [request-signing.md](./request-signing.md)); the public key is stored in the control plane and used by `DynamoSigningKeyStore` to verify inbound signed requests from the proxy.

### Key mutations are event-sourced (#113 V3)

`POST .../keys`, `DELETE .../keys/{key_id}`, and `POST .../keys/{key_id}/rotate` write through `ModelEventStore::{generate_org_key, revoke_org_key, rotate_org_key}` onto the org's event log, mirroring the org-CRUD pattern (#113 V1). `OrgStore` no longer has key-write methods — it keeps only reads (`list_keys`, `get`) plus `write_through_signing_keys`, the write-through target `InMemoryModelEventStore` uses to mirror key mutations into the read model consumed by `list_keys`/`DynamoSigningKeyStore`.

Each mutation appends one event alongside the org's new `signing_keys` list, in the same transaction:

| Event kind | Appended by | Narrowing |
|------------|-------------|-----------|
| `org.key_generated` | `POST .../keys` | no |
| `org.key_revoked` | `DELETE .../keys/{key_id}` | yes |
| `org.key_rotated` | `POST .../keys/{key_id}/rotate` | no |

Event payloads carry the public half only (`key_id`, `public_key`, `status`, `created_at`, optionally `expires_at`) — the private key never appears on the log, only in the one-time mutation response.

`generate_org_key`/`rotate_org_key` return the new key material together with the `Revision` the append landed at, atomically from the same transaction — handlers surface it as both the `x-fg-revision` response header and a `revision` field in the JSON body, so callers never need a separate `GET .../events` read to learn the log position their mutation produced.

### Endpoints

| Method | Path | Description | Success |
|--------|------|-------------|---------|
| `POST` | `/api/v1/organizations/{org_id}/keys` | Generate a new Ed25519 signing key | 201 |
| `GET` | `/api/v1/organizations/{org_id}/keys` | List signing keys for an org | 200 |
| `DELETE` | `/api/v1/organizations/{org_id}/keys/{key_id}` | Revoke a signing key | 204 |
| `POST` | `/api/v1/organizations/{org_id}/keys/{key_id}/rotate` | Rotate a signing key | 201 |

All endpoints return 404 if the organization does not exist, except DELETE which returns 204 regardless (idempotent). Rotate returns 404 for an unknown `key_id` and 409 (`{"error": "..."}`) if the target key is already `Revoked` or already `Rotating`.

### Generate Key (POST)

Returns the full keypair on creation. The private key is returned only once and is not stored by the control plane -- the caller must persist it.

```sh
curl -s -X POST \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys | jq .
```

Response (201, `x-fg-revision` header also set):

```json
{
  "key_id": "key-...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "created_at": "2026-04-15T12:00:00+00:00",
  "revision": 3
}
```

### List Keys (GET)

Returns public metadata for all active keys. Never includes private keys. Reads through `OrgStore::list_keys` (the read model kept in sync by key-mutation write-through), not the event log directly.

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

Idempotent -- returns 204 whether the key existed or not. This is the D6 no-op rule: revoking an absent/already-revoked key appends no event and `x-fg-revision` carries the log's *current* revision unchanged; an actual revocation appends `org.key_revoked` (narrowing) and `x-fg-revision` carries the *new* revision.

```sh
curl -s -X DELETE \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys/key-abc123
# 204 No Content
```

### Rotate Key (POST .../rotate)

Moves the target key to `Rotating` (with a grace window) and appends a new `Active` key in the same transaction. Returns the new keypair, shaped identically to Generate Key.

```sh
curl -s -X POST \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys/key-abc123/rotate | jq .
```

Response (201, `x-fg-revision` header also set): same shape as Generate Key.

## What's NOT Here Yet

- CORS middleware (no browser clients -- deferred to #40 dashboard)
- Hot-reload of config file

## V2 of #102 — Groups CRUD (Draft only)

Endpoints under `/api/v1/organizations/{org_id}/groups[/{name}]`. ETag/`If-Match` is mandatory on PUT/DELETE (omitting it returns 422). DELETE pre-checks for both live memberships (`count_memberships_for_group`) and inheriting groups (`list_inheritors`); either non-empty set blocks deletion. The Active-org branch that pushes compiled Cedar policies to Verified Permissions is `todo!("V3")` until VP push lands. The `is_declared_group(org_id, name)` predicate is exposed on `OrgStore` for issue #100's `POST /users` validator, which must confirm that a referenced group name is actually declared before accepting a membership assignment.

## Event Append Spine (V1)

Every principal upsert appends a signed, gap-free, per-org event to DynamoDB atomically with its state write, replayable via `GET .../events`. Pure event types (`EventEnvelope`, `EventKind`, `NarrowingFlag`, canonical signing bytes) live in `forgeguard_authz_core::event`; raw Ed25519 sign/verify-over-bytes helpers live in `forgeguard_authn_core::signing`. All I/O — the transactional append, the cursor query, and lazy signing-key mint — lives in `crates/control-plane/src/{event_log,principal_store}.rs`.

### `PUT /api/v1/organizations/{org_id}/principals/{native_id}`

1. `native_id` must parse as a `NativeId` (422 otherwise).
2. Org must exist and be `Active` (404 / 409 otherwise, mirroring every other org-scoped handler).
3. Strongly-consistent read of the existing principal, then `decide_upsert(existing, incoming)`:
   - `NoOp` (canonical JSON equality, key-order insensitive) — responds `200` with the current revision; appends nothing.
   - `Changed` — mints an `EventId` (ULID), signs the canonical event bytes with the org's Ed25519 event-signing key, and atomically (`TransactWriteItems`) increments the org's `seq` counter, puts the event item, and puts the principal state item. Responds `201` when nothing existed before the write, `200` otherwise. The appended `principal.upserted` event's payload (visible over `GET .../events`) is `{"native_id": "<id>", "principal": {<raw doc>}}` (V5 identity wrapper, `forgeguard_authz_core::principal_event_payload`) — the principal state item and the `decide_upsert` no-op compare both keep the raw doc unwrapped. Events appended before this wrapper existed carry the bare raw doc and cannot be folded (see Time Travel below).
4. Every response carries the new revision in both the `X-Fg-Revision` header and the JSON body's `revision` field.

### `GET /api/v1/organizations/{org_id}/events`

Cursor-based replay of the per-org event log, ordered by monotonic `seq`.

- Query params: `after` (u64 cursor, default 0 — returns events with `seq > after`), `limit` (default 100, clamped to 1000; a request for `0` is floored to `1` — both clamps are logged via `tracing::warn!`).
- `wait=1` selects long-poll mode (V2, N8): if the initial query returns a non-empty page, it's returned immediately; on an empty page, the handler ticks the org's `SEQ` counter every 200ms (strongly consistent) for up to ~1s, re-running the cursor query and returning early once the revision advances past `after`, or returning the empty page at the deadline. Any `wait` value other than `1` (including empty `wait=`) is `400 {"error": "wait must be '1'"}`.
- `X-Fg-Min-Revision: <u64>` request header (V2, N11): strongly-consistent-reads the log's current revision and compares against the header value *before* any wait. `current >= required` proceeds normally; `current < required` responds `412 Precondition Failed` with `{"error": "revision_behind", "current_revision": <u64>, "min_revision": <u64>}` and an `X-Fg-Revision` header carrying the current revision — this means a caller that is ahead of the server gets an immediate `412` even with `wait=1`, never a 1s hold. An unparseable header value is `400 {"error": "invalid X-Fg-Min-Revision header"}`. The guard's pure core (`parse_min_revision`, `check_min_revision`) lives in `crates/control-plane/src/handlers/min_revision.rs`, one level above `events/`, so later model-plane reads (e.g. V3 promotion lists) can reuse it.
- Response: `{"events": [...], "next_after": <u64>, "revision": <u64>}` plus an `X-Fg-Revision` header. `next_after` is the last returned event's `seq`, or the unchanged `after` on an empty page (never regresses). An `after` cursor ahead of the log's head simply holds the full watch deadline and returns empty — `X-Fg-Min-Revision` is the mechanism for "the caller knows more than the server", not this loop.
- Order of checks: parse `wait` → parse `X-Fg-Min-Revision` → org existence/non-`Deleted` check (D10, see Lifecycle Verbs below) → min-revision guard → query (+ optional watch) → respond.
- Org must exist and be non-`Deleted` (404 otherwise) — D10 relaxed this from an `Active`-only gate so `Draft`/`Suspended`/`Deleting` orgs stay observable.

### Event signing key

A dedicated per-org Ed25519 keypair (`SK = EVENT_SIGNING_KEY`) signs event envelopes. This is distinct from `signing_key_store.rs`'s key list, which is verification-only (public keys for verifying externally-signed BYOC proxy requests) and never persists a private key. The event-signing private key is lazily minted on first use with a conditional-write (CAS) retry, since it is self-managed by the control plane rather than provisioned by the onboarding saga.

### DynamoDB layout

New sparse item types (never populate `GSI1PK`/`GSI1SK` — see [infra-control-plane.md](./infra-control-plane.md)):

| Item | PK | SK |
|------|----|----|
| `seq_counter` | `ORG#{org_id}` | `SEQ` |
| `event` | `ORG#{org_id}` | `EVT#{seq:020}` (zero-padded so lexicographic order matches numeric order) |
| `principal` | `ORG#{org_id}` | `PRINCIPAL#{native_id}` |
| `promotion` | `ORG#{org_id}` | `PROMO#{resource_type}#{native_id}` |

`event_sk(seq)` computes the sort key; `EVT_SK_MAX` is a sentinel (`EVT#99999999999999999999`) used as the upper bound of a `BETWEEN` query so the counter item's bare `SK="SEQ"` (which lexicographically sorts after all `EVT#...` keys) never leaks into a replay page. The `after` cursor is `saturating_add(1)`'d before use — `after = u64::MAX` must floor to an empty page, not wrap to zero and return the entire history.

## Promotion Lifecycle (V3 of the event-log spine, A7/D7)

Idempotent tombstone + reconciliation endpoints for promoted resources, riding the same `TransactWriteItems` event-append spine as the principal-upsert flow. There is **no promotion-create HTTP API in this slice** — the `PrincipalEventStore::put_promotion` trait method exists and is exercised by tests, but nothing routes to it; promotions are seeded store-level only (e.g. a raw `put-item` against the `PROMO#{resource_type}#{native_id}` item shape above).

### `DELETE /api/v1/organizations/{org_id}/promoted-resources/{resource_type}/{native_id}`

1. `resource_type` and `native_id` must each parse (`Segment`/`NativeId`) — 422 otherwise.
2. Org must exist and be `Active` (404 / 409, same gate as every other org-scoped handler).
3. Strongly-consistent read of the promotion:
   - Absent (never existed, or a concurrent delete already won the race) — `204 No Content` with the current revision in `X-Fg-Revision`, body empty. Nothing is appended — this is D7's idempotent no-op rule.
   - Present — atomically (`TransactWriteItems`) appends a `resource.tombstoned` event and hard-deletes the `PROMO#...` state item. Responds `200` with `{"fgrn": "...", "revision": <u64>}` and `X-Fg-Revision`.
4. The read-then-tombstone window is race-safe: the transactional delete is conditioned on `attribute_exists(pk)`, so a lost race still surfaces as the `204` no-op path rather than a spurious error.

### `GET /api/v1/organizations/{org_id}/promoted-resources?type={t}&after={id}&limit={n}`

Cursor-based reconciliation page over one org's promotions of a given `resource_type`, ascending by `native_id`.

- `type` is required — missing is `400 {"error": "type query parameter is required"}`; invalid is `400 {"error": "invalid type"}`.
- `after` is an optional exclusive-start `native_id` cursor; `limit` defaults to 100, clamped to 1000 (shares `clamp_limit`/`DEFAULT_LIMIT`/`MAX_LIMIT` with the events endpoint, hoisted into `handlers/mod.rs`).
- `X-Fg-Min-Revision` guard (same semantics as the events endpoint, reusing `handlers/min_revision.rs`): `412 Precondition Failed` with `{"error": "revision_behind", "current_revision": <u64>, "min_revision": <u64>}` if the org's log is behind the requested revision.
- Response: `{"promotions": [{"fgrn": "...", "native_id": "..."}, ...], "next_after": <string|null>, "revision": <u64>}` plus `X-Fg-Revision`. `next_after` is the last page entry's `native_id`, or `null` on an empty page.
- Order of checks: parse query params → parse `X-Fg-Min-Revision` → org existence/Active check → min-revision guard → page query → respond.

### Authorization

`cp:resource:tombstone` and `cp:promotion:list` map to Cedar actions `cp-resource-tombstone` / `cp-promotion-list` (both `Some("org_id")`, tenant-scoped). RBAC: `cp-promotion-list` is read-tier (`member` role, beside `cp-events-read`); `cp-resource-tombstone` is write-tier (`admin` role, beside `cp-principal-upsert`). Both operators in the shaping doc are machines (app backend tombstones, SDK reconciler lists), so `forgeguard.toml` also carries `machine-resource-tombstone` / `machine-promotion-list` Cedar permits mirroring `machine-events-read`.

## Trust (V4 of the event-log spine, D8/N10)

External verification of the event log: any consumer can recompute an envelope's canonical bytes and Ed25519-verify its signature using only the org's published public key — no store access, no private keys.

### `GET /api/v1/organizations/{org_id}/signing-keys`

Serves the org's event-signing public key(s), for external envelope verification. `200` with `{"keys": [{"key_id", "public_key"}]}` (empty list if no model event has ever been appended for that org); `404` unknown/deleted org — D10 relaxed this from an `Active`-only gate, so `Draft`/`Suspended`/`Deleting` orgs are readable too. No revision header — keys are not event-log state. This is distinct from `GET /organizations/{org_id}/keys` (`handlers/keys.rs`), which serves the org-plane's request-signing key list (verification-only, for incoming BYOC proxy requests); the signing-keys endpoint instead derives and serves the public half of the event-signing private key (`SK = EVENT_SIGNING_KEY`) described above. `PrincipalEventStore::list_signing_keys` (both the Dynamo and in-memory impls) derives the public PEM from the stored private key material — no separate public-key item is persisted.

`canonical_envelope_bytes(envelope, org_id)` (`forgeguard_authz_core::event`) reconstructs the exact same canonical byte string that `canonical_event_bytes(draft, org_id)` produces at append time, but from an `EventEnvelope` read back from storage or over HTTP — this byte-identity is what makes external, store-independent verification possible.

`cargo xtask control-plane verify-events --org-id <org> [--url <base>] [--after <n>] [--limit <n>]` externally verifies an org's event log purely over the public HTTP API: fetches `GET .../events` and `GET .../signing-keys`, recomputes canonical bytes, and Ed25519-verifies each envelope's signature, printing a per-event `seq=... kind=... key_id=... OK|FAIL (...)` line and exiting non-zero if any envelope fails.

### Authorization

`cp:signing-key:read` maps to the Cedar action `cp-signing-key-read` (`Some("org_id")`, tenant-scoped), read-tier (`member` role, beside `cp-promotion-list`). `forgeguard.toml` carries a `machine-signing-key-read` permit mirroring `machine-promotion-list`, since SDK consumers verifying envelopes are machines. **Not yet synced to the prod VP policy store** — `cargo xtask control-plane cedar sync` is a deployment step outside this slice.

## Time Travel (V5 of the event-log spine, D9)

Revision-pinned historical reads: reconstruct an org's entity state as of any past revision by folding its event log, rather than storing versioned state items. No HTTP endpoint or xtask subcommand consumes this yet — it is a library-level capability (conformance tests are the only consumer), closing the `AuthzStore`/D9 trait-contract question with a JSON-shaped fold rather than a typed `EntitySlice` (arbitrary JSON principal docs can't build the typed model).

- `forgeguard_authz_core::fold_events(events: &[EventEnvelope], at: Revision) -> Result<FoldedState>` — pure. Folds a gap-free log prefix (seq 1, 2, 3, ...) up to `at`; events after `at` are ignored. Three event kinds are foldable: `principal.upserted` (insert/replace by `native_id`, requires the V5 payload wrapper above), `resource.promoted` (insert `(resource_type, native_id) → fgrn`), `resource.tombstoned` (remove that promotion). Any other kind, a missing wrapper (pre-V5 event), or a sequence gap is `Error::UnfoldableEvent { seq, reason }` — unfoldable events fail loudly rather than being silently skipped, since skipping would fabricate history. `at == 0` or `at` past the log's latest seq is `Error::UnknownRevision`.
- `FoldedState` — private fields, JSON-shaped: `principal(native_id) -> Option<&Value>` / `principals() -> &BTreeMap<String, Value>`, `promotion(resource_type, native_id) -> Option<&str>` / `promotions() -> &BTreeMap<(String, String), String>`, `revision() -> Revision`. `FoldedState::empty()` is revision 0, no entities.
- `PrincipalEventStore::fold_at(org_id, at: Option<Revision>) -> Result<FoldedState>` — default trait method (both the Dynamo and in-memory impls inherit it, `#[allow(dead_code)]` since no route calls it yet). `at = None` resolves to the org's latest revision, except an empty log returns `FoldedState::empty()` directly rather than erroring. Pages `events_after` in chunks of 100 and delegates to `fold_events`.

Pre-V5 events (appended before the identity wrapper existed) are permanently unfoldable — no backfill/migration is planned; dev logs are ephemeral and the prod log holds only QA events at this point.

## V3 of #102 — Active-org VP materialization

V3 replaces the V2 `todo!("V3")` Active branch with a real DDB + Verified Permissions write pipeline (pure pre-flight → DDB write → parent VP push → alphabetical fanout) under `crates/control-plane/src/{vp_client,handlers/groups}/`. Failure-mode taxonomy (F3 / F3' / F4), rollback metric, test scaffolding, and Risk #5 boundary live in [groups-v3.md](./groups-v3.md). The Active path runs end-to-end against `StubVpClient` today; no production org is Active until the saga (V4) ships.
