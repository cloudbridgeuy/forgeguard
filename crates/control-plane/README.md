# forgeguard_control_plane

ForgeGuard control plane API server. This is an **I/O binary crate**.

Serves per-organization proxy configuration to BYOC connected proxies. File-backed config store for development; DynamoDB in production.

Authentication and authorization are handled by the `forgeguard-axum` middleware layer.

**Auth-enabled mode** (`--jwks-url` + `--policy-store-id`): all API routes are protected. The middleware uses `VpPolicyEngine` backed by AWS Verified Permissions with `DefaultPolicy::Deny`. The Cedar project namespace is `forgeguard` (from `ProjectId::new("forgeguard")`). Route-to-action mapping uses the `cp` namespace — see the Authorization section below.

**Dev mode** (no `--jwks-url`): `StaticPolicyEngine(Allow)` with `DefaultPolicy::Passthrough`. All requests pass through without auth enforcement.

## Classification

**Binary / I/O** -- depends on `axum`, `tokio`, `tower-http`, `forgeguard-axum`, file I/O.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check -- returns `{"status": "ok"}` |
| `GET` | `/metrics` | Prometheus metrics (anonymous, no auth) |
| `POST` | `/api/v1/organizations` | Create organization (status: Draft) |
| `GET` | `/api/v1/organizations` | List organizations (paginated: `?offset=&limit=`) |
| `GET` | `/api/v1/organizations/{org_id}` | Get organization details (supports `If-None-Match` → `304 Not Modified`) |
| `PUT` | `/api/v1/organizations/{org_id}` | Update organization name and/or config — event-sourced, optional `X-Fg-If-Revision` |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | Per-org proxy config with ETag caching |
| `POST` | `/api/v1/organizations/{org_id}/keys` | Generate Ed25519 signing key |
| `GET` | `/api/v1/organizations/{org_id}/keys` | List signing keys for an org |
| `DELETE` | `/api/v1/organizations/{org_id}/keys/{key_id}` | Revoke a signing key |
| `POST` | `/api/v1/organizations/{org_id}/groups` | Create a group (V2) |
| `GET` | `/api/v1/organizations/{org_id}/groups` | List groups, sorted by name (V2) |
| `GET` | `/api/v1/organizations/{org_id}/groups/{name}` | Get a group (V2) |
| `PUT` | `/api/v1/organizations/{org_id}/groups/{name}` | Update a group — event-sourced, optional `X-Fg-If-Revision` (#113 V4) |
| `DELETE` | `/api/v1/organizations/{org_id}/groups/{name}` | Delete a group — event-sourced, optional `X-Fg-If-Revision` (#113 V4) |

There is no `DELETE /api/v1/organizations/{org_id}` — org deletion isn't supported on the event log yet; the route falls through to Axum's default `405`.

### Response Codes (proxy-config)

| Code | Meaning |
|------|---------|
| 200 | Config returned with `ETag` header |
| 304 | Config unchanged (`If-None-Match` matched) |
| 404 | Organization not found |

### Groups sub-resource (V2 + V3)

Groups are RBAC role definitions stored per-org. Full request/response shapes and
validation rules are defined in the design doc (§A.1 / §B.x):
[`.claude/plans/2026-04-30-issue-102-cp-groups-v2/v2-plan.md`](../../.claude/plans/2026-04-30-issue-102-cp-groups-v2/v2-plan.md).
The V3 implementation plan lives at
[`.claude/designs/issue-102-v3-implementation-plan.md`](../../.claude/designs/issue-102-v3-implementation-plan.md).

**Error codes:**

| Code | Meaning |
|------|---------|
| 201 | Group created; `ETag` header included |
| 200 | Group updated; `ETag` header included |
| 204 | Group deleted |
| 404 | Group or org not found |
| 409 | Conflict — group name already exists on create |
| 412 | Precondition Failed — stale `X-Fg-If-Revision` on PUT/DELETE (#113 V4) |
| 422 | Unprocessable Entity — validation error (bad name, empty allow, bad action format, etc.) |
| 500 | Inconsistent State — F-append compensation failed (VP-revert failed after a failed event append) |
| 503 | VP Push Failed — F-VP (parent push failed) or F-VP-mid (mid-fanout failure on UPDATE) |

**Caveats:**

- `PUT` and `DELETE` accept an optional `X-Fg-If-Revision` header; a stale
  value returns `412`, omitting it skips the check (see
  [`.claude/context/groups-v3.md`](../../.claude/context/groups-v3.md)).
- `DELETE` pre-checks for live memberships and inheriting groups; either
  blocks deletion with an appropriate error.

#### V3: Active-org VP materialization

When an org is in `OrgStatus::Active` (config carries a `vp_store_id`), the
group write handlers materialise the compiled Cedar permit into the org's
Verified Permissions policy store as part of the same request. The full
pipeline (DDB write → VP parent push → alphabetical fanout), failure-mode
taxonomy (F3 / F3' / F4 with status codes and body shapes), the
`forgeguard_cp_group_rollback_failed_total` metric, the `vp_client` module
shape, and the test scaffolding are documented in
[`.claude/context/groups-v3.md`](../../.claude/context/groups-v3.md).

#### Storage layout

Groups share the org's DynamoDB partition (`PK=ORG#{org_id}`):

Top-level DynamoDB attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `PK` | `S` | `ORG#{org_id}` — same partition as the org `META` row |
| `SK` | `S` | `GROUP#{name}` — sort key prefix distinguishes group rows from `META` |
| `config` | `S` | JSON-serialized `RbacEntry` (`name`, `description?`, `inherits`, `allow`, `tenant_scoped`) |
| `etag` | `S` | Content-addressed etag (xxHash64 of canonical entry JSON, quoted) |

The full entry shape encoded inside `config`:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Group name (mirrors the SK suffix) |
| `description` | string? | Optional human-readable description |
| `inherits` | list of strings | Parent group names |
| `allow` | list of strings | Directly granted actions (`{namespace}:{action}` format) |
| `tenant_scoped` | bool | When `true`, Cedar permit appends a tenant-equality clause |

`etag` is a separate top-level attribute so it can be used in DynamoDB condition
expressions without deserialising `config`.

#### Authorization

Groups CRUD is authorised via four `cp-group-*` actions in the `cp` namespace.
The role mapping mirrors the CP-wide RBAC model in `forgeguard.toml`:

| Role | Actions |
|------|---------|
| `member` | `cp:group:read` |
| `admin` | `cp:group:create`, `cp:group:update`, `cp:group:delete` (inherits `member`) |
| `owner` | inherits all from `admin` |

Declared in `forgeguard.toml` `[[policies]]` `allow` arrays; apply with
`cargo xtask control-plane cedar sync`. See
[`.claude/plans/2026-05-13-issue-102-cp-groups-v6/v6-plan.md`](../../.claude/plans/2026-05-13-issue-102-cp-groups-v6/v6-plan.md)
for V6 implementation details.

#### Round-trip parity

`crates/control-plane/src/handlers/tests/groups_round_trip.rs` proves that
the `forgeguard.toml` RBAC role definitions survive a full HTTP round-trip
without information loss. The fixture parses the `[[policies]]` entries into
`Vec<RbacEntry>`, POSTs each as a group to a Draft test org via the in-memory
store, GETs them back, converts to `Vec<RbacEntry>`, and asserts `toml::Value`
equality against the canonical source. This catches any serialization drift
between the `RbacEntry` type, the `GroupResource` wire shape, and the TOML
representation before it can diverge silently.

For fast iteration:

```sh
cargo test -p forgeguard_control_plane handlers::tests::groups_round_trip
```

## Quick Start

A test config with two orgs (`org-acme`, `org-globex`) is included at
`examples/control-plane/orgs.test.json`. No real AWS resources needed.

### 1. Start the control plane

```sh
# Terminal 1 -- start the control plane
cargo run -p forgeguard_control_plane -- \
  --config examples/control-plane/orgs.test.json

# Terminal 2 -- test endpoints
# Health check -> 200
curl -s http://localhost:3001/health | jq .

# Fetch org config -> 200 + ETag
curl -si http://localhost:3001/api/v1/organizations/org-acme/proxy-config

# Unknown org -> 404
curl -si http://localhost:3001/api/v1/organizations/org-unknown/proxy-config

# ETag match -> 304 (paste the ETag from the 200 response above)
curl -si \
  -H 'If-None-Match: "<paste-etag>"' \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config
```

### 2. Key Management

Generate, list, and revoke Ed25519 signing keys for outbound request signing.

```sh
# Generate a new signing key -> 201
# The private key is returned ONLY on creation -- store it securely.
curl -s -X POST \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys | jq .

# List signing keys -> 200 (public metadata only, no private keys)
curl -s \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys | jq .

# Revoke a signing key -> 204 (idempotent -- also 204 for nonexistent keys)
curl -s -X DELETE \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/keys/key-abc123
```

### 3. With your own orgs

For real AWS resources, copy the sample and fill in your values:

```sh
cp examples/control-plane/orgs.sample.json orgs.json
# Edit orgs.json -- add your project ID, upstream URL, routes, etc.

cargo run -p forgeguard_control_plane -- --config orgs.json
```

The `orgs.json` file is gitignored (contains AWS resource IDs).

### 4. Optimistic locking — revision tokens (#113 V1)

Org and group mutations are event-sourced. `PUT`/`DELETE` no longer accept
`If-Match`/`ETag` for write-side concurrency control — that's replaced by an
optional `X-Fg-If-Revision: <u64>` header:

- `GET /api/v1/organizations/{org_id}/proxy-config` returns the current `ETag`
  for **read-side** conditional GET only (no write semantics).
- `GET /api/v1/organizations/{org_id}` supports `If-None-Match`: returns
  **304 Not Modified** when the stored etag matches (or org is Configured and
  `If-None-Match: *` is sent); returns **200** with full body otherwise.
- `PUT /api/v1/organizations/{org_id}` accepts an optional
  `X-Fg-If-Revision: <u64>` header. When present, the write is conditioned on
  it matching the org's current revision; a mismatch returns
  **412 Precondition Failed** with
  `{"error": "revision_mismatch", "current_revision", "expected_revision"}`
  and an `X-Fg-Revision` header carrying the current revision. Omitting the
  header skips the check.
- A semantically-identical `PUT` (same payload, ignoring `updated_at`) is a
  no-op: `200` with the current revision, no event appended, no revision
  check performed.
- On success, the response carries the new revision in both the
  `X-Fg-Revision` header and the JSON body's `revision` field.
- Group `PUT`/`DELETE` use the same `X-Fg-If-Revision` model (#113 V4) — see
  [`.claude/context/groups-v3.md`](../../.claude/context/groups-v3.md).
- There is no `DELETE /api/v1/organizations/{org_id}`.

```sh
curl -is -H 'x-api-key: test-key' \
  -H 'content-type: application/json' \
  -X PUT http://localhost:3001/api/v1/organizations/org-acme \
  -d '{"config": { ... }}'
# 200 OK, X-Fg-Revision: <new revision> header on the response.

curl -is -H 'x-api-key: test-key' -H 'X-Fg-If-Revision: 3' \
  -H 'content-type: application/json' \
  -X PUT http://localhost:3001/api/v1/organizations/org-acme \
  -d '{"config": { ... }}'
# 200 OK on match, 412 Precondition Failed with a fresh X-Fg-Revision on mismatch.
```

Conditional GET — skip re-downloading an unchanged org config:

```sh
ETAG=$(curl -si \
  -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme \
  | awk 'tolower($1) == "etag:" {print $2}' | tr -d '\r')

curl -is \
  -H 'x-api-key: test-key' \
  -H "If-None-Match: $ETAG" \
  http://localhost:3001/api/v1/organizations/org-acme
# -> HTTP/1.1 304 Not Modified
```

### 5. Metrics

The control plane exposes Prometheus metrics on `GET /metrics` (anonymous, no
auth), including `forgeguard_cp_group_rollback_failed_total{stage="parent"|"fanout"}`
— bumped when a group write's VP-revert compensation fails after a failed
event append (see [`.claude/context/groups-v3.md`](../../.claude/context/groups-v3.md)).

### CLI Options

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

## Config File Format

JSON file mapping `org_id` to its organization entry. Each entry has a `name` (display name) and a nested `config` object (`OrgConfig`) with a date-based `version` field:

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

At load time, each org entry is parsed into an `Organization` domain entity (from `forgeguard_core`), paired with the optional `OrgConfig`. The entry's `status` field selects the lifecycle state (defaults to `OrgStatus::Draft` when omitted); the V0 `configured.is_some() → Active` heuristic was dropped in V5 of issue #102 — entries that need to start `Active` must declare `"status": "active"` explicitly. The `Organization` entity tracks lifecycle state (8-variant `OrgStatus` enum) and timestamps.

Unknown fields in the config are ignored by serde, so older config files with extra fields will still parse.

## Authorization

When auth is enabled, every API request is authorized against AWS Verified Permissions using the `forgeguard` Cedar namespace (`ProjectId::new("forgeguard")`).

### Route-to-Action Mapping

Each route maps to a `namespace:entity:action` QualifiedAction in the `cp` namespace:

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
| `POST` | `/api/v1/organizations/{org_id}/groups` | `cp:group:create` |
| `GET` | `/api/v1/organizations/{org_id}/groups` | `cp:group:read` |
| `GET` | `/api/v1/organizations/{org_id}/groups/{name}` | `cp:group:read` |
| `PUT` | `/api/v1/organizations/{org_id}/groups/{name}` | `cp:group:update` |
| `DELETE` | `/api/v1/organizations/{org_id}/groups/{name}` | `cp:group:delete` |

### PrincipalKind Routing

The Cedar principal entity type is determined by the `PrincipalKind` on the resolved `Identity`:

- Cognito JWT (`Authorization: Bearer`) → `PrincipalKind::User` → Cedar entity `forgeguard::user`
- Ed25519 signed request (BYOC proxy) → `PrincipalKind::Machine` → Cedar entity `forgeguard::Machine`

Machine principals carry an `org_id` attribute and have no group parents. User principals may carry group memberships.

### Memory Mode Limitation

`--store=memory` cannot use `VpPolicyEngine` — no DynamoDB client is available for key lookup, so `StaticPolicyEngine(Allow)` is used instead, even when `--jwks-url` is provided.

## Membership Model

Per-user organization roles live in DynamoDB, not in JWT claims. Each
membership is a single item keyed by the user's Cognito `sub` and the
organization ID:

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `PK` | `USER#{sub}` | Partition by user |
| `SK` | `ORG#{org_id}` | One item per (user, org) pair |
| `user_id` | `{sub}` | Convenience duplicate for GSI lookups |
| `org_id` | `{org_id}` | Convenience duplicate for GSI lookups |
| `groups` | `L[S]` | Group roles within this organization |
| `joined_at` | ISO-8601 string | Creation timestamp |

An **inverted GSI** (`SK` as partition key, `PK` as sort key) supports
listing every user in a given organization (`ORG#{org_id}` → all `USER#*`).

At request time the proxy's Phase 5b reads the `X-ForgeGuard-Org-Id` header,
calls the `MembershipResolver` (`GetItem` on `PK=USER#{sub}, SK=ORG#{org_id}`),
and either replaces the `Identity` with a tenant+groups-enriched copy or
rejects the request (`403` when the user is not a member, `400` when the
header is missing on a credential-required route). A DynamoDB I/O failure or
malformed `groups` attribute causes `DynamoMembershipResolver` to return
`Err(ResolveError)`, which the pipeline maps to HTTP `500 Internal Server
Error`; the error detail is logged via `tracing::warn!` in the shell and never
leaks to the response body.

`DynamoMembershipResolver` (in `membership_store.rs`) is wired into the
control plane's `IdentityChain` whenever both `--jwks-url` and
`--store=dynamodb` are configured.

## Domain Model

The control plane uses the `Organization` entity from `forgeguard_core` to represent each org. File-loaded orgs default to `OrgStatus::Draft`; entries can declare `"status": "active"` to start Active (V5 of issue #102 dropped the V0 `configured.is_some() → Active` heuristic). The `OrgStore` trait is object-safe via `#[async_trait]`; the runtime carries an `Arc<dyn OrgStore>` and handlers extract it through Axum state:

| Type | Location | Purpose |
|------|----------|---------|
| `Organization` | `forgeguard_core` | Domain entity with status lifecycle, timestamps |
| `OrgConfig` | `config.rs` | Versioned proxy configuration (replaces old `OrgProxyConfig`) |
| `Etag` | `etag.rs` | Typed ETag value (`pub(crate)` newtype over `String`). Constructed via `Etag::try_new(raw)` (rejects empty strings); `as_str()` exposes the raw value. Read-side only — drives conditional GET. Companions `IfMatch` and `IfNoneMatchResult` cover the RFC 7232 conditional-GET state machine in pure code. |
| `OrgRecord` | `store.rs` | Pairs `Organization` + `OrgConfig` + precomputed `Etag` |
| `OrgStore` trait | `store.rs` | Object-safe async trait for org storage backends |
| `InMemoryOrgStore` | `store.rs` | In-memory HashMap behind `tokio::sync::RwLock` |
| `DynamoOrgStore` | `dynamo_store.rs` | DynamoDB-backed organization store for production |

## ETag Caching (read-side only)

Every org config response includes an `ETag` header (xxHash64 of the canonical JSON). Proxies send `If-None-Match` on subsequent polls and receive `304 Not Modified` when nothing has changed, saving bandwidth. This is a **read-side** optimization only — org and group writes use revision tokens (`X-Fg-If-Revision`), not `ETag`/`If-Match`.

ETag values are represented end-to-end as the typed `Etag` newtype (see `etag.rs`). This eliminates raw-string comparisons in handlers and store implementations — the companion pure functions (`parse_if_match`, `check_if_none_match`) centralise all comparison logic and guard against accidental equality tests on unquoted strings.

## Dependencies

| Crate | Role |
|-------|------|
| `forgeguard_core` (pure) | `OrganizationId`, `Organization`, `OrgStatus`, `DefaultPolicy` |
| `forgeguard-axum` | Auth middleware (identity + policy) |
| `axum` | HTTP framework |
| `tower-http` | Middleware (tracing, timeout) |
| `xxhash-rust` | ETag computation |
| `chrono` | Timestamps for `Organization` entity |
| `aws-sdk-dynamodb` | DynamoDB client for `DynamoOrgStore` |
| `aws-config` | AWS SDK configuration loading |
