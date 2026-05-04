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
| `PUT` | `/api/v1/organizations/{org_id}` | Update organization name and/or config |
| `DELETE` | `/api/v1/organizations/{org_id}` | Delete organization |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | Per-org proxy config with ETag caching |
| `POST` | `/api/v1/organizations/{org_id}/keys` | Generate Ed25519 signing key |
| `GET` | `/api/v1/organizations/{org_id}/keys` | List signing keys for an org |
| `DELETE` | `/api/v1/organizations/{org_id}/keys/{key_id}` | Revoke a signing key |
| `POST` | `/api/v1/organizations/{org_id}/groups` | Create a group (V2) |
| `GET` | `/api/v1/organizations/{org_id}/groups` | List groups, sorted by name (V2) |
| `GET` | `/api/v1/organizations/{org_id}/groups/{name}` | Get a group (V2) |
| `PUT` | `/api/v1/organizations/{org_id}/groups/{name}` | Update a group — `If-Match` required (V2) |
| `DELETE` | `/api/v1/organizations/{org_id}/groups/{name}` | Delete a group — `If-Match` required (V2) |

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
| 412 | Precondition Failed — `If-Match` etag mismatch on PUT/DELETE |
| 422 | Unprocessable Entity — validation error (bad name, empty allow, bad action format, etc.) |
| 500 | Inconsistent State — F3' (DDB committed, VP push failed, rollback also failed) |
| 503 | VP Push Failed — F3 (parent push failed, DDB rolled back) or F4 (mid-fanout failure on UPDATE) |

**Caveats:**

- `PUT` and `DELETE` require an `If-Match` header; omitting it returns `412`.
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

**`is_declared_group` predicate:** exposed as
`OrgStore::is_declared_group(org_id, name) -> Result<bool>`. Consumed by
`POST /api/v1/organizations/{org_id}/users` (issue #100) to validate that a
group name referenced in a user membership request is an actual declared group.

#### V4 — Saga handoff stub

`crates/control-plane/src/handlers/groups/saga.rs` exposes
`materialize_groups_to_vp(MaterializeParams)`: a single async function that
walks every declared group for an org, compiles each via
`forgeguard_authz_core::groups_to_permits`, and pushes each resulting
`NamedPermit` into the org's VP store using the V3 `push_permit`
delete-then-create primitive. Permits push **alphabetically by group name**
for test reproducibility — Cedar permits are independent so order has no
semantic effect.

Failure modes (see `MaterializeError`):

| Variant | Stage | When |
|---|---|---|
| `ListGroupsFailed(Error)` | pre-walk | `OrgStore::list_groups` failed |
| `CompileFailed { compile }` | pure compile | `groups_to_permits` rejected an entry; `compile.name` identifies it |
| `PushFailed { name, source }` | VP push | `push_permit` failed for `cp-rbac-{group}` |

V4 deliberately ships **no rollback, no Prometheus counter, no resume
state**: at the first push failure the function returns and earlier
permits remain in VP. Retry semantics, observability, and partial-failure
recovery are the responsibility of the future saga ticket that owns the
Draft → Active transition. The stub exists now so that ticket can call
into a stable orchestration boundary; correctness is covered by
`handlers::tests::groups_saga` against the in-memory `OrgStore` and
`StubVpClient`.

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

### 4. Optimistic locking (issue #56)

`PUT /api/v1/organizations/{org_id}` supports RFC 7232 `If-Match` optimistic locking
on the organization's proxy config:

- `GET /api/v1/organizations/{org_id}/proxy-config` returns the current `ETag`.
- `GET /api/v1/organizations/{org_id}` supports `If-None-Match`: returns
  **304 Not Modified** when the stored etag matches (or org is Configured and
  `If-None-Match: *` is sent); returns **200** with full body otherwise.
- `PUT /api/v1/organizations/{org_id}` with `If-Match: <etag>` writes only if
  the stored etag still matches; otherwise it returns **412 Precondition Failed**
  with the current etag and a `reason` field in the body (mirrors the
  `forgeguard_control_plane_put_org_412_total{reason=...}` Prometheus label).
- Pass `If-Match: *` to write against any current representation — matches
  Configured orgs unconditionally, fails closed (412) on Draft orgs.
- `PUT` without `If-Match` preserves today's last-write-wins behaviour so that
  CLI and script callers are not broken.
- Name-only `PUT` bodies (no `config` field) skip the etag check — names are
  cosmetic and not covered by optimistic locking (wildcard included).
- `POST /api/v1/organizations` with a `config` field returns the new org's
  `ETag` header in the 201 response, so first-update callers can skip a
  pre-flight GET.

ForgeGuard-owned callers (`forgeguard_cli`, dashboard, xtask) should send
`If-Match` on every PUT. Absence is tolerated only for ad-hoc external callers.

```sh
ETAG=$(curl -s -I -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config \
  | awk 'tolower($1) == "etag:" {print $2}' | tr -d '\r')

curl -is -H 'x-api-key: test-key' -H "If-Match: $ETAG" \
  -H 'content-type: application/json' \
  -X PUT http://localhost:3001/api/v1/organizations/org-acme \
  -d '{"config": { ... }}'
# 200 OK on match, 412 Precondition Failed on mismatch.
```

To write unconditionally against any configured org:

```sh
curl -is -H 'x-api-key: test-key' -H 'If-Match: *' \
  -H 'content-type: application/json' \
  -X PUT http://localhost:3001/api/v1/organizations/org-acme \
  -d '{"config": { ... }}'
# 200 OK for Configured orgs, 412 for Draft orgs.
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

Both backends (`--store=memory` and `--store=dynamodb`) enforce `If-Match`
identically as of V3. Exercise the Dynamo path locally via
`cargo xtask control-plane test`.

### 5. Metrics

The control plane exposes Prometheus metrics on `GET /metrics` (anonymous, no
auth). 412 responses are counted with a reason label:

```sh
curl -s http://localhost:3001/metrics | grep put_org_412_total
# forgeguard_control_plane_put_org_412_total{reason="draft_fail_closed"} 0
# forgeguard_control_plane_put_org_412_total{reason="stale_etag"} 0
# forgeguard_control_plane_put_org_412_total{reason="wildcard_on_draft"} 0
```

The `update_org` tracing span also carries a `precondition_reason` attribute
mirroring the `reason` label, enabling per-request attribution via structured
logs without adding an `org_id` label to the counter (cardinality risk).

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

At load time, each org entry is parsed into an `Organization` domain entity (from `forgeguard_core`) with `OrgStatus::Active` status, paired with the `OrgConfig`. The `Organization` entity tracks lifecycle state (8-variant `OrgStatus` enum) and timestamps.

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
| `DELETE` | `/api/v1/organizations/{org_id}` | `cp:organization:delete` |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | `cp:proxy-config:read` |
| `POST` | `/api/v1/organizations/{org_id}/keys` | `cp:key:generate` |
| `GET` | `/api/v1/organizations/{org_id}/keys` | `cp:key:read` |
| `DELETE` | `/api/v1/organizations/{org_id}/keys/{key_id}` | `cp:key:revoke` |

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

The control plane uses the `Organization` entity from `forgeguard_core` to represent each org. File-loaded orgs are created with `OrgStatus::Active`. The `OrgStore` trait is async with generic handlers (no `dyn` dispatch):

| Type | Location | Purpose |
|------|----------|---------|
| `Organization` | `forgeguard_core` | Domain entity with status lifecycle, timestamps |
| `OrgConfig` | `config.rs` | Versioned proxy configuration (replaces old `OrgProxyConfig`) |
| `Etag` | `etag.rs` | Typed ETag value (`pub(crate)` newtype over `String`). Constructed via `Etag::try_new(raw)` (rejects empty strings); `as_str()` exposes the raw value. Companions `IfMatch`, `ResolvedIfMatch`, `EtagCheck`, and `IfNoneMatchResult` cover the full RFC 7232 optimistic-locking state machine in pure code. |
| `OrgRecord` | `store.rs` | Pairs `Organization` + `OrgConfig` + precomputed `Etag` |
| `OrgStore` trait | `store.rs` | Async trait for org storage backends |
| `InMemoryOrgStore` | `store.rs` | In-memory HashMap behind `tokio::sync::RwLock` |
| `DynamoOrgStore` | `dynamo_store.rs` | DynamoDB-backed organization store for production |
| `AnyOrgStore` | `store.rs` | Dispatch enum for runtime store selection (`Memory` / `DynamoDb`) |

## ETag Caching

Every org config response includes an `ETag` header (xxHash64 of the canonical JSON). Proxies send `If-None-Match` on subsequent polls and receive `304 Not Modified` when nothing has changed, saving bandwidth.

ETag values are represented end-to-end as the typed `Etag` newtype (see `etag.rs`). This eliminates raw-string comparisons in handlers and store implementations — the companion pure functions (`parse_if_match`, `check_etag`, `check_if_none_match`) centralise all comparison logic and guard against accidental equality tests on unquoted strings.

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
