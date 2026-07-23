# Verified Permissions Integration

> This file covers two unrelated things sharing a filename for historical reasons: (1) proxy-side AWS Verified Permissions (VP) integration — still live, unchanged, covers `crates/proxy`, `crates/cli`, `crates/authz` — and (2) the control-plane RBAC role model, which used to be pushed to a CP-dogfood VP store but is now compiled entirely in-process. **All Cedar-sync/VP-push machinery on the control-plane side is fully retired (#117 V3).** There is no VP client, no `cargo xtask control-plane cedar`, and no CP-dogfood policy store anymore. Section headers below are marked accordingly.

## Overview (proxy-side, unchanged)

ForgeGuard uses AWS Verified Permissions (VP) as the authorization engine for the proxy. The proxy calls `IsAuthorized` at runtime; the CLI manages schema and policies at dev/deploy time.

## Action Format (proxy-side, unchanged)

Canonical three-part format: `namespace:entity:action` (e.g., `todo:list:read`).

| Surface | Format | Example |
|---|---|---|
| Action | `namespace:entity:action` | `todo:list:read` |
| FGRN | `...namespace:entity:id` | `fgrn:todo-app:acme-corp:todo:list:list-001` |
| Cedar entity type | `namespace__entity` | `todo__list` |
| Action pattern | `namespace:entity:action` | `todo:list:*` |

## Cedar Type System (proxy-side, unchanged)

Types in `forgeguard_core` encode Cedar IDENT validity:

- **`CedarIdent`** — validated `[_a-zA-Z][_a-zA-Z0-9]*`. Constructed from `Segment` via `to_cedar_ident()` (lossless `-` to `_`).
- **`CedarEntityType`** — `{namespace}__{entity}`. Double underscore is unambiguous because `Segment` forbids underscores.
- **`CedarNamespace`** — VP namespace from `ProjectId::to_cedar_ident()`.

IAM entities (`user`, `group`) use bare names without namespace prefix.

## VP Architecture Decisions (proxy-side, unchanged)

- **`IsAuthorized` only** — no `IsAuthorizedWithToken`. The proxy validates JWTs via `forgeguardauthn`; re-validation in VP wastes latency. Cache keys use claim-derived values.
- **No entity store** — VP stores schema and policies only. Entity data (user-in-group hierarchy) is passed inline via the `entities` parameter on each `IsAuthorized` call.
- **Single namespace per policy store** — derived from `ProjectId`. ForgeGuard namespaces flatten into Cedar entity types using `__` separator.
- **Cache key includes groups** — format: `{user_id}|{action}|{resource}|{tenant}|{sorted_groups}` to avoid collisions when the same user has different group memberships.

## Control-plane Role Model (historical — no longer VP-backed)

The CP ships three RBAC roles plus a single machine permit. Each human role maps 1:1 to a Cognito group claim (`cognito:groups`); membership is data resolved per-request from DynamoDB (`PK=USER#{sub}, SK=ORG#{org_id}`), not from any policy store.

| Role | Inherits | Adds |
|---|---|---|
| `member` | — | `cp-organization-read`, `cp-key-read`, `cp-config-read`, `cp-group-read` |
| `admin` | `member` | org create/update, member invite/remove/change-role, `cp-config-write`, key generate/revoke/rotate, `cp-group-create`, `cp-group-update`, `cp-group-delete` |
| `owner` | `admin` | `cp-member-promote-owner` |

Canonical source: the `[[policies]]` `allow` arrays in `forgeguard.toml` at the workspace root. Since #117 V1, this same file is compiled to Cedar policy text at control-plane build time (`forgeguard_authz_core::compile_cp_model`, invoked from `crates/control-plane/build.rs`) and embedded into the `CpCedarEngine` that decides every `cp:*` request in-process — no VP call on the request path, ever. Since #117 V3, there is no VP-backed fallback path at all: the CP-dogfood VP store, `cargo xtask control-plane cedar sync`, and the CDK `VerifiedPermissionsStack` have all been deleted.

The compiler emits one `permit(principal in forgeguard::Group::"<role>", ...)` per role with `when { principal.org_id == resource.org_id }` auto-appended for tenant scoping. No per-user VP instantiation runs at invitation time — group membership alone grants the permit.

**Resource `org_id` provenance.** The resource entity's `org_id` attribute is the resource's *owning* org, resolved from `ResourceRef::org_source()`: control-plane org-scoped routes (`/organizations/{org_id}/...`) carry `ResourceOrgSource::OwnId`, so `org_id` is the `{org_id}` path param; proxy resources and CP collection endpoints use the `RequestTenant` default. This is what makes the tenant-scope clause meaningful — sourcing it from the `X-Fg-Org-Id` header instead (the pre-fix bug) made the clause a no-op and allowed cross-org access.

The single non-RBAC permit is `machine-proxy-config-read`, a raw Cedar policy that lets `Machine` principals (Ed25519-signed) read their own org's proxy config and nothing else.

### Why owner is RBAC, not a template

`owner` is structurally tenant-shaped — same scoping the other two RBAC permits use, just a wider action list. Cedar templates earn their keep on per-resource scoping (e.g., "Bob is editor of *this specific* bookshelf"); `owner` has no per-resource axis to bind. Folding it into RBAC closed the only outstanding role-lifecycle gap (#42) without dragging in template-link CRUD that nothing currently consumes.

The broader question — whether ForgeGuard should expose Cedar templates as a customer-facing primitive for per-resource permissions — is tracked separately as #84 and waits on a real driver.

### Where the RBAC compiler lives (proxy/CLI + control-plane, shared pure code)

The pure RBAC → Cedar compiler (`compile_rbac_to_cedar`, `resolve_inherits`, `validate_cedar_ident`, `RbacEntry`, `TenantConfig`) lives in `forgeguard_authz_core::rbac`. It has two consumers: `crates/cli` for the proxy-side `forgeguard policies sync`/`validate` workflow described below, and `crates/control-plane/build.rs` (via `forgeguard_authz_core::compile_cp_model`), which compiles `forgeguard.toml` into the embedded `CpCedarEngine` at build time. There is no xtask-side Cedar tooling anymore — `cargo xtask control-plane cedar {status,diff,sync}` was deleted in #117 V3.

## CLI Commands (proxy-side, unchanged)

- `forgeguard policies validate` — pure local validation, no AWS calls
- `forgeguard policies sync` — validate then push schema + policies to VP (`--dry-run`)
- `forgeguard policies test` — run authorization tests against live VP

## Config Sections (proxy-side, unchanged)

- `[aws]` — optional region/profile. Precedence: CLI flag > env var > config > SDK default.
- `[authz]` — `policy_store_id`, `cache_ttl_secs`, `cache_max_entries` (no `aws_region`).
- `[[policy_tests]]` — inline authorization test scenarios.
- `[schema.entities]` — entity relationships and attributes for Cedar schema generation.
