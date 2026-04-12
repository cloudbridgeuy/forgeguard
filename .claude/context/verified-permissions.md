# Verified Permissions Integration

## Overview

ForgeGuard uses AWS Verified Permissions (VP) as the authorization engine. The proxy calls `IsAuthorized` at runtime; the CLI manages schema and policies at dev/deploy time.

## Action Format

Canonical three-part format: `namespace:entity:action` (e.g., `todo:list:read`).

| Surface | Format | Example |
|---|---|---|
| Action | `namespace:entity:action` | `todo:list:read` |
| FGRN | `...namespace:entity:id` | `fgrn:todo-app:acme-corp:todo:list:list-001` |
| Cedar entity type | `namespace__entity` | `todo__list` |
| Action pattern | `namespace:entity:action` | `todo:list:*` |

## Cedar Type System

Types in `forgeguard_core` encode Cedar IDENT validity:

- **`CedarIdent`** — validated `[_a-zA-Z][_a-zA-Z0-9]*`. Constructed from `Segment` via `to_cedar_ident()` (lossless `-` to `_`).
- **`CedarEntityType`** — `{namespace}__{entity}`. Double underscore is unambiguous because `Segment` forbids underscores.
- **`CedarNamespace`** — VP namespace from `ProjectId::to_cedar_ident()`.

IAM entities (`user`, `group`) use bare names without namespace prefix.

## VP Architecture Decisions

- **`IsAuthorized` only** — no `IsAuthorizedWithToken`. The proxy validates JWTs via `forgeguardauthn`; re-validation in VP wastes latency. Cache keys use claim-derived values.
- **No entity store** — VP stores schema and policies only. Entity data (user-in-group hierarchy) is passed inline via the `entities` parameter on each `IsAuthorized` call.
- **Single namespace per policy store** — derived from `ProjectId`. ForgeGuard namespaces flatten into Cedar entity types using `__` separator.
- **Cache key includes groups** — format: `{user_id}|{action}|{resource}|{tenant}|{sorted_groups}` to avoid collisions when the same user has different group memberships.

## Cedar Sync Engine

The sync engine (`cargo xtask control-plane cedar`) manages the VP policy store declaratively from `forgeguard.toml`. It supports dual-dialect policies: RBAC roles compiled to Cedar with tenant scoping, and raw Cedar for patterns RBAC can't express.

### Commands

| Command | Purpose |
|---|---|
| `cargo xtask control-plane cedar status` | Show current VP store state |
| `cargo xtask control-plane cedar diff --config forgeguard.toml` | Preview changes (exit 0=clean, 1=pending) |
| `cargo xtask control-plane cedar sync --config forgeguard.toml` | Apply changes to VP |
| `cargo xtask control-plane cedar sync --config forgeguard.toml --dry-run` | Show plan without applying |

### VP API Quirks

These workarounds are baked into the sync engine. Knowing them prevents re-introducing the original bugs:

1. **No `name` field on CreatePolicyTemplate/CreatePolicy.** The SDK v1.110.0 exposes `.name()` on the builder, but VP rejects it with `ValidationException: Invalid input`. The sync engine encodes names as a `[name]` prefix in the `description` field and decodes on read. See `encode_name_in_description` / `decode_name_from_description` in `cedar_io.rs`.

2. **Actions require `appliesTo` blocks.** Schema actions defined as `"name": {}` (no `appliesTo`) are accepted by `PutSchema` but cause `ValidationException` when templates/policies reference them. The schema generator adds `appliesTo` with all entity types as both `principalTypes` and `resourceTypes`. See `generate_schema_json` in `schema.rs`.

3. **VP normalizes schema JSON.** `PutSchema` accepts pretty-printed JSON but `GetSchema` returns minified. The sync engine uses semantic JSON comparison (`serde_json::Value` equality) to avoid false diffs on every run. See `schemas_equal` in `sync.rs`.

### Sync Design

- **Idempotent:** second sync = no changes. Comparison is by name + statement content.
- **Update = delete + create:** VP has no update API; the engine deletes then recreates.
- **Ordering:** schema first → update-deletes → update-creates → new creates → standalone deletes.
- **Resource matching:** `[name]` prefix in description field (not VP `name` field).
- **Partial failure recovery:** re-run sync — already-applied actions become no-ops.

### Config Structure (`forgeguard.toml`)

The root `forgeguard.toml` is the control plane's own dogfooding authorization model:

- `[authz]` — `policy_store_id` (1Password reference or raw ID)
- `[schema]` — namespace, explicit actions, entity types with attributes
- `[tenant]` — principal/resource attribute names for RBAC tenant scoping
- `[[policies]]` — RBAC roles (`allow`, `inherits`) or raw Cedar (`type = "cedar"`, `body`)
- `[[templates]]` — Cedar templates with `?principal`/`?resource` slots

Actions from RBAC `allow` lists are auto-collected into the schema. Actions only in raw Cedar or templates must be listed in `[schema] actions`.

## CLI Commands

- `forgeguard policies validate` — pure local validation, no AWS calls
- `forgeguard policies sync` — validate then push schema + policies to VP (`--dry-run`)
- `forgeguard policies test` — run authorization tests against live VP

## Config Sections

- `[aws]` — optional region/profile. Precedence: CLI flag > env var > config > SDK default.
- `[authz]` — `policy_store_id`, `cache_ttl_secs`, `cache_max_entries` (no `aws_region`).
- `[[policy_tests]]` — inline authorization test scenarios.
- `[schema.entities]` — entity relationships and attributes for Cedar schema generation.

## Infrastructure

- CDK stack `verified-permissions-stack.ts` creates policy store (OFF validation mode) + Cognito identity source.
- Control-plane infrastructure is managed via `cargo xtask control-plane infra` subcommands (deploy, diff, destroy, status).
