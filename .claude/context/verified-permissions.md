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

## CLI Commands

- `forgeguard policies validate` — pure local validation, no AWS calls
- `forgeguard policies sync` — validate then push schema + policies to VP (`--dry-run`)
- `forgeguard policies test` — run authorization tests against live VP

## Config Sections

- `[aws]` — optional region/profile. Precedence: CLI flag > env var > config > SDK default.
- `[authz]` — `policy_store_id`, `cache_ttl_secs`, `cache_max_entries` (no `aws_region`).
- `[[policy_tests]]` — inline authorization test scenarios.
- `[schema.entities]` — optional entity relationships and attributes (commented out for MVP).

## Infrastructure

- CDK stack `verified-permissions-stack.ts` creates policy store (OFF validation mode) + Cognito identity source.
- `cargo xtask dev setup --vp` deploys the stack and writes `PolicyStoreId` to config.
- `cargo xtask dev setup --all` runs both Cognito and VP setup.
