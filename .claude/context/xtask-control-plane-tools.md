# xtask: Control Plane Manual QA Tools

The `cargo xtask control-plane` binary ships three subcommands that automate end-to-end manual QA against a deployed control plane: `seed`, `token`, and `curl`. They all share 1Password + AWS wiring and are designed to compose via pipes.

## `seed` — Reset organizations as Draft

Reads `xtask/seed.toml`, tears down prior fixtures, and re-seeds each declared org as `OrgStatus::Draft` with its RBAC roles and Cognito users. There is no Verified Permissions involvement anywhere in this flow — group writes are pure event-sourced appends (see [groups-v3.md](./groups-v3.md)), and the CP-dogfood VP store itself was deleted in #117 V3.

The command runs in three phases:

1. **Phase 0 (preflight, pure)** — `pure::preflight_validate` walks every declared org and, before any AWS call, validates `OrganizationId::new(org_id)`, `PoolId::try_new(cognito_user_pool_id)`, validates every declared user's attributes, validates each user's `GroupName`s, and validates the group inheritance graph (name regex, dangling inherit, cycles). A failure anywhere aborts the seed before Teardown or Re-seed touch AWS.
2. **Teardown** — scans the CP dashboard Cognito pool for usernames matching `org-{seeded_org_id_suffix}-*` (per `pure::is_seeded_username`), deletes those users, and deletes their `PK=USER#{sub}, SK=ORG#…` membership rows in DynamoDB. There is no VP-policy teardown sweep — that machinery (and the CP-dogfood VP store it targeted) was deleted in #117 V3.
3. **Re-seed** — `write_orgs` writes one DynamoDB org row per `[[organization]]` entry at `PK=ORG#{org_id}, SK=META` with `status=draft`. `write_groups` writes the validated GROUP rows. Finally `write_users` provisions each declared `[[organization.user]]` in Cognito (via `UserPoolClient`) and writes its `PK=USER#{sub}, SK=ORG#{org_id}` membership row in DynamoDB.

```bash
cargo xtask control-plane seed
cargo xtask control-plane seed --config path/to/custom-seed.toml
```

`xtask/seed.toml` ships with two orgs (`org-acme`, `org-globex`), each declaring `member`, `admin`, and `owner` roles whose action lists match `forgeguard.toml` byte-for-byte. Both orgs point `cognito_user_pool_id` at the prod dashboard pool (`us-east-2_Ge850AP5u`) — the per-org pool ids the file originally carried (`us-east-2_acme`/`us-east-2_globex`) were CDK-output placeholders for pools that were never deployed.

**Known limitation — user provisioning fails against the dashboard pool.** The pool is configured for email alias, which forbids email-format usernames, but `admin_create_user` (`crates/authn/src/user_pool/aws.rs`) passes the user's email as the Cognito username → `InvalidParameterException: Username cannot be of email format`. Seed's org/group phases complete; the user phase aborts. Teardown already expects `org-{suffix}-*` usernames, so the aligned fix is deriving a non-email username in the create path. Until then, provision users by hand (or reuse the existing `acme-*`/`globex-*` users) and write their membership rows directly: `PK=USER#{sub}, SK=ORG#{org_id}` with a `groups` string-list attribute.

### Seed groups schema

Each org declares its RBAC roles via `[[organization.group]]` entries. The shape mirrors `forgeguard_authz_core::RbacEntry` 1:1:

```toml
[[organization]]
org_id = "org-acme"
name = "Acme Corp"

[[organization.group]]
name = "member"                    # required, snake-case
description = "Read-only access"   # optional
allow = ["cp-organization-read"]   # action ids
# inherits = []                    # optional, defaults to []
# tenant_scoped = true             # optional, defaults to true

[[organization.group]]
name = "admin"
inherits = ["member"]
allow = ["cp-organization-update"]
```

Roles are validated against the same rules used by the live CP groups handler — invalid names, dangling inherits, and cycles all abort the seed before any DynamoDB write. The canonical RBAC content for V5 orgs is the `[[policies]]` blocks in `forgeguard.toml`; `forgeguard.toml` uses `[[policies]]` as the top-level key while `seed.toml` mirrors the same content under `[[organization.group]]`.

### Local DynamoDB Target

For local QA against `dynamodb-local` (started by `cargo xtask control-plane dev` — see [xtask-control-plane-dev.md](./xtask-control-plane-dev.md)), pass both flags:

```bash
cargo xtask control-plane seed \
  --dynamodb-endpoint http://127.0.0.1:<PORT> \
  --dynamodb-table forgeguard-orgs-dev
```

- Org and group rows are written to the local table; the prod 1Password lookup for the table name is skipped.
- Cognito teardown still talks to real AWS — there is no local emulator for it. The teardown phase is a no-op against a freshly-started local pool.
- Omit both flags to target prod (reads `op://forgeguard-prod/dynamodb/table-name`).
- Passing only one flag is a validation error.

## `token` — Fetch a JWT for a seeded user

Calls Cognito `AdminInitiateAuth` with the `AdminUserPasswordAuth` flow (enabled on the dashboard client via `infra/control-plane/lib/cognito-stack.ts`). Reads the user's password from 1Password.

```bash
# Pipe-friendly: prints raw id_token on stdout.
TOKEN=$(cargo xtask control-plane token --user acme-admin)

# Full JSON with access_token, expires_in, token_type.
cargo xtask control-plane token --user acme-admin --verbose
```

## `curl` — Send an Ed25519-signed HTTP request

Generates the machine-principal signature headers (`x-forgeguard-signature`, `x-forgeguard-timestamp`, `x-forgeguard-key-id`, `x-forgeguard-trace-id`) from a PEM private key and sends the request via `reqwest`. Useful for QA'ing the machine principal → embedded `cp:*` authorization flow without a real proxy.

```bash
cargo xtask control-plane curl \
    --key-id kid-abc123 \
    --private-key @key.pem \
    --org-id org-acme \
    --verbose \
    GET https://cp.forgeguard.dev/api/v1/organizations/org-acme/proxy-config
```

The canonical payload that the server recomputes and verifies against matches exactly: the `CanonicalPayload::new(&trace_id, timestamp, &identity_headers)` constructor uses the lowercase `x-forgeguard-org-id` header to match what the `http` crate normalises on the server side.

`--private-key` accepts either the PEM inline or a `@path` reference that is read from disk. The contents are `.trim()`-ed before handing to `SigningKey::from_pkcs8_pem`, so PEMs written by `jq -r .private_key > key.pem` (which appends a trailing newline that `pem-rfc7468` rejects as post-encapsulation whitespace) load cleanly.

## Shared Helpers

- `op::read_op(vault, item, field, op_account)` — one-shot 1Password read, used by `seed` (CP dashboard pool id, prod DynamoDB table name) and by `token` for the dashboard app-client id and per-user password.
- `op::store_in_op(...)` — one-shot 1Password write used by `infra deploy` and `lambda deploy`. Resolves the item title to an ID via `op item list` first: one match → edit by ID, zero → create then edit, multiple → hard error listing the duplicate IDs (creation is never triggered by an edit failure, so transient `op` errors can't spawn duplicate items). **No longer used by `seed`** (no users are created).
- `op::build_aws_config(profile, region)` — constructs an `aws_config::SdkConfig` with the requested profile and region.

## Environment Defaults

All three subcommands share these defaults:

| Flag | Env var | Default |
|------|---------|---------|
| `--env` | `FORGEGUARD_ENV` | `prod` (only valid value) |
| `--op-account` | `FORGEGUARD_OP_ACCOUNT` | `YYN6IHBFRRD5RCLU63J46WPKMA` |
| `--region` | `AWS_REGION` | `us-east-2` |
| `--profile` | `AWS_PROFILE` | `admin` |
