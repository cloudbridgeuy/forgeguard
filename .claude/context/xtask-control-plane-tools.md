# xtask: Control Plane Manual QA Tools

The `cargo xtask control-plane` binary ships three subcommands that automate end-to-end manual QA against a deployed control plane: `seed`, `token`, and `curl`. They all share 1Password + AWS wiring and are designed to compose via pipes.

## `seed` — Seed organizations and test users

Reads `xtask/seed.toml` and provisions both ends of the authorization flow:

- **DynamoDB:** creates `Organization` records using the shared `orgs_schema()` from `infra/control-plane/schema/forgeguard-orgs.json`. Each org gets a default `OrgConfig` stub (version, upstream URL, default policy = `deny`) and a deterministic ETag seed.
- **Cognito:** provisions users with `custom:org_id`, email auto-verified, and group membership. Passwords are generated via `openssl rand -base64 24` (prefixed `Fg1!` to cover all Cognito password policy classes) and stored in 1Password under `op://forgeguard-prod/test-user-{username}/password`.

The command is idempotent: re-running rotates passwords and realigns group membership (removing from any non-target groups before adding to the target).

```bash
cargo xtask control-plane seed
cargo xtask control-plane seed --config path/to/custom-seed.toml
```

`xtask/seed.toml` ships with `acme-*` and `globex-*` fixtures covering `admin`, `member`, and `owner` groups.

### Local DynamoDB Target

For local QA against `dynamodb-local` (started by `cargo xtask control-plane dev`), pass both flags:

```bash
cargo xtask control-plane seed \
  --dynamodb-endpoint http://127.0.0.1:<PORT> \
  --dynamodb-table forgeguard-orgs-dev
```

- Organizations and membership rows are written to the local table.
- Cognito users are still provisioned in real AWS (no local Cognito emulator exists). Passwords still land in 1Password.
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

Generates the machine-principal signature headers (`x-forgeguard-signature`, `x-forgeguard-timestamp`, `x-forgeguard-key-id`, `x-forgeguard-trace-id`) from a PEM private key and sends the request via `reqwest`. Useful for QA'ing the machine principal → VP authorization flow without a real proxy.

```bash
cargo xtask control-plane curl \
    --key-id kid-abc123 \
    --private-key @key.pem \
    --org-id org-acme \
    --verbose \
    GET https://cp.forgeguard.dev/api/v1/organizations/org-acme/proxy-config
```

The canonical payload that the server recomputes and verifies against matches exactly: the `CanonicalPayload::new(&trace_id, timestamp, &identity_headers)` constructor uses the lowercase `x-forgeguard-org-id` header to match what the `http` crate normalises on the server side.

## Shared Helpers

- `op::read_op(vault, item, field, op_account)` — one-shot 1Password read, used by `seed` and `token` for bootstrapping AWS resource IDs (user pool, app client) and user passwords.
- `op::store_in_op(...)` — one-shot 1Password write, used by `seed` to persist rotated passwords.
- `op::build_aws_config(profile, region)` — constructs an `aws_config::SdkConfig` with the requested profile and region.

## Environment Defaults

All three subcommands share these defaults:

| Flag | Env var | Default |
|------|---------|---------|
| `--env` | `FORGEGUARD_ENV` | `prod` (only valid value) |
| `--op-account` | `FORGEGUARD_OP_ACCOUNT` | `YYN6IHBFRRD5RCLU63J46WPKMA` |
| `--region` | `AWS_REGION` | `us-east-2` |
| `--profile` | `AWS_PROFILE` | `admin` |
