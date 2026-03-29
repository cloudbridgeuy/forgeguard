# forgeguard_cli

ForgeGuard developer CLI. This is an **I/O binary crate**.

Owns schema validation, policy testing, local development server, and project scaffolding. The CLI binary is named `forgeguard`.

## Dependencies

- `forgeguard_core` — Cedar types, schema generation, route/segment primitives
- `forgeguard_http` — route configuration and matching
- `aws-sdk-verifiedpermissions` — VP SDK for policy sync and authorization testing

## Policy Commands

All policy commands accept `--config <path>` (default: `forgeguard.toml`).

### `forgeguard policies validate`

Validates the project configuration, compiles Cedar policies and schema locally. No AWS calls are made.

```bash
forgeguard policies validate
forgeguard policies validate --config custom.toml
```

### `forgeguard policies sync`

Validates locally then pushes the Cedar schema and policies to Verified Permissions.

| Flag        | Effect |
| ----------- | ------ |
| `--dry-run` | Print what would be pushed without making any AWS calls. |
| `--profile` | AWS CLI profile to use. |
| `--region`  | AWS region for the VP policy store. |

```bash
forgeguard policies sync --dry-run
forgeguard policies sync --profile admin --region us-east-2
```

### `forgeguard policies test`

Runs authorization tests against a live VP policy store.

| Flag          | Effect |
| ------------- | ------ |
| `--tests`     | Path to a test definitions file. |
| `--principal` | Principal entity UID for the test request. |
| `--groups`    | Comma-separated group names for the principal. |
| `--tenant`    | Tenant ID for the test request. |
| `--action`    | Action to authorize (format: `namespace:entity:action`). |
| `--resource`  | Resource entity UID for the test request. |
| `--expect`    | Expected decision: `allow` or `deny`. |

```bash
forgeguard policies test --tests tests/authz.toml
forgeguard policies test \
  --principal alice --groups admin,viewer \
  --tenant acme-corp \
  --action "Api:Route:read" \
  --resource "/api/projects" \
  --expect allow
```
