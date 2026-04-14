# Infrastructure: Control Plane CDK

The control plane AWS infrastructure lives in `infra/control-plane/` as a TypeScript CDK v2 project managed by Bun (no `ts-node`).

## Architecture

```
xtask control-plane infra          CDK Project (infra/control-plane/)
        |                                    |
        +-- deploy -----> op run --env-file --> bun run cdk deploy
        +-- diff -------> op run --env-file --> bun run cdk diff
        +-- destroy ----> op run --env-file --> bun run cdk destroy
        +-- status -----> AWS SDK describe_stacks (direct)
```

All CDK commands are wrapped with `op run --env-file=.env` so 1Password resolves `op://` references in the `.env` file and injects them as environment variables. The xtask binary never reads the `.env` file itself — clap owns all configuration via `--flags` and `env = "VAR"` attributes.

## 1Password Integration

Secrets and infrastructure outputs are stored in 1Password vaults named `forgeguard-{env}`:

```
forgeguard-prod/
  aws/          → account-id, region, profile
  dynamodb/     → table-name, table-arn (written by deploy)
```

The committed `.env` file at `infra/control-plane/.env` contains `op://` references (no secrets on disk):

```
AWS_ACCOUNT_ID=op://forgeguard-prod/aws/account-id
AWS_REGION=op://forgeguard-prod/aws/region
AWS_PROFILE=op://forgeguard-prod/aws/profile
```

**Prerequisite:** Vaults and items must be created manually before first deploy. xtask does not auto-create them.

## xtask Subcommands

```
cargo xtask control-plane infra deploy  [--env <ENV>] [--op-account <ACCT>] [--region <R>] [--profile <P>]
cargo xtask control-plane infra diff    [--env <ENV>] [--op-account <ACCT>]
cargo xtask control-plane infra destroy [--env <ENV>] [--op-account <ACCT>]
cargo xtask control-plane infra status  [--env <ENV>] [--op-account <ACCT>] [--region <R>] [--profile <P>]
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--env` | `FORGEGUARD_ENV` | `prod` | Target environment. Validated: must be `dev` or `prod`. |
| `--op-account` | `FORGEGUARD_OP_ACCOUNT` | — | 1Password account (email or UUID) for multi-account setups |
| `--region` | `AWS_REGION` | — | AWS region for CloudFormation queries (required by deploy, status) |
| `--profile` | `AWS_PROFILE` | — | AWS CLI profile name (required by deploy, status) |

All flags use clap's `env` attribute — precedence is: CLI flag > env var > default.

### Deploy Flow

1. Preflight: verify `bun` and `op` on PATH
2. `bun install` if `node_modules/` missing
3. `op run --env-file=.env -- bun run cdk deploy --require-approval never`
4. Read CloudFormation outputs (TableName, TableArn) via AWS SDK
5. Store outputs in 1Password vault via `op item edit`

### Destroy Flow

1. Preflight check
2. Print warning with stack name
3. Prompt user to type `"destroy"` (case-sensitive, trimmed)
4. If confirmed: `op run --env-file=.env -- bun run cdk destroy --force`

## CDK Stacks

### DynamoDB Global Table (`forgeguard-{env}-dynamodb`)

- **Table name:** `forgeguard-{env}-orgs`
- **Keys:** `PK` (String), `SK` (String) — single-table design
- **Billing:** on-demand (PAY_PER_REQUEST)
- **Removal policy:** RETAIN (always — this is prod data)
- **Replicas:** us-east-1, us-east-2, us-west-2 (primary region auto-excluded from replica list)
- **Tags:** `project=forgeguard`, `environment={env}`
- **Outputs:** TableName, TableArn

### Cognito User Pool (`forgeguard-{env}-cognito`)

- **Pool name:** `forgeguard-{env}-dashboard-users`
- **Self-signup:** disabled (admin-created users only)
- **Sign-in:** username or email
- **MFA:** optional (TOTP only, no SMS)
- **Password policy:** 12+ chars, upper, lower, digit, symbol
- **Custom attribute:** `org_id` (immutable)
- **Groups:** `admin` (precedence 0), `owner` (10), `member` (20)
- **App client:** `forgeguard-{env}-dashboard` — no secret, SRP auth, PKCE OAuth
- **Domain:** `forgeguard-{env}.auth.{region}.amazoncognito.com`
- **Outputs:** UserPoolId, UserPoolArn, AppClientId, JwksUrl, Issuer
- **1Password items:** `cognito/user-pool-id`, `cognito/user-pool-arn`, `cognito/app-client-id`, `cognito/jwks-url`, `cognito/issuer`

The Lambda stack reads Cognito outputs as cross-stack references and injects them as env vars (`FORGEGUARD_CP_JWKS_URL`, `FORGEGUARD_CP_ISSUER`, `FORGEGUARD_CP_AUDIENCE`) into the control-plane function.

## FCIS Split (xtask)

| Module | Role | Pure? |
|--------|------|-------|
| `op_core.rs` | Functional Core | Yes — `ForgeguardEnv` enum, `PreflightChecks`, `build_stack_name`, `confirm_destroy`, `format_status_output` |
| `op.rs` | Imperative Shell | No — `op read`, `op item edit`, `op run`, `bun install`, AWS SDK calls |
| `infra/*.rs` | Shell (commands) | No — orchestrate I/O calls from `op.rs`, no business logic |

## Environment Type

`ForgeguardEnv` is a `clap::ValueEnum` enum with variants `Dev` and `Prod`. Parsed at the CLI boundary — invalid values are rejected before any command logic runs. Implements `Display` for string formatting in stack/vault names.
