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
- **Keys:** `PK` (String), `SK` (String) — single-table design, defined in `infra/control-plane/schema/forgeguard-orgs.json`
- **Billing:** on-demand (PAY_PER_REQUEST)
- **Removal policy:** RETAIN (always — this is prod data)
- **Replicas:** us-east-1, us-east-2, us-west-2 (primary region auto-excluded from replica list)
- **Tags:** `project=forgeguard`, `environment={env}`
- **Outputs:** TableName, TableArn
- **Schema source of truth:** `infra/control-plane/schema/forgeguard-orgs.json` — consumed by CDK (TypeScript `import`) and Rust (`include_str!` at compile time). Both CDK and DynamoDB integration tests read key names from this single file to prevent drift.

### Cognito User Pool (`forgeguard-{env}-cognito`)

- **Pool name:** `forgeguard-{env}-dashboard-users`
- **Self-signup:** disabled (admin-created users only)
- **Sign-in:** username or email
- **MFA:** optional (TOTP only, no SMS)
- **Password policy:** 12+ chars, upper, lower, digit, symbol
- **Identity-only:** no custom attributes, no Cognito groups. Org context (`tenant_id`) and roles (`groups`) come from DynamoDB membership items keyed by `PK=USER#{sub}, SK=ORG#{org_id}` — see [control-plane.md](./control-plane.md).
- **App client:** `forgeguard-{env}-dashboard` — no secret, SRP auth, PKCE OAuth
- **Domain:** `forgeguard-{env}.auth.{region}.amazoncognito.com`
- **Outputs:** UserPoolId, UserPoolArn, AppClientId, JwksUrl, Issuer
- **1Password items:** `cognito/user-pool-id`, `cognito/user-pool-arn`, `cognito/app-client-id`, `cognito/jwks-url`, `cognito/issuer`

The Lambda stack reads Cognito outputs as cross-stack references and injects them as env vars (`FORGEGUARD_CP_JWKS_URL`, `FORGEGUARD_CP_ISSUER`, `FORGEGUARD_CP_AUDIENCE`) into the control-plane function.

### Verified Permissions (`forgeguard-{env}-vp`)

- **Policy store:** validation mode `OFF` (we author Cedar directly; relying on CDK-side schema validation is left to the `cedar sync` engine).
- **Identity source:** Cognito user pool wired in when `userPoolArn` and `appClientId` props are passed (currently always present from `bin/app.ts`). Used by VP for `IsAuthorizedWithToken` flows; the CP doesn't call that today.
- **Outputs:** `PolicyStoreId` (CFN output for operator visibility).
- **Public stack properties:** `policyStoreId` and `policyStoreArn` are exposed as `public readonly` fields on `VerifiedPermissionsStack`. Both are sourced from CFN attribute getters (`attrPolicyStoreId`, `attrArn`) — never from `cdk.Stack.formatArn`. See [aws-arn-formats.md](./aws-arn-formats.md) for the empty-region-segment trap.

These properties feed the Lambda stack via constructor props in `bin/app.ts`. Deploy order: VP stack must be constructed (and exist in CFN) before LambdaStack, because the cross-stack reference becomes an `Fn::ImportValue` that requires the export to already be resolved. CDK's `cdk deploy --all` handles this automatically; selective `cdk deploy forgeguard-{env}-lambda` against a fresh account fails until the VP stack lands first.

### Control-plane Lambda runtime contract

The control-plane Lambda's startup behavior depends on a coupled env-var-plus-IAM contract. The Rust binary's parse-time invariant ([authn-wiring.md](./authn-wiring.md)) panics at cold start if the env says "JWT auth is on" without a backing VP store, so the CDK stack must inject both halves together.

| Env var | Source | Required |
| ------- | ------ | -------- |
| `TABLE_NAME` | DynamoDB stack | Always |
| `FORGEGUARD_CP_JWKS_URL` | Cognito stack | When auth is enabled (always in deployed envs) |
| `FORGEGUARD_CP_ISSUER` | Cognito stack | When auth is enabled |
| `FORGEGUARD_CP_AUDIENCE` | Cognito stack (app client id) | When auth is enabled |
| `FORGEGUARD_CP_POLICY_STORE_ID` | VP stack (`policyStoreId`) | When auth is enabled (parse-time invariant: JWT ⇒ VP) |

| IAM grant | Resource | Why |
| --------- | -------- | --- |
| `dynamodb:*` (read+write) | `TABLE_NAME` ARN | `table.grantReadWriteData(controlPlane)` |
| `verifiedpermissions:IsAuthorized` | Policy store ARN (`policyStoreArn`) | CP authorization decisions; scoped — never `*` |

`IsAuthorizedWithToken` is **not** granted because the CP parses JWTs itself and submits a fully-formed `IsAuthorized` request. If a future slice adopts token-mode VP calls, expand the action list there.

#### Schema changes that require pool replacement

Cognito does not support removing or modifying custom schema attributes or Cognito groups on a live user pool (`AddCustomAttributes` exists; no delete/modify counterpart). A CDK change that removes such an attribute will deploy as `UPDATE_FAILED` with `Existing schema attributes cannot be modified or deleted`.

When a schema change is required, force pool recreation by changing the construct id (e.g., `DashboardUserPool` → `DashboardUserPoolV2`). CDK emits a new logical id; CloudFormation creates a fresh pool and handles the old one per its `RemovalPolicy`.

Because the Lambda and VP stacks import pool exports (`userPoolId`, `userPoolArn`, `appClientId`), a straight CDK redeploy blocks with `Cannot update export … as it is in use`. The canonical migration is:

1. Replace the cognito props passed to `LambdaStack`/`VerifiedPermissionsStack` in `bin/app.ts` with dummy literals (`"DECOMMISSIONED"` / `undefined`).
2. `cdk deploy forgeguard-prod-lambda forgeguard-prod-vp --exclusively` — drops imports.
3. Apply the pool rename in `cognito-stack.ts` and `cdk deploy forgeguard-prod-cognito --exclusively`.
4. Restore the real cognito props in `bin/app.ts` and `cargo xtask control-plane infra deploy`.
5. Update 1Password entries (auto-refreshed by `infra deploy`) and run `cargo xtask control-plane seed`.

The old pool is deleted per its `removalPolicy` (or orphaned on `RETAIN`). Child `UserPoolDomain`/`UserPoolClient` resources whose physical parent is already gone may land in `DELETE_FAILED`; the parent stack still reaches `UPDATE_COMPLETE` and the zombie does not block subsequent deploys.

### Verified Permissions (`forgeguard-{env}-vp`)

- **Policy store:** `vp.CfnPolicyStore` with `validationSettings.mode = "OFF"` (Cedar schema is managed via `cargo xtask control-plane cedar sync`, not CloudFormation).
- **Identity source:** `vp.CfnIdentitySource` bound to the Cognito user pool + app client when both arns are passed in.
- **Stack exports:** `policyStoreId` and `policyStoreArn` as `public readonly` properties (consumed by the Lambda stack via cross-stack references) plus matching `CfnOutput`s for human visibility.
- **ARN format:** Verified Permissions is region-less. The stack builds the ARN with `cdk.Stack.of(this).formatArn({ service: "verifiedpermissions", region: "", resource: "policy-store", resourceName, arnFormat: SLASH_RESOURCE_NAME })` so the resulting `arn:aws:verifiedpermissions::<account>:policy-store/<id>` matches what the SDK expects.
- **Stack ordering:** instantiated in `bin/app.ts` *before* `LambdaStack` so the policy store id and arn are available as constructor props.

The Lambda stack imports those exports and:

1. Sets `FORGEGUARD_CP_POLICY_STORE_ID` on the control-plane function. The CP binary requires JWT (`FORGEGUARD_CP_JWKS_URL`) and policy-store id to be configured *together* — V4 wires `VpPolicyEngine` with `DefaultPolicy::Deny` whenever JWT is on. Missing the policy-store id makes init panic and the function URL returns 502 on every request.
2. Grants `verifiedpermissions:IsAuthorized` on the execution role, scoped to `policyStoreArn` (no wildcard).

## FCIS Split (xtask)

| Module | Role | Pure? |
|--------|------|-------|
| `op_core.rs` | Functional Core | Yes — `ForgeguardEnv` enum, `PreflightChecks`, `build_stack_name`, `confirm_destroy`, `format_status_output` |
| `op.rs` | Imperative Shell | No — `op read`, `op item edit`, `op run`, `bun install`, AWS SDK calls |
| `infra/*.rs` | Shell (commands) | No — orchestrate I/O calls from `op.rs`, no business logic |

## Environment Type

`ForgeguardEnv` is a `clap::ValueEnum` enum with variants `Dev` and `Prod`. Parsed at the CLI boundary — invalid values are rejected before any command logic runs. Implements `Display` for string formatting in stack/vault names.
