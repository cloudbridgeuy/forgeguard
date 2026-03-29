# Development Infrastructure

This directory contains CDK stacks that provision AWS resources for local
development: a Cognito user pool (authentication) and a Verified Permissions
policy store (authorization). The `cargo xtask dev` commands deploy the stacks,
seed test users, and retrieve JWTs.

## Prerequisites

| Tool         | Purpose                          |
| ------------ | -------------------------------- |
| Rust         | Build and run xtask              |
| `bun`        | Run CDK (xtask calls it for you) |
| AWS CLI v2   | CDK deployment and credential resolution |
| AWS profile `admin` | Must exist in `~/.aws/config`; set via `AWS_PROFILE` in `.env` |

Verify your AWS profile works before proceeding:

```bash
aws sts get-caller-identity --profile admin
```

## Quick Start

1. Copy the template files:

   ```bash
   cp infra/dev/.env.example infra/dev/.env
   cp infra/dev/users.example.toml infra/dev/users.toml
   ```

2. Edit `infra/dev/.env` if you need a different region, stack prefix, or
   password.

3. Deploy the Cognito stack and seed users:

   ```bash
   cargo xtask dev setup --cognito
   ```

   This command installs node dependencies (via `bun install`), deploys the CDK
   stack `${STACK_PREFIX}-cognito`, creates each user in `users.toml` with
   `AdminCreateUser`, sets a permanent password, assigns groups, and writes the
   resulting pool ID, client ID, JWKS URL, and issuer back into `.env` and
   `forgeguard.dev.toml`.

4. (Optional) Deploy the Verified Permissions policy store:

   ```bash
   cargo xtask dev setup --vp
   ```

   Or deploy both Cognito and VP together:

   ```bash
   cargo xtask dev setup --all
   ```

## Available Commands

### `cargo xtask dev setup --cognito`

Deploy the Cognito user pool and seed test users.

| Flag         | Effect |
| ------------ | ------ |
| `--cognito`  | Required. Selects the Cognito setup path. |
| `--force`    | Delete and recreate every test user. Without this flag, existing users are skipped. |
| `--dry-run`  | Print what would happen without executing anything. |

```bash
# Preview the plan
cargo xtask dev setup --cognito --dry-run

# Recreate all users from scratch
cargo xtask dev setup --cognito --force
```

### `cargo xtask dev setup --vp`

Deploy the Verified Permissions policy store with a Cognito identity source.

The VP CDK stack creates a policy store in OFF validation mode and configures
the Cognito user pool as an identity source. After deployment, the
`PolicyStoreId` is written to `.env` and `forgeguard.dev.toml`.

| Flag         | Effect |
| ------------ | ------ |
| `--vp`       | Required. Selects the VP setup path. |
| `--dry-run`  | Print what would happen without executing anything. |

```bash
cargo xtask dev setup --vp
cargo xtask dev setup --vp --dry-run
```

### `cargo xtask dev setup --all`

Deploy both the Cognito and VP stacks in a single command.

```bash
cargo xtask dev setup --all
```

### `cargo xtask dev token --user <username>`

Authenticate as a test user and print the Cognito ID token (JWT).

| Flag               | Effect |
| ------------------ | ------ |
| `--user <username>` | Required. The username from `users.toml`. |
| `--decode`         | Base64-decode the JWT payload and pretty-print the claims instead of printing the raw token. |

```bash
# Raw JWT
cargo xtask dev token --user alice

# Decoded claims
cargo xtask dev token --user alice --decode
```

### `cargo xtask dev users`

List the test users defined in `infra/dev/users.toml`.

| Flag     | Effect |
| -------- | ------ |
| `--json` | Output as JSON instead of an aligned table. |

```bash
cargo xtask dev users
cargo xtask dev users --json
```

## Manual Fallback

If `cargo xtask dev setup --cognito` fails, you can run the equivalent AWS CLI
commands directly. All commands assume `AWS_PROFILE=admin` and
`AWS_REGION=us-east-2` are exported in your shell.

### Create the user pool

```bash
aws cognito-idp create-user-pool \
  --pool-name forgeguard-dev-cognito-user-pool \
  --auto-verified-attributes email \
  --schema Name=email,Required=true,Mutable=true \
           Name=custom:org_id,AttributeDataType=String,Mutable=true \
  --policies 'PasswordPolicy={MinimumLength=8,RequireLowercase=true,RequireUppercase=true,RequireNumbers=true,RequireSymbols=true}' \
  --query 'UserPool.Id' --output text
```

Save the output as `USER_POOL_ID`.

### Create the app client

```bash
aws cognito-idp create-user-pool-client \
  --user-pool-id "$USER_POOL_ID" \
  --client-name forgeguard-dev-cognito-app-client \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_USER_SRP_AUTH \
  --no-generate-secret \
  --query 'UserPoolClient.ClientId' --output text
```

Save the output as `APP_CLIENT_ID`.

### Create groups

```bash
for GROUP in admin member viewer top-secret-readers; do
  aws cognito-idp create-group \
    --user-pool-id "$USER_POOL_ID" \
    --group-name "$GROUP"
done
```

### Create a user and assign groups

Repeat for each user in `users.toml`:

```bash
USERNAME=alice
TENANT=acme-corp
PASSWORD='ForgeGuard-Dev-2026!'

aws cognito-idp admin-create-user \
  --user-pool-id "$USER_POOL_ID" \
  --username "$USERNAME" \
  --temporary-password "$PASSWORD" \
  --message-action SUPPRESS \
  --user-attributes Name=custom:org_id,Value="$TENANT"

aws cognito-idp admin-set-user-password \
  --user-pool-id "$USER_POOL_ID" \
  --username "$USERNAME" \
  --password "$PASSWORD" \
  --permanent

aws cognito-idp admin-add-user-to-group \
  --user-pool-id "$USER_POOL_ID" \
  --username "$USERNAME" \
  --group-name admin

aws cognito-idp admin-add-user-to-group \
  --user-pool-id "$USER_POOL_ID" \
  --username "$USERNAME" \
  --group-name top-secret-readers
```

### Get a token manually

```bash
aws cognito-idp initiate-auth \
  --client-id "$APP_CLIENT_ID" \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=alice,PASSWORD='ForgeGuard-Dev-2026!' \
  --query 'AuthenticationResult.IdToken' --output text
```

## Configuration Reference

### `.env`

| Key                    | Description | Default |
| ---------------------- | ----------- | ------- |
| `AWS_PROFILE`          | AWS CLI profile used for all AWS operations | `admin` |
| `AWS_REGION`           | AWS region for the Cognito stack | `us-east-2` |
| `STACK_PREFIX`         | Prefix for the CloudFormation stack name. The stack deploys as `${STACK_PREFIX}-cognito`. | `forgeguard-dev` |
| `DEV_PASSWORD`         | Shared password assigned to every test user | `ForgeGuard-Dev-2026!` |
| `COGNITO_USER_POOL_ID` | Written by `setup --cognito`. The deployed user pool ID. | -- |
| `COGNITO_APP_CLIENT_ID` | Written by `setup --cognito`. The app client ID. | -- |
| `COGNITO_JWKS_URL`    | Written by `setup --cognito`. JWKS endpoint for JWT verification. | -- |
| `COGNITO_ISSUER`       | Written by `setup --cognito`. Token issuer URL (`https://cognito-idp.<region>.amazonaws.com/<pool-id>`). | -- |
| `VP_POLICY_STORE_ID`   | Written by `setup --vp`. The Verified Permissions policy store ID. | -- |

The auto-written keys are populated after a successful deploy. Do not edit them
by hand.

### `users.toml`

Copy `users.example.toml` to `users.toml` and adjust as needed.

```toml
groups = ["admin", "member", "viewer", "top-secret-readers"]

[[users]]
username = "alice"
tenant = "acme-corp"
groups = ["admin", "top-secret-readers"]

[[users]]
username = "bob"
tenant = "acme-corp"
groups = ["member", "top-secret-readers"]
```

| Field             | Description |
| ----------------- | ----------- |
| `groups`          | Top-level list of Cognito groups to create in the user pool. |
| `users[].username` | Login name. Must be unique. |
| `users[].tenant`  | Value written to the `custom:org_id` attribute. |
| `users[].groups`  | Groups this user belongs to. Each must appear in the top-level `groups` list. |

## Verification

After setup completes, confirm the token contains the expected claims:

```bash
TOKEN=$(cargo xtask dev token --user alice)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
# sub, iss, cognito:groups=["admin","top-secret-readers"], custom:org_id="acme-corp"
```

Or use the built-in decoder:

```bash
cargo xtask dev token --user alice --decode
```
