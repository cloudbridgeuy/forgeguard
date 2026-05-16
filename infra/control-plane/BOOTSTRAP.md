# Platform Org Bootstrap Runbook

One-shot operator procedure to seed the `forgeguard` platform organisation —
the meta-tenant that owns the control-plane dashboard itself. This is a
non-repeatable runbook: it is never executed by `cargo xtask control-plane
seed` (R10.4 explicitly excludes `forgeguard` from `seed.toml`), and the
DynamoDB writes are idempotent only in the sense that re-running them
overwrites the same rows.

Run this **once**, after the CDK stack has deployed (`cargo xtask
control-plane infra deploy`) and the Cognito user pool, DynamoDB table, and
Verified Permissions policy store all exist.

---

## Prerequisites

- `aws` CLI configured with `--profile admin` and SSO session active
  (`aws sso login --profile admin`).
- AWS region: `us-east-2` (project default per `CLAUDE.md`).
- The four CDK outputs you will need (run `aws cloudformation
  describe-stacks --stack-name forgeguard-prod-control-plane --region
  us-east-2 --profile admin --query 'Stacks[0].Outputs'`):
  - DynamoDB table name → `${TABLE}`
  - Cognito user pool id  → `${POOL_ID}` (pattern:
    `forgeguard-prod-dashboard-users`)
  - Verified Permissions policy-store id → `${POLICY_STORE_ID}`
- The first admin operator's email address → `${ADMIN_EMAIL}` and a display
  name → `${ADMIN_NAME}`.
- `xxhsum` or any xxhash-64 implementation for ETag computation. Recommended:

  ```bash
  brew install xxhash
  # or use the project's helper:
  cargo run -q --package forgeguard_control_plane --bin compute-etag -- '<json>'
  ```

  (If no helper binary exists, compute manually:
  `printf '%s' '<json>' | xxh64sum | awk '{print "\""$1"\""}'`.)

The runbook writes **six** rows into DynamoDB and creates **one** Cognito
user.

---

## Row 1 — Org metadata

```bash
aws dynamodb put-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --item '{
    "PK":               {"S": "ORG#forgeguard"},
    "SK":               {"S": "META"},
    "name":             {"S": "ForgeGuard Platform"},
    "status":           {"S": "Active"},
    "cognito_pool_id":  {"S": "'"${POOL_ID}"'"},
    "created_at":       {"S": "'"$(date -u +%FT%TZ)"'"},
    "updated_at":       {"S": "'"$(date -u +%FT%TZ)"'"},
    "config":           {"S": "{}"},
    "etag":             {"S": ""}
  }'
```

The platform org has no proxy traffic, so `config` is an empty object and
`etag` is the empty string — there is no proxy config to version.

---

## Row 2 — User schema

The dashboard requires every operator to have a `name` attribute (used in
the UI header and audit logs). No custom attributes.

```bash
SCHEMA_JSON='{"standard":{"name":{"required":true}},"custom":{}}'
SCHEMA_ETAG=$(printf '%s' "${SCHEMA_JSON}" | xxh64sum | awk '{print "\""$1"\""}')

aws dynamodb put-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --item '{
    "PK":     {"S": "ORG#forgeguard"},
    "SK":     {"S": "USER_SCHEMA"},
    "schema": {"S": "'"${SCHEMA_JSON}"'"},
    "etag":   {"S": "'"${SCHEMA_ETAG}"'"}
  }'
```

---

## Row 3 — `member` group

Default role: read-only access to the org's own user schema.

```bash
MEMBER_JSON='{"name":"member","description":"Default member role","inherits":[],"allow":["cp:user-schema:read"],"tenant_scoped":true}'
MEMBER_ETAG=$(printf '%s' "${MEMBER_JSON}" | xxh64sum | awk '{print "\""$1"\""}')

aws dynamodb put-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --item '{
    "PK":     {"S": "ORG#forgeguard"},
    "SK":     {"S": "GROUP#member"},
    "config": {"S": "'"${MEMBER_JSON}"'"},
    "etag":   {"S": "'"${MEMBER_ETAG}"'"}
  }'
```

---

## Row 4 — `admin` group

Inherits from `member`, adds schema-mutation and org-update permissions.

```bash
ADMIN_JSON='{"name":"admin","description":"Admin role","inherits":["member"],"allow":["cp:user-schema:update","cp:organization:update"],"tenant_scoped":true}'
ADMIN_ETAG=$(printf '%s' "${ADMIN_JSON}" | xxh64sum | awk '{print "\""$1"\""}')

aws dynamodb put-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --item '{
    "PK":     {"S": "ORG#forgeguard"},
    "SK":     {"S": "GROUP#admin"},
    "config": {"S": "'"${ADMIN_JSON}"'"},
    "etag":   {"S": "'"${ADMIN_ETAG}"'"}
  }'
```

---

## Row 5 — `owner` group

Inherits from `admin`, adds the destructive org-deletion permission.

```bash
OWNER_JSON='{"name":"owner","description":"Owner role","inherits":["admin"],"allow":["cp:organization:delete"],"tenant_scoped":true}'
OWNER_ETAG=$(printf '%s' "${OWNER_JSON}" | xxh64sum | awk '{print "\""$1"\""}')

aws dynamodb put-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --item '{
    "PK":     {"S": "ORG#forgeguard"},
    "SK":     {"S": "GROUP#owner"},
    "config": {"S": "'"${OWNER_JSON}"'"},
    "etag":   {"S": "'"${OWNER_ETAG}"'"}
  }'
```

---

## Cognito step — Create the first admin user

```bash
aws cognito-idp admin-create-user \
  --user-pool-id "${POOL_ID}" \
  --username "${ADMIN_EMAIL}" \
  --user-attributes Name=email,Value="${ADMIN_EMAIL}" \
                    Name=email_verified,Value=true \
                    Name=name,Value="${ADMIN_NAME}" \
  --region us-east-2 --profile admin
```

Capture the returned `User.Attributes` block — extract the `sub` value and
export it:

```bash
export ADMIN_SUB="<sub from the previous response>"
```

The temporary password is sent to `${ADMIN_EMAIL}`. The first login forces a
password reset.

---

## Row 6 — Membership row for the first admin

Binds the Cognito user to the `forgeguard` org with the `owner` role. The
inverted GSI1 makes this row discoverable from both directions
(`USER#{sub} → ORG#forgeguard` and `ORG#forgeguard → USER#{sub}`).

```bash
aws dynamodb put-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --item '{
    "PK":        {"S": "USER#'"${ADMIN_SUB}"'"},
    "SK":        {"S": "ORG#forgeguard"},
    "user_id":   {"S": "'"${ADMIN_SUB}"'"},
    "org_id":    {"S": "forgeguard"},
    "groups":    {"L": [{"S": "owner"}]},
    "email":     {"S": "'"${ADMIN_EMAIL}"'"},
    "joined_at": {"S": "'"$(date -u +%FT%TZ)"'"}
  }'
```

---

## Verification

```bash
# All six rows for the platform org
aws dynamodb query \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --key-condition-expression "PK = :pk" \
  --expression-attribute-values '{":pk": {"S": "ORG#forgeguard"}}' \
  --query 'Items[].SK.S'
# Expected: ["META", "USER_SCHEMA", "GROUP#member", "GROUP#admin", "GROUP#owner"]
# (order varies — DynamoDB returns items in SK order by default)

# Membership row
aws dynamodb get-item \
  --table-name "${TABLE}" \
  --region us-east-2 --profile admin \
  --key '{"PK": {"S": "USER#'"${ADMIN_SUB}"'"}, "SK": {"S": "ORG#forgeguard"}}' \
  --query 'Item.groups.L[0].S'
# Expected: "owner"
```

---

## Notes & Gotchas

- **`seed.toml` MUST NOT include `forgeguard`** (R10.4). The seeder is for
  customer orgs; the platform org is operator-managed.
- **Cross-org permissions for platform admins live in `forgeguard.toml`
  Cedar** (R10.5) — the `owner` role's `cp:*` permissions are tenant-scoped
  by design. To grant the platform `owner` the ability to act on customer
  orgs, add explicit Cedar policies in `forgeguard.toml` and run `cargo
  xtask control-plane cedar sync`.
- **Cognito pool name pattern**: `forgeguard-${env}-dashboard-users`. The
  project ships a single environment, `prod`, per `CLAUDE.md`.
- **PUT user-schema on Active orgs**: V2 of issue #100 returns `409
  Conflict` (`reason: active_schema_put_requires_v4`) when the org status is
  `Active`. The platform org is `Active`, so its schema is fixed by this
  runbook and cannot be mutated through the API until V4 ships the
  Cognito-first update path. If the platform schema needs to change before
  V4, edit Row 2 directly via `aws dynamodb put-item` and recompute the
  ETag.
- **Idempotency**: each `put-item` overwrites unconditionally — re-running
  the runbook re-stamps `updated_at` and re-computes ETags. Membership rows
  for additional admins should be created via the dashboard's invite flow,
  not by re-running this runbook.
