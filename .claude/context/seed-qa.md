# Seed Command Manual QA

Companion to [xtask-control-plane-tools.md](./xtask-control-plane-tools.md). Use this doc to validate `cargo xtask control-plane seed` end-to-end after refactors that touch the seed/loader/teardown paths.

The canonical step-by-step plan lives at `.claude/plans/2026-05-06-issue-102-cp-groups-v5/v5-plan-qa.md`. That file is the source of truth for the **scenarios** (lint → unit → DDB integration → loader behavior → local e2e). This doc holds the **prod-only** procedure that the plan flags as "nice-to-have" — concretely, the template-linked VP policy survival check that needs a live Verified Permissions store.

## Quick Scenario Summary

| # | Scope | Command |
|---|---|---|
| 1 | Workspace lint | `cargo xtask lint` |
| 2 | Pure seed unit tests | `cargo test -p xtask --bin xtask seed` |
| 3 | V5 DDB integration | `cargo xtask control-plane test` |
| 4 | Loader respects explicit `status` | `cargo test -p forgeguard_control_plane build_org_store` |
| 5 | Local e2e against `dynamodb-local` | `cargo xtask control-plane dev` + `seed --dynamodb-endpoint <ep> --dynamodb-table forgeguard-orgs-dev` |

Acceptance is "all four `seed_*` integration tests pass" — `seed_happy_path_writes_one_config_and_three_group_rows`, `seed_is_idempotent`, `seed_dangling_inherit_aborts_before_any_put`, `seed_cycle_aborts_before_any_put`.

## Prod-VP Template-Linked Fixture (Edge Case 3)

**Why:** the teardown filter at `xtask/src/control_plane/seed/teardown.rs:157` (`PolicyType::TemplateLinked → continue`) protects template-linked policies from the `cp-rbac-*` description sweep. This procedure validates the filter end-to-end against a real VP store.

**Blast radius:** the seed command runs against the prod VP store + prod DynamoDB + prod Cognito. This is the canonical dev workflow per `CLAUDE.md` ("only `prod` exists"), but every invocation rewrites the prod seed orgs. Run only when you intend to refresh the seed state.

### 1. Resolve the prod policy store

```bash
export FG_VP_STORE_ID=$(op read 'op://forgeguard-prod/verified-permissions/policy-store-id')
aws verifiedpermissions get-policy-store \
  --region us-east-2 --profile admin \
  --policy-store-id "$FG_VP_STORE_ID" --query 'arn'
```

### 2. Create a policy template with a `cp-rbac-` description

The description prefix makes the test rigorous: if the `TemplateLinked` filter ever regressed, the description filter would catch the fixture and delete it.

```bash
export FG_VP_TEMPLATE_ID=$(aws verifiedpermissions create-policy-template \
  --region us-east-2 --profile admin \
  --policy-store-id "$FG_VP_STORE_ID" \
  --description "cp-rbac-qa-template-linked-fixture-issue-102-v5" \
  --statement 'permit(principal == ?principal, action, resource);' \
  --query 'policyTemplateId' --output text)
```

### 3. Link the template to a synthetic principal

```bash
export FG_VP_LINKED_POLICY_ID=$(aws verifiedpermissions create-policy \
  --region us-east-2 --profile admin \
  --policy-store-id "$FG_VP_STORE_ID" \
  --definition "{
    \"templateLinked\": {
      \"policyTemplateId\": \"$FG_VP_TEMPLATE_ID\",
      \"principal\": {
        \"entityType\": \"forgeguard::User\",
        \"entityId\": \"qa-fixture-issue-102-v5\"
      }
    }
  }" \
  --query 'policyId' --output text)
```

### 4. Run the seed (destructive against prod DDB/Cognito/VP)

```bash
cargo xtask control-plane seed
```

Expected: exit 0, both orgs seeded as Draft, six group rows total.

### 5. Verify the fixture survived

```bash
aws verifiedpermissions get-policy \
  --region us-east-2 --profile admin \
  --policy-store-id "$FG_VP_STORE_ID" \
  --policy-id "$FG_VP_LINKED_POLICY_ID" \
  --query '{type:policyType,created:createdDate}'
```

Acceptance: `type` is `TEMPLATE_LINKED` and `created` matches the pre-seed timestamp (proves it was not deleted+recreated).

### 6. Cleanup (required — fixtures must not linger)

```bash
aws verifiedpermissions delete-policy \
  --region us-east-2 --profile admin \
  --policy-store-id "$FG_VP_STORE_ID" \
  --policy-id "$FG_VP_LINKED_POLICY_ID"

aws verifiedpermissions delete-policy-template \
  --region us-east-2 --profile admin \
  --policy-store-id "$FG_VP_STORE_ID" \
  --policy-template-id "$FG_VP_TEMPLATE_ID"
```

VP requires linked policies to be deleted before their template.

## Where The Filters Live

| Filter | File | What it skips |
|---|---|---|
| `PolicyType::TemplateLinked` early-exit | `xtask/src/control_plane/seed/teardown.rs:157` | Any template-linked policy, before description is inspected |
| `pure::is_seeded_cp_rbac_policy` description match | `xtask/src/control_plane/seed/teardown.rs:183` | Any static policy whose description does not name a seeded org scope |
| Local-DDB short-circuit on teardown | `xtask/src/control_plane/seed/teardown.rs` | Cognito + VP teardown is skipped when `--dynamodb-endpoint` is set (local emulator has neither) |
