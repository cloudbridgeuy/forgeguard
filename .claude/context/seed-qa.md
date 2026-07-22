# Seed Command Manual QA

Companion to [xtask-control-plane-tools.md](./xtask-control-plane-tools.md). Use this doc to validate `cargo xtask control-plane seed` end-to-end after refactors that touch the seed/loader/teardown paths.

The canonical step-by-step plan lives at `.claude/plans/2026-05-06-issue-102-cp-groups-v5/v5-plan-qa.md`. That file is the source of truth for the **scenarios** (lint → unit → DDB integration → loader behavior → local e2e).

> The prod-VP template-linked survival fixture that used to live in this doc was removed in #117 V3: `seed`'s Verified Permissions teardown sweep, the CP-dogfood VP store it targeted, and the `verified-permissions/policy-store-id` 1Password field are all gone. Seed teardown is now Cognito-users-and-membership-rows only.

## Quick Scenario Summary

| # | Scope | Command |
|---|---|---|
| 1 | Workspace lint | `cargo xtask lint` |
| 2 | Pure seed unit tests | `cargo test -p xtask --bin xtask seed` |
| 3 | V5 DDB integration | `cargo xtask control-plane test` |
| 4 | Loader respects explicit `status` | `cargo test -p forgeguard_control_plane build_org_store` |
| 5 | Local e2e against `dynamodb-local` | `cargo xtask control-plane dev` + `seed --dynamodb-endpoint <ep> --dynamodb-table forgeguard-orgs-dev` |

Acceptance is "all four `seed_*` integration tests pass" — `seed_happy_path_writes_one_config_and_three_group_rows`, `seed_is_idempotent`, `seed_dangling_inherit_aborts_before_any_put`, `seed_cycle_aborts_before_any_put`.

## Where The Teardown Logic Lives

Teardown (`xtask/src/control_plane/seed/teardown.rs`) is Cognito-users-and-DynamoDB-membership-rows only: it deletes seeded users (matched via `pure::is_seeded_username`) and their `PK=USER#{sub}, SK=ORG#{org_id}` rows. The `--dynamodb-endpoint` local-DDB path short-circuits Cognito teardown entirely (no local emulator for it).
