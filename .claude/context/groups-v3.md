# Groups CRUD (event-sourced)

> **VP push retired in #117 V2.** This doc previously described V3/V4
> (issue #102 / #113) Active-org Verified Permissions (VP) materialization on
> group writes — a distributed push-then-append pipeline with its own
> failure-mode taxonomy and rollback metric. Issue #117 V2 deleted that
> pipeline entirely: `VpClient`, `AwsVpClient`, `StubVpClient`, the
> `aws-sdk-verifiedpermissions` dependency, `OrgWriteContext`/`VpContext`, and
> the `ActiveWithoutVpStore` (D11) invariant are all gone from
> `crates/control-plane`. Group `PUT`/`POST`/`DELETE` is now a **pure
> event-sourced append for every org status** (Draft or Active) — there is no
> VP call on the write path at all. `vp_store_id` still exists on `OrgConfig`
> as inert metadata (unrelated to CP's own self-authz; it still matters to the
> proxy's tenant policy delivery), but the control plane no longer reads it to
> branch group-write behavior. The historical VP-push material below
> (`VP Client`, `[name]` description-prefix encoding, policy naming) is kept
> for archaeological reference. It originally noted that `xtask cedar sync`
> was unaffected and retained its own VP client — that is no longer true:
> #117 V3 deleted `cargo xtask control-plane cedar {status,diff,sync}`
> entirely, along with the CDK `VerifiedPermissionsStack`. There is now no
> Verified Permissions client or CLI anywhere in the control-plane toolchain;
> the material below describes code and tooling that no longer exists.

## Write Pipeline (event-sourced append, current)

Every group `PUT`/`POST`/`DELETE`, regardless of org status, goes straight to
the event-sourced append:

```
pure pre-flight (parse + validate + D6 no-op check)
    └─> event-sourced append (ModelEventStore::put_group / delete_group)
```

- **`X-Fg-If-Revision` / 412 `revision_mismatch` (D5).** Unchanged. Callers
  send the last-seen revision in `X-Fg-If-Revision`; a stale value yields
  `412` with the standard `{"error":"revision_mismatch",...}` body. Successful
  writes echo the new revision in `X-Fg-Revision`.
- **No-op detection (D6).** Unchanged. If the incoming entry is identical
  (JSON-equality) to the current one, no append happens at all — the handler
  short-circuits to `GroupWriteOutcome::NoOp`.
- **No VP push, no Active-org branch.** The V3/V4 `OrgWriteContext::{Draft,Active}`
  split, the `ActiveWithoutVpStore` 503 invariant, and the F-VP / F-VP-mid /
  F-append failure-mode taxonomy described further below **no longer exist**.
  Draft and Active orgs go through the exact same append path.
- **No rollback metric.** `forgeguard_cp_group_rollback_failed_total` is
  deleted — there is nothing to roll back since there is no cross-store
  (DDB + VP) write to compensate.

## API Wire Format

The following sections describe the request/response wire format, which is
**unaffected** by the #117 V2 change.

### `X-Fg-If-Revision` / `X-Fg-Revision`

Group `PUT`/`DELETE` use revision tokens instead of ETag/`If-Match`:

- Request: `X-Fg-If-Revision: <revision>` — the client's last-seen revision.
- Success response: `X-Fg-Revision: <new-revision>`.
- Stale revision: `412` with `{"error":"revision_mismatch",...}`.

### Colon-form actions

Group action ids use the colon-form (`cp:groups:read`, etc.) shared with the
embedded `cp:*` Cedar engine — see [control-plane.md](./control-plane.md) for
the full action catalog.

---

## Historical: V3/V4 VP Push Pipeline (retired in #117 V2)

The rest of this document describes the **retired** VP-materialization
pipeline for historical/archaeological reference. None of it reflects current
CP runtime behavior — every group write is a pure event-sourced append (see
above).

V3 (issue #102) extended the V2 Groups CRUD (DDB-only, Draft orgs) with a
distributed-write path that materialised compiled Cedar permits into each
Active org's Verified Permissions (VP) policy store on every CREATE/UPDATE/DELETE.
V4 (issue #113, "Groups — Push-Then-Append") inverted the ordering so the VP
push happened **first** and the event-sourced append second; if the append
then failed, the shell compensated by reverting the VP push.

> Implementation plan: `.claude/designs/issue-102-v3-implementation-plan.md`
> (local-only). Manual QA plan: `.claude/plans/issue-102-v3-implementation-plan-qa.md`
> (local-only). Both are gitignored — see [CONTEXT.md § Local-Only Documents](../../CONTEXT.md).
> V4 plan: `.claude/plans/2026-07-17-issue-113-v4-groups-push-then-append-plan.md`.

### Active-org Boundary (historical)

Group writes split on `OrgWriteContext`, parsed once at the handler boundary
from the loaded `OrgRecord` (`crates/control-plane/src/handlers/groups/active_pure.rs`,
now deleted):

```rust
pub(crate) enum OrgWriteContext {
    Draft,                  // V2 path — DDB-only.
    Active(VpContext),      // V3 path — DDB + VP.
}
```

`VpContext { store_id, namespace, tenant }` was the closed set of inputs the
Active path needed. `OrgWriteContext::from_record` was the only constructor:

- `OrgStatus::Active` + `cfg.vp_store_id == Some(_)` → `Active(VpContext)`
- `OrgStatus::Active` + `vp_store_id == None` → `ActiveStateError::ActiveWithoutVpStore`
  (Risk #5 — an Active org must carry a `vp_store_id`; see _Boundary cases_ below)
- Anything else → `Draft`

### Write Pipeline (historical — V4 push-then-append, D6)

For each handler the shape was inverted from V3: the VP push happened
first, and the event-sourced append (`ModelEventStore::{put_group,delete_group}`)
happened only after the push succeeded.

```
pure pre-flight (parse + compile)
    └─> VP parent push  (CREATE: create / DELETE: delete /
                         UPDATE: delete-then-create)
            └─> VP fanout to dependents  (UPDATE only; alphabetical)
                    └─> event-sourced append (ModelEventStore::put_group / delete_group)
```

The fanout walked transitive inheritors of the parent (computed by
`compute_dependents_in_order`). Dependent ordering was globally alphabetical
so F-VP-mid reproductions landed on the same boundary every run.

Rationale for the inversion: VP was the harder side to compensate (no atomic
transaction across DDB and VP), so the shell pushed to VP first — if that
failed, nothing was written anywhere and there was nothing to roll back. Only
once VP reflected the new state did the shell attempt the event append; if
*that* failed, the shell compensated by reverting the VP push it just made
(see _Failure Mode Taxonomy_, F-append).

Group writes on Draft orgs skipped the VP push entirely (`OrgWriteContext::Draft`)
and went straight to the event-sourced append.

### VP Client (historical, deleted in #117 V2)

`crates/control-plane/src/vp_client/` was the only module that talked to VP.
It has been deleted entirely, along with the `aws-sdk-verifiedpermissions`
dependency. `xtask cedar sync`'s own, separate VP client (`xtask/src/control_plane/cedar_io.rs`)
was later deleted too, in #117 V3 — there is no VP client anywhere in the
control-plane toolchain today.

| File | Role |
|------|------|
| `mod.rs` | `VpClient` trait, `Error`, `NamedPolicy`, the `[name]` description-prefix codec. |
| `aws.rs` | `AwsVpClient` — production impl wrapping `aws_sdk_verifiedpermissions::Client`. |
| `stub.rs` | `StubVpClient` — in-process test impl with failure-injection knobs. Gated `cfg(any(test, feature = "test-support"))`. |

The trait surface was intentionally small — three async methods returning
`impl Future + Send` so axum handler futures stayed `Send`:

```rust
pub(crate) trait VpClient: Send + Sync {
    fn create_policy(&self, store_id: &str, name: &str,
                     description: Option<&str>, statement: &str)
        -> impl Future<Output = Result<String>> + Send;

    fn delete_policy_by_name(&self, store_id: &str, name: &str)
        -> impl Future<Output = Result<()>> + Send;

    fn list_policy_ids(&self, store_id: &str)
        -> impl Future<Output = Result<Vec<NamedPolicy>>> + Send;
}
```

`delete_policy_by_name` was internally `list_policy_ids` then `delete`, so it
was non-atomic — callers had to treat `Error::NotFound` as "no policy with
that name right now," not "the delete itself failed."

#### `[name]` Description-Prefix Encoding (historical, deleted #117 V3)

VP rejects a `name` field on `CreatePolicy` (`ValidationException: Invalid input`).
The workaround — encoding the resource name as a `[name]` prefix in the
`description` field — was **shared between two callers**, both now deleted:

1. `xtask cedar sync` (`xtask/src/control_plane/cedar_io.rs`) — deleted in #117 V3.
2. The control-plane runtime (`crates/control-plane/src/vp_client/mod.rs`) — deleted in #117 V2.

Kept here for archaeology only — the encoder/decoder no longer exists anywhere in the repo.

#### Policy Naming (historical, deleted #117 V3)

Group `name` → VP policy name via `policy_name_for_group`, formerly in
`active_pure.rs` (deleted in #117 V2), then in `xtask cedar sync` (deleted in
#117 V3):

```
admin   →  cp-rbac-admin
member  →  cp-rbac-member
```

### Failure Mode Taxonomy (historical — deleted in #117 V2)

Push-then-append inverted which side needed compensation. Under V3, DDB was
written first and a failed VP push meant rolling back DDB. Under V4, VP was
pushed first — a failed VP push left nothing written anywhere, and a failed
*append* (after a successful VP push) meant compensating VP instead of DDB.

| Mode | Trigger | Status | Compensation | Body |
|------|---------|--------|--------------|------|
| **F-VP** | VP parent push fails before anything is written | `503` | None needed — nothing was written | `{"error":"vp_push_failed","stage":"parent","completed":[],"failed":"<policy>","remaining":[]}` |
| **F-VP-mid** | UPDATE: parent push succeeded, then a dependent push failed mid-fanout | `503` | Restore already-completed dependents' prior permits | `{"error":"vp_push_failed","stage":"fanout","completed":[…],"failed":"<policy>","remaining":[…]}` |
| **F-append** | VP push (parent + fanout) succeeded, but the event-sourced append failed | `412` (revision mismatch) or `500` (other append error) | Revert the VP push just made (`resolve_append_compensation` in `active.rs`) | `412`: same shape as any revision-mismatch response (`{"error":"revision_mismatch",...}`). `500`: `{"error":"internal"}` |
| **F-append, compensation also fails** | F-append trigger AND the VP-reverting compensation also fails | `500` | n/a — VP and the event log have diverged | `{"error":"inconsistent_state","vp_committed":true,"append_committed":false}` |

None of these failure modes exist any more — there is only one write target
(the event log), so there is nothing left to reconcile between two stores.

#### Boundary cases (historical)

- **Active-without-vp_store_id** (Risk #5, carried from V3, deleted in
  #117 V2). An Active org with `vp_store_id == None` used to violate the
  invariant that Active orgs carry a `vp_store_id`; the handler surfaced a
  `503 vp_push_failed{stage="parent"}`. This check (`ActiveWithoutVpStore`,
  D11) no longer exists — `vp_store_id` is inert metadata and is never
  consulted on the group-write path.
- **Idempotent DELETE on Active**. `DELETE` on a missing group still returns
  `404`/absent-noop semantics — unchanged.
- **D6 no-op rule**. If the incoming entry is identical (JSON-equality) to
  the current one, no append happens at all — unchanged, still current
  behavior.

### Metrics (historical, deleted in #117 V2)

| Metric | Labels | Bumped on |
|--------|--------|-----------|
| `forgeguard_cp_group_rollback_failed_total` | `stage="parent"\|"fanout"` | (retired) F-append's compensation failing (VP-revert fails after a failed append). |

This metric and its `rollback_stage` tracing-span attribute are gone from
`crates/control-plane`. There is no successor metric — pure event-sourced
appends either succeed or fail cleanly (`412`/`500`), with nothing to
compensate.

### Test Scaffolding (historical, deleted in #117 V2)

The Active-branch test fixtures below (`active_org_store` VP variants,
`FailingStore`, `metric_lock`, `StubVpClient` failure knobs) were deleted
along with the VP push pipeline. Group-write tests now exercise the single
event-sourced append path directly.

- **`active_org_store(org_id, vp_store_id)`** — seeded an `InMemoryOrgStore`
  with one Active org carrying a populated `vp_store_id`.
- **`test_app_for_store<S>`** — generic counterpart to `test_app_with_stub`,
  parameterised over the store impl so failure-mode tests could plug in
  `FailingStore<InMemoryOrgStore>`.
- **`FailingStore<S>`** — delegating wrapper with one-shot `AtomicBool`
  knobs `fail_next_delete_group` / `fail_next_put_group`.
- **`metric_lock()`** — process-wide async lock guarding tests that read
  `GROUP_ROLLBACK_FAILED_TOTAL` deltas.

#### `StubVpClient` failure knobs (historical)

| Knob | Semantics |
|------|-----------|
| `fail_on_create(name)` | First `create_policy` call with this exact name returns `Error::Other`. One-shot. |
| `fail_on_delete(name)` | First `delete_policy_by_name` call with this exact name returns `Error::Other`. One-shot. |
| `fail_after_n_creates(n)` | Trips on the `(n+1)`-th successful create. |

### Follow-ups (historical, moot)

Automated reconciliation for F-append's compensation-failure case was a
follow-up concern before #117 V2 deleted the pipeline it would have applied
to.
