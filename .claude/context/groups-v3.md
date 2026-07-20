# Groups V3/V4 — Active-org VP Materialization

V3 extended the V2 Groups CRUD (DDB-only, Draft orgs) with the distributed-write
path that materialises compiled Cedar permits into each Active org's Verified
Permissions (VP) policy store on every CREATE/UPDATE/DELETE. The handler shape
stayed the same; the V2 `todo!("V3")` Active branches became real.

**Superseded by #113 V4 (issue #113, "Groups — Push-Then-Append"):** group
writes are event-sourced (`ModelEventStore::{put_group,delete_group}`) instead
of `OrgStore::{put_group,delete_group}`, revision tokens (`X-Fg-If-Revision`)
replace ETag/`If-Match` on group `PUT`/`DELETE`, and the write ordering is
**inverted** — VP push now happens first, the event-sourced append second.
The F3/F3'/F4 failure-mode taxonomy below is superseded by F-VP / F-VP-mid /
F-append (see _Failure Mode Taxonomy_). Sections describing the VP client,
policy naming, and the `[name]` description-prefix encoding are unaffected by
V4 and remain accurate.

> Implementation plan: `.claude/designs/issue-102-v3-implementation-plan.md`
> (local-only). Manual QA plan: `.claude/plans/issue-102-v3-implementation-plan-qa.md`
> (local-only). Both are gitignored — see [CONTEXT.md § Local-Only Documents](../../CONTEXT.md).
> V4 plan: `.claude/plans/2026-07-17-issue-113-v4-groups-push-then-append-plan.md`.

## Active-org Boundary

Group writes split on `OrgWriteContext`, parsed once at the handler boundary
from the loaded `OrgRecord` (`crates/control-plane/src/handlers/groups/active_pure.rs`):

```rust
pub(crate) enum OrgWriteContext {
    Draft,                  // V2 path — DDB-only.
    Active(VpContext),      // V3 path — DDB + VP.
}
```

`VpContext { store_id, namespace, tenant }` is the closed set of inputs the
Active path needs. `OrgWriteContext::from_record` is the only constructor:

- `OrgStatus::Active` + `cfg.vp_store_id == Some(_)` → `Active(VpContext)`
- `OrgStatus::Active` + `vp_store_id == None` → `ActiveStateError::ActiveWithoutVpStore`
  (Risk #5 — an Active org must carry a `vp_store_id`; see _Boundary cases_ below)
- Anything else → `Draft`

The orchestrator never re-checks `Option<vp_store_id>` — make-impossible-states-impossible
done at the handler edge.

## Write Pipeline (V4 — push-then-append, D6)

For each handler the shape is now **inverted** from V3: the VP push happens
first, and the event-sourced append (`ModelEventStore::{put_group,delete_group}`)
happens only after the push succeeds.

```
pure pre-flight (parse + compile)
    └─> VP parent push  (CREATE: create / DELETE: delete /
                         UPDATE: delete-then-create)
            └─> VP fanout to dependents  (UPDATE only; alphabetical)
                    └─> event-sourced append (ModelEventStore::put_group / delete_group)
```

The fanout walks transitive inheritors of the parent (computed by
`compute_dependents_in_order`) and re-emits a compiled permit for each one.
Dependent ordering is **globally alphabetical** so F-VP-mid reproductions land
on the same boundary every run.

Rationale for the inversion: VP is the harder side to compensate (no atomic
transaction across DDB and VP), so the shell pushes to VP first — if that
fails, nothing has been written anywhere and there is nothing to roll back.
Only once VP reflects the new state does the shell attempt the event append;
if *that* fails, the shell compensates by reverting the VP push it just made
(see _Failure Mode Taxonomy_, F-append).

Group writes on Draft orgs skip the VP push entirely (`OrgWriteContext::Draft`)
and go straight to the event-sourced append — there's no VP store to push to
before an org is Active.

## VP Client

`crates/control-plane/src/vp_client/` is the only module that talks to VP.

| File | Role |
|------|------|
| `mod.rs` | `VpClient` trait, `Error`, `NamedPolicy`, the `[name]` description-prefix codec. |
| `aws.rs` | `AwsVpClient` — production impl wrapping `aws_sdk_verifiedpermissions::Client`. |
| `stub.rs` | `StubVpClient` — in-process test impl with failure-injection knobs. Gated `cfg(any(test, feature = "test-support"))`. |

The trait surface is intentionally small — three async methods returning
`impl Future + Send` so axum handler futures stay `Send`:

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

`delete_policy_by_name` is internally `list_policy_ids` then `delete`, so it's
non-atomic — callers must treat `Error::NotFound` as "no policy with that name
right now," not "the delete itself failed."

### `[name]` Description-Prefix Encoding

VP rejects a `name` field on `CreatePolicy` (`ValidationException: Invalid input`).
The workaround — encoding the resource name as a `[name]` prefix in the
`description` field — is **shared between two callers**:

1. `xtask cedar sync` (`xtask/src/control_plane/cedar_io.rs`)
2. The control-plane runtime (`crates/control-plane/src/vp_client/mod.rs`)

Both produce byte-identical output via `encode_name_in_description`/
`decode_name_from_description` in `vp_client/mod.rs`. Policies created by
either tool round-trip cleanly through the other. See
[verified-permissions.md § VP API Quirks](./verified-permissions.md#vp-api-quirks)
for the original quirk.

### Policy Naming

Group `name` → VP policy name via `policy_name_for_group` in `active_pure.rs`:

```
admin   →  cp-rbac-admin
member  →  cp-rbac-member
```

This mapping is canonical and shared with `xtask cedar sync` so policies
materialised by either tool collide deterministically.

## Failure Mode Taxonomy (V4 — supersedes F3/F3'/F4)

Push-then-append inverts which side needs compensation. Under V3, DDB was
written first and a failed VP push meant rolling back DDB. Under V4, VP is
pushed first — a failed VP push leaves nothing written anywhere, and a failed
*append* (after a successful VP push) means compensating VP instead of DDB.
The three failure classes have distinct status codes and body shapes:

| Mode | Trigger | Status | Compensation | Body |
|------|---------|--------|--------------|------|
| **F-VP** | VP parent push fails before anything is written | `503` | None needed — nothing was written | `{"error":"vp_push_failed","stage":"parent","completed":[],"failed":"<policy>","remaining":[]}` |
| **F-VP-mid** | UPDATE: parent push succeeded, then a dependent push failed mid-fanout | `503` | Restore already-completed dependents' prior permits | `{"error":"vp_push_failed","stage":"fanout","completed":[…],"failed":"<policy>","remaining":[…]}` |
| **F-append** | VP push (parent + fanout) succeeded, but the event-sourced append failed | `412` (revision mismatch) or `500` (other append error) | Revert the VP push just made (`resolve_append_compensation` in `active.rs`) | `412`: same shape as any revision-mismatch response (`{"error":"revision_mismatch",...}`). `500`: `{"error":"internal"}` |
| **F-append, compensation also fails** | F-append trigger AND the VP-reverting compensation also fails | `500` | n/a — VP and the event log have diverged | `{"error":"inconsistent_state","vp_committed":true,"append_committed":false}` |

`resolve_append_compensation` (`active.rs`) special-cases the append error:
a `RevisionMismatch` from the append attempt, once compensation succeeds,
surfaces as `412` (the client's stale-revision request bounced cleanly, with
VP already reverted) — not the generic `500`. Any other append error still
maps to `500 Internal` after successful compensation. Compensation *failure*
always maps to `500 InconsistentState` regardless of the underlying append
error, since at that point VP and the event log genuinely disagree.

### Boundary cases

- **Active-without-vp_store_id** (Risk #5, carried from V3). An Active org
  with `vp_store_id == None` violates the invariant that Active orgs carry a
  `vp_store_id`. The handler
  surfaces the same `503 vp_push_failed{stage="parent"}` shape as F-VP, with
  `failed` set to the canonical policy name the request would have written.
  Nothing is written, so no compensation is needed.
- **Idempotent DELETE on Active**. `DELETE` on a missing group still returns
  `404`/absent-noop semantics — the VP push only runs after the pre-flight
  read confirms the group exists.
- **D6 no-op rule**. If the incoming entry is identical (JSON-equality) to
  the current one, no VP push and no append happen at all — the handler
  short-circuits to `GroupWriteOutcome::NoOp` before either side is touched.

## Metrics

| Metric | Labels | Bumped on |
|--------|--------|-----------|
| `forgeguard_cp_group_rollback_failed_total` | `stage="parent"\|"fanout"` | F-append's compensation failing (VP-revert fails after a failed append). Each increment means **VP and the event log are inconsistent** — alert and reconcile. |

Note the metric's meaning changed under V4: under V3 it counted failed DDB
rollbacks after a failed VP push; under V4 it counts failed VP-revert
compensations after a failed event append — the compensation direction
reversed along with the write ordering, but the metric name and alert
semantics ("something failed to roll back cleanly") stayed the same.
`stage="fanout"` remains reserved for forward compatibility. The
`update_org` and group-write tracing spans also record `rollback_stage` so
per-request attribution is available without exploding cardinality.

Recommended alert: `rate(forgeguard_cp_group_rollback_failed_total[5m]) > 0`.

## Test Scaffolding

Active-branch tests live under
`crates/control-plane/src/handlers/tests/groups_active_*.rs` and share fixtures
from `tests/active_support.rs`:

- **`active_org_store(org_id, vp_store_id)`** — seeds an `InMemoryOrgStore`
  with one Active org carrying a populated `vp_store_id`.
- **`test_app_for_store<S>`** — generic counterpart to `test_app_with_stub`,
  parameterised over the store impl so failure-mode tests can plug in
  `FailingStore<InMemoryOrgStore>`. Mounts **only** the group routes (the only
  ones the Active-branch tests need).
- **`FailingStore<S>`** — delegating wrapper with one-shot `AtomicBool`
  knobs `fail_next_delete_group` / `fail_next_put_group`. The first matching
  call after arming returns `Error::Store`; the flag is cleared via
  `swap(false, SeqCst)` so subsequent calls pass through.
- **`metric_lock()`** — process-wide async lock guarding tests that read
  `GROUP_ROLLBACK_FAILED_TOTAL` deltas. The Prometheus counter is
  process-global and `cargo test` runs in parallel, so concurrent
  F-VP/F-VP-mid/F-append tests would race on `counter_after - counter_before`
  without it. Uses
  `tokio::sync::Mutex` (not `std::sync::Mutex`) because the guard must cross
  `await` points — `clippy::await_holding_lock` would otherwise reject it.

### `StubVpClient` failure knobs

| Knob | Semantics |
|------|-----------|
| `fail_on_create(name)` | First `create_policy` call with this exact name returns `Error::Other`. One-shot. |
| `fail_on_delete(name)` | First `delete_policy_by_name` call with this exact name returns `Error::Other`. One-shot. |
| `fail_after_n_creates(n)` | Trips on the `(n+1)`-th successful create. **Counts absolute successful creates from the stub's lifetime, not from the moment the knob is armed** — UPDATE/DELETE tests that replay seed creates against a fresh stub must include the seed-replay count in `n`. |

Example: an UPDATE test that seeds 4 groups via `create_group(...)` (which
each go through one `create_policy` call) and then wants the editor's fanout
to fail on the 3rd handler-driven create must arm `fail_after_n_creates(4 + 2)`
— 4 seed creates already burnt `creates_so_far` to 4, the parent push burns
the 5th, the first dependent burns the 6th, and the 7th fails.

## Follow-ups

Automated reconciliation for F-append's compensation-failure case is a
follow-up concern (the alert points operators at it; nothing automated runs
yet).
