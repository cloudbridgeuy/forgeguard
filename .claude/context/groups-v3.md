# Groups V3 — Active-org VP Materialization

V3 extends the V2 Groups CRUD (DDB-only, Draft orgs) with the distributed-write
path that materialises compiled Cedar permits into each Active org's Verified
Permissions (VP) policy store on every CREATE/UPDATE/DELETE. The handler shape
stays the same; the V2 `todo!("V3")` Active branches are now real.

> Implementation plan: `.claude/designs/issue-102-v3-implementation-plan.md`
> (local-only). Manual QA plan: `.claude/plans/issue-102-v3-implementation-plan-qa.md`
> (local-only). Both are gitignored — see [CONTEXT.md § Local-Only Documents](../../CONTEXT.md).

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
  (Risk #5 — saga-invariant violation; see _Boundary cases_ below)
- Anything else → `Draft`

The orchestrator never re-checks `Option<vp_store_id>` — make-impossible-states-impossible
done at the handler edge.

## Write Pipeline

For each handler the shape is:

```
pure pre-flight (parse + compile)
    └─> DDB write
            └─> VP parent push  (CREATE: create / DELETE: delete /
                                 UPDATE: delete-then-create)
                    └─> VP fanout to dependents  (UPDATE only; alphabetical)
```

The fanout walks transitive inheritors of the parent (computed by
`compute_dependents_in_order`) and re-emits a compiled permit for each one.
Dependent ordering is **globally alphabetical** so F4 reproductions land on the
same boundary every run.

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

## Failure Mode Taxonomy

The shell pairs each VP push with a rollback strategy. The three failure
classes have distinct status codes and body shapes (driven by
`VpPushFailedBody` / `InconsistentStateBody` in `active_pure.rs`):

| Mode | Trigger | Status | Rollback | Body |
|------|---------|--------|----------|------|
| **F3** | VP parent push fails after DDB write; rollback succeeds | `503` | DDB compensating write succeeds | `{"error":"vp_push_failed","stage":"parent","completed":[],"failed":"<policy>","remaining":[]}` |
| **F3'** | F3 trigger AND the DDB compensating write also fails | `500` | n/a — DDB and VP have diverged | `{"error":"inconsistent_state","ddb_committed":true,"vp_committed":false}` |
| **F4** | UPDATE: parent push succeeded, then a dependent push failed mid-fanout | `503` | None — see Risk #5 in plan | `{"error":"vp_push_failed","stage":"fanout","completed":[…],"failed":"<policy>","remaining":[…]}` |

### Boundary cases

- **Active-without-vp_store_id** (Risk #5). An Active org with
  `vp_store_id == None` is a saga-invariant violation. The handler surfaces the
  same `503 vp_push_failed{stage="parent"}` shape as F3, with `failed` set to
  the canonical policy name the request would have written. No DDB mutation
  happens, so no rollback is needed.
- **Idempotent DELETE on Active**. `DELETE` on a missing group still returns
  `404` (matches V2 behaviour). The Active branch only runs after the DDB
  pre-check succeeds.

## Metrics

| Metric | Labels | Bumped on |
|--------|--------|-----------|
| `forgeguard_cp_group_rollback_failed_total` | `stage="parent"\|"fanout"` | F3' (rollback fails). Each increment means **DDB and VP are inconsistent** — alert and reconcile. |

`stage="fanout"` is reserved for forward compatibility — V3 fanout failures
(F4) do not attempt rollback, so the label is currently never bumped from
production code paths. The `update_org` and group-write tracing spans also
record `rollback_stage` so per-request attribution is available without
exploding cardinality.

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
  process-global and `cargo test` runs in parallel, so concurrent F3/F3'/F4
  tests would race on `counter_after - counter_before` without it. Uses
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

## Saga Coupling (V4 follow-up)

V3 makes the Active write path real but **no real Active org exists yet** —
the saga that flips `Draft → Active` and seeds the per-org VP store with the
project schema is V4. V3 is end-to-end exercised through the stub today; the
production hot path stays Draft until V4 ships. F3'/F4 reconciliation work is
also a V4 concern (the alert points operators at it; nothing automated runs
yet).
