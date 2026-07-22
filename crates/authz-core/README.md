# forgeguard_authz_core

Authorization domain types for ForgeGuard. This is a **pure crate** — no I/O dependencies.

Owns Cedar policy types, permission check types, role/resource/action definitions, and feature gate types.

## Modules

### `store`

Snapshot-at-revision reads and revision-returning writes over the phase-1
core model (`Spine`, `Principal`, `PrincipalSet`, `Grant`, `PromotedResource`).
The change stream is deliberately absent — it arrives with the event log
(#110).

**Public types:**

- `Revision` — the monotonic consistency token every write returns and every
  read can pin to.
- `ModelState` — a Vec-backed snapshot of the model at one revision.
- `EntitySlice` — everything one decision needs, read at one revision.
  Built only by `select_slice`.
- `SliceQuery` — a decision-scoped read request (`principal`, `resource`,
  optional pinned `revision`).
- `StoreWrite` — the mutation ADT (`PutOrgUnit`, `PutPrincipal`,
  `PutPrincipalSet`, `PutGrant`, `RemoveGrant`, `PutPromotion`).
- `AuthzStore` — the store trait (`slice`, `apply`, `latest_revision`),
  object-safe via boxed futures (same style as `PolicyEngine`).
- `MemoryStore` — an in-memory reference implementation. **Tests and
  conformance only** — a full `ModelState` clone per revision, not meant
  for production scale. The phase-3 DynamoDB store implements the same
  `AuthzStore` trait and reuses `select_slice` for slice selection.

**Public functions:**

- `select_slice(model, principal, resource, revision)` — pure selection of
  the `EntitySlice` for one decision from a `ModelState` snapshot.

### `rbac`

Pure RBAC compiler — no I/O, no clock, no randomness. Compiles `RbacEntry`
values to Cedar `permit(...)` statements with optional tenant scoping.

**Public types:**

- `RbacEntry` — role definition (name, description, inherits, allow, tenant_scoped).
- `TenantConfig` — tenant scoping config (`enabled`, `principal_attribute`,
  `resource_attribute`). Default: enabled with `tenant_id` on both sides.

**Public functions:**

- `compile_rbac_to_cedar(entry, tenant, namespace)` — produces a single Cedar permit block.
- `resolve_inherits(entries, target)` — depth-first action collection over the inheritance graph with cycle detection.
- `validate_cedar_ident(value, label)` — rejects empty strings, double quotes, backslashes, and control characters (`"` and `\` are Cedar's string-escape characters — either would let a crafted value break out of its quoted literal when interpolated into generated policy text). Called by `compile_rbac_to_cedar` and by `engine_cedar`'s grant-policy synthesis; exposed so external callers can apply the same hygiene check.

**Consumers:** `crates/control-plane/build.rs` (compiles `forgeguard.toml` into
the embedded `CpCedarEngine` at build time) and `forgeguard_control_plane`
Groups handlers (V2+).

### `snapshot`

The immutable, versioned compiled policy (Design A1's `fg-compiler` output;
phase-2 scope is the RBAC bridge only — multi-source merge and provenance are
phase 5, #112). A snapshot is *static*: once built, nobody edits it, and it
carries its own content hash so a decision can always be replayed against the
exact policy text that produced it.

**Public types:**

- `Snapshot` — a Cedar `PolicySet` plus its raw policy text and `SnapshotVersion`. Built via `Snapshot::from_rbac(entries, tenant, namespace)` (compiles `RbacEntry` values through `rbac::compile_rbac_to_cedar`) or `Snapshot::from_policy_text(text)` (parses raw Cedar text directly — used by the conformance harness).
- `SnapshotVersion` — content-addressed version: FNV-1a 64 over the compiled policy text. Deterministic across Rust releases, so `DecisionRecord`s stay replayable against the snapshot that decided them.

### `engine_cedar`

The embedded Cedar engine (Design A1's `fg-engine`): one consistent store
read, in-process Cedar evaluation, and a `DecisionRecord` that carries both
the `SnapshotVersion` and the store `Revision` it was decided against.

This is where the brief's two-tier split lives: the `snapshot` module above
is *static* compiled policy (roles/permissions), while **grants are live
data** — read fresh from the store on every `decide` call and compiled into
one-off Cedar policies for that single decision. A snapshot never encodes a
grant; `engine_cedar::translate` does that at decision time.

**Public types:**

- `CedarEngine` — holds a `Snapshot`; `decide(store, query)` does the one store read (`select_slice`), translates the resulting `EntitySlice` to Cedar entities, synthesizes grant policies, evaluates via `cedar_policy::Authorizer`, and returns a `DecisionRecord`.
- `DecisionQuery` — a decision request (`principal`, `action`, `resource`).
- `DecisionRecord` / `Decision` — the decision outcome (`Allow`/`Deny`) plus the `SnapshotVersion` and `Revision` it was decided against.

**Submodules (not re-exported, internal to the engine):**

- `translate` — pure `EntitySlice` → Cedar entity translation and per-decision grant-policy synthesis. Its module doc comment carries the full **entity-mapping table** (model type → Cedar entity type → UID → parents) that the conformance fixtures depend on exactly, plus the documented `PrincipalKind` collapse (`Human` → `User`; `Service`/`Agent` → `Machine`).
- `record` — the `DecisionRecord`/`Decision` types themselves.
- `engine` — `CedarEngine` and its `decide` orchestration.
- `adapter` — see **`EmbeddedPolicyEngine` adapter (phase 2 / V4)** below.

See `conformance/engine/README.md` for the end-to-end fixture format that exercises this module.

#### `EmbeddedPolicyEngine` adapter (phase 2 / V4)

`EmbeddedPolicyEngine` (`engine_cedar::adapter`, re-exported from the crate
root) is the existing-trait face of the embedded engine: it wraps a
`CedarEngine` + `Arc<dyn AuthzStore>` and implements `PolicyEngine`, so
today's five `Arc<dyn PolicyEngine>` consumers (control-plane, proxy) can
point at embedded Cedar without changing shape. It translates a flat
`PolicyQuery` (`PrincipalRef`/`QualifiedAction`/`ResourceRef`) into an
org-scoped `DecisionQuery` via the pure `adapter::map_query` function; the
full mapping contract (principal → FGRN, action → `Verb`, resource →
FGRN or the `app/app` fallback, context dropped) is documented in that
module's doc comment.

This adapter is scheduled for retirement on #111 during the middleware
refit, once `PolicyEngine` itself is retired or evolved into the
`DecisionRecord` shape — it exists only to bridge today's consumers, not
as a long-term interface.

#### Pure validation (V2)

The `rbac::validation` submodule provides group write validation that is
consumed by the control-plane Groups handlers before any I/O:

- `ValidatedRbacEntry` — a newtype wrapper around `RbacEntry`. Holding one is
  proof that every field-level validator passed. Constructed only via
  `validate_rbac_entry`; cannot be constructed directly.
- `GroupValidationError` — ADT of all validation failure cases:
  `BadNameRegex`, `BadActionFormat`, `EmptyAllow`, `InheritCycle`,
  `UnknownInherit`, `DescriptionTooLong`, `NameMismatch`.
- `validate_rbac_entry(proposed, all_after)` — validates a single entry
  against the post-write group set (passed in by the caller). Checks name
  regex, non-empty allow list, description length, action format for each
  allow entry, and runs `resolve_inherits` to catch cycles and unknown
  parent references.

V2 of issue #102 consumes these from the control-plane Groups handler to
validate create and update requests before writing to DynamoDB or memory.

#### Permit compilation (V4)

For the saga handoff stub (`materialize_groups_to_vp` in
`crates/control-plane`), this crate exposes:

| Symbol | Purpose |
|---|---|
| `NamedPermit { name, statement }` | A single Cedar permit with its canonical `cp-rbac-{group}` policy name already applied. |
| `policy_name_for_group(name)` | Canonical mapping from group name to VP policy name. |
| `groups_to_permits(entries, namespace, tenant)` | Pure compile-many: turns a slice of `RbacEntry` into a `Vec<NamedPermit>` sorted alphabetically by group name. Stops at the first compile failure (`MaterializeCompileError`). |

The V3 Active write path (`crates/control-plane/src/handlers/groups/active*.rs`)
also imports `NamedPermit` and `policy_name_for_group` from here so all three
codepaths produce byte-identical names and statements.
