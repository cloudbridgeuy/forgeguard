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
- `validate_cedar_ident(value, label)` — rejects empty strings, double quotes, and control characters. Called by `compile_rbac_to_cedar`; exposed so external callers can apply the same hygiene check.

**Consumers:** `xtask` (`cargo xtask control-plane cedar sync`) and
`forgeguard_control_plane` Groups handlers (V2+).

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
| `policy_name_for_group(name)` | Canonical mapping from group name to VP policy name. Shared with `xtask cedar sync` and the V3 Active write path. |
| `groups_to_permits(entries, namespace, tenant)` | Pure compile-many: turns a slice of `RbacEntry` into a `Vec<NamedPermit>` sorted alphabetically by group name. Stops at the first compile failure (`MaterializeCompileError`). |

The V3 Active write path (`crates/control-plane/src/handlers/groups/active*.rs`)
also imports `NamedPermit` and `policy_name_for_group` from here so all three
codepaths produce byte-identical names and statements.
