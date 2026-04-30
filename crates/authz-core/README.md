# forgeguard_authz_core

Authorization domain types for ForgeGuard. This is a **pure crate** — no I/O dependencies.

Owns Cedar policy types, permission check types, role/resource/action definitions, and feature gate types.

## Modules

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
