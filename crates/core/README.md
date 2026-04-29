# forgeguard_core

Shared primitives, traits, and error types for the ForgeGuard workspace. This is a **pure crate** — it contains no I/O dependencies and can be depended on by any crate in the workspace.

Owns domain-level identifiers (TenantId, UserId, PolicyId), domain entities (Organization), common trait definitions for storage and cache abstractions, and shared error types.

## Domain Types

| Type | Module | Purpose |
|------|--------|---------|
| `DefaultPolicy` | `default_policy` | What happens when no route matches: `Passthrough` or `Deny`. Moved here from `forgeguard_http` so all crates can reference it without an I/O dependency. |
| `OrgStatus` | `org` | 8-variant lifecycle enum for organizations: `Draft`, `PendingProvisioning`, `Provisioning`, `Active`, `Suspended`, `Deleting`, `Deleted`, `Failed`. Includes `can_transition_to()` for validated state transitions. |
| `Organization` | `org` | Domain entity with private fields, constructor (`new()`), and methods for status transitions (`transition_to()`) and name updates (`update_name()`). AWS resource fields (`cognito_pool_id`, `policy_store_id`, etc.) are `Option` -- populated after provisioning. |

### OrgStatus Lifecycle

```text
Draft -> PendingProvisioning -> Provisioning -> Active -> Suspended -> Deleting -> Deleted
                                     |                        |
                                   Failed                   Failed
                                     |
                                   Draft (recovery)
```

Valid transitions are enforced by `OrgStatus::can_transition_to()`. `Organization::transition_to()` returns `Err` for invalid transitions.

## Principal Types

| Type | Module | Purpose |
|------|--------|---------|
| `PrincipalKind` | `action` | `User` (default) or `Machine`. Drives Cedar entity type selection in VP calls. |
| `PrincipalRef` | `action` | Principal reference: wraps a `UserId` + `PrincipalKind`. Constructed via `PrincipalRef::new()` (User) or `PrincipalRef::machine()` (Machine). |

`PrincipalKind` determines which Cedar entity type is used when authorizing with Verified Permissions:

- `User` → `{ns}::user` (e.g. `forgeguard::user`)
- `Machine` → `{ns}::Machine` (e.g. `forgeguard::Machine`)

Machine principals carry an `org_id` attribute and have no group parents. The kind is set at resolver time (Ed25519 → Machine; Cognito JWT and static API key → User) and propagated through `Identity` → `build_query()` → `PrincipalRef`.

## Cedar types

The crate provides Cedar-specific types for policy and schema generation:

| Type                   | Purpose |
| ---------------------- | ------- |
| `CedarIdent`           | A validated Cedar identifier (ASCII alphanumeric + `_`). |
| `CedarEntityType`      | A qualified Cedar entity type (`Namespace::Entity`). |
| `CedarNamespace`       | A Cedar namespace identifier. |
| `EntitySchemaConfig`   | Configuration for generating a Cedar entity schema entry. |
| `CedarAttributeType`   | Cedar attribute type descriptors for schema attributes. |

### Action format

Actions follow the format `namespace:entity:action` (not `namespace:action:entity`). For example: `Api:Route:read`.

### Segment conversion

`Segment::to_cedar_ident()` converts route segments to valid Cedar identifiers with lossless `-` to `_` conversion, so that `my-route` becomes `my_route`.

### Schema generation

`generate_cedar_schema()` produces a Cedar JSON schema from the route configuration and entity schema configs. This is used by the CLI `policies validate` and `policies sync` commands.

## Optional Features

| Feature   | Purpose                                                                                                                |
| --------- | ---------------------------------------------------------------------------------------------------------------------- |
| `testing` | Exposes `forgeguard_core::features::testing` with `make_flag_override` and `make_flag_config` builders. Gated behind `cfg(any(test, feature = "testing"))` so internal tests get them automatically. For `FlagDefinition`, use `FlagDefinition::new(FlagDefinitionParams { ... })` directly — no builder is provided because `FlagDefinitionParams` already gives comfortable named-field construction. Other crates opt in via `[dev-dependencies] forgeguard_core = { ..., features = ["testing"] }`. |

## Visibility Conventions

The three feature-flag types — `FlagOverride`, `FlagDefinition`, `FlagConfig` — have private fields. Construct via `Type::new(...)` (or the `testing` builders for `FlagOverride` and `FlagConfig`); read via accessor methods. Encapsulation was chosen over a Parse-Don't-Validate split because no validation logic exists today — if invariants are added later, the private-field boundary is already in place.
