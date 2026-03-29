# forgeguard_core

Shared primitives, traits, and error types for the ForgeGuard workspace. This is a **pure crate** — it contains no I/O dependencies and can be depended on by any crate in the workspace.

Owns domain-level identifiers (TenantId, UserId, PolicyId), common trait definitions for storage and cache abstractions, and shared error types.

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
