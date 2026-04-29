# Visibility Conventions

How `pub`, `pub(crate)`, and private fields are used across the workspace, plus the documented exceptions.

## The Rules

1. **`pub(crate)` is the default for internal items.** Anything you don't intentionally expose to dependents stays crate-local.
2. **`pub` is reserved for public API surface.** A `pub` item commits the crate to maintaining that signature.
3. **No `pub` struct fields on domain types.** Construct through `Type::new(...)` (or `Type::try_new(...)` when validation can fail), read through `&self` accessors. Private fields preserve the encapsulation boundary so you can add invariants later without breaking callers.

## Constructor + Accessor Shape

```rust
pub struct FlagOverride {
    tenant: Option<TenantId>,
    user: Option<UserId>,
    group: Option<GroupName>,
    value: FlagValue,
}

impl FlagOverride {
    pub fn new(
        tenant: Option<TenantId>,
        user: Option<UserId>,
        group: Option<GroupName>,
        value: FlagValue,
    ) -> Self { Self { tenant, user, group, value } }

    pub fn tenant(&self) -> Option<&TenantId> { self.tenant.as_ref() }
    pub fn user(&self)   -> Option<&UserId>   { self.user.as_ref() }
    pub fn group(&self)  -> Option<&GroupName> { self.group.as_ref() }
    pub fn value(&self)  -> &FlagValue        { &self.value }
}
```

Why accessors return references: callers rarely need ownership, and `&T` forces the caller to copy/clone explicitly when they do — keeping the cost visible.

## When Constructors Grow Past 5 Args: Params Struct

`clippy.toml` sets `too-many-arguments-threshold = 5`. When a constructor needs more than five arguments, replace the positional list with a Params struct. `pub` fields on a Params struct are the **one carve-out** from the no-`pub`-fields rule — Params structs carry no invariants beyond those of their field types.

Full rules: [params-struct-rule.md](./params-struct-rule.md).

```rust
pub struct FlagDefinitionParams {
    pub flag_type: FlagType,
    pub default_value: FlagValue,
    pub enabled: bool,
    pub overrides: Vec<FlagOverride>,
    pub rollout_percentage: Option<u8>,
    pub rollout_variant: Option<FlagValue>,
}

impl FlagDefinition {
    pub fn new(params: FlagDefinitionParams) -> Self { /* ... */ }
}
```

Use `pub(crate)` Params fields when the struct is crate-internal (e.g. `ProxyParams` in `crates/proxy/src/proxy.rs` — `pub(crate)` because it stays inside the proxy binary).

## Cross-Crate Test Helpers: the `testing` Cargo Feature

When a pure crate's domain type has private fields, downstream crates' tests can't construct fixtures directly. The pattern: ship a `testing` Cargo feature that exposes constructor helpers behind a `cfg`-gated module.

**In the producing crate** (`crates/core/Cargo.toml`):

```toml
[features]
testing = []
```

**In `lib.rs` / module root**:

```rust
#[cfg(any(test, feature = "testing"))]
pub mod testing;
```

The `cfg(any(test, feature = "testing"))` gate ensures:
- In-crate tests get the helpers automatically (no feature flag needed).
- Downstream crates opt in via `[dev-dependencies]`.
- Production builds never see the helpers — the module is invisible without the feature.

**The `testing` module** holds thin wrapper functions, not full builder DSLs:

```rust
//! Test-only constructors for feature-flag types.
//!
//! Gated behind `cfg(any(test, feature = "testing"))`.

use crate::{FlagConfig, FlagDefinition, FlagName, FlagOverride, FlagValue, GroupName, TenantId, UserId};

pub fn make_flag_override(
    tenant: Option<TenantId>,
    user: Option<UserId>,
    group: Option<GroupName>,
    value: FlagValue,
) -> FlagOverride {
    FlagOverride::new(tenant, user, group, value)
}

pub fn make_flag_config(pairs: impl IntoIterator<Item = (FlagName, FlagDefinition)>) -> FlagConfig {
    FlagConfig::new(pairs.into_iter().collect())
}
```

**Downstream consumer** (`crates/proxy-core/Cargo.toml`):

```toml
[dev-dependencies]
forgeguard_core = { workspace = true, features = ["testing"] }
```

### When to Add a Helper vs. Use the Constructor Directly

- **Add a `make_*` helper** when the constructor takes multiple positional args of similar types and the helper meaningfully reduces test noise (e.g. `FlagOverride` — four `Option<_>` / single value).
- **Skip the helper** when a Params struct already provides named-field readability (e.g. `FlagDefinition::new(FlagDefinitionParams { ... })` is already clear; wrapping it would be a no-op).
- Helpers are **thin wrappers** over the public constructor. Never hide invariants in the helper — if a helper needs to do "validation lite," that logic belongs in the public constructor instead.

## The Axum Extractor PDV Exception

Axum `FromRequestParts` extractors that callers destructure inline (`async fn handler(ForgeGuardIdentity(id): ForgeGuardIdentity)`) **must** keep their tuple-struct field public. Without `pub`, the destructure pattern fails to compile in handler parameter position.

This is the documented exception in `lib/forgeguard-axum/src/extractor.rs`:

```rust
/// PDV exception: tuple-struct field is intentionally pub. Making it
/// private would prevent destructuring in handler parameter position,
/// which is the canonical Axum extractor usage pattern.
pub struct ForgeGuardIdentity(pub Identity);
```

Apply this carve-out only to types whose primary use is being destructured by handler signatures. Library types that callers consume through methods stay private-fields-only.

## Verifying Compliance

A grep audit catches struct-literal construction that bypasses constructors:

```bash
grep -rn 'FlagOverride {\|FlagDefinition {\|FlagConfig {' crates lib --include='*.rs'
```

Hits should appear only in:
- The struct declaration line (`pub struct Foo {`)
- The `impl Foo {` block opener
- Function signatures with `Foo` in return position (`-> Foo {`)

Any `Foo { field: value, ... }` literal outside the owning module's `impl` is a regression.

## Worked Examples in the Workspace

| Type | Constructor | Accessors | Test helper |
| --- | --- | --- | --- |
| `FlagOverride` | `new()` | `tenant()`, `user()`, `group()`, `value()` | `testing::make_flag_override` |
| `FlagDefinition` | `new(FlagDefinitionParams)` | `flag_type()`, `default_value()`, `overrides()`, etc. | none — use Params directly |
| `FlagConfig` | `new()` | `flags()`, `is_empty()`, `insert()` | `testing::make_flag_config` |
| `Organization` | `new()` | `status()`, `name()`, etc.; mutators `transition_to()`, `update_name()` | n/a |
| `Identity` | `new(IdentityParams)` | `user_id()`, `tenant_id()`, `groups()`, etc. | n/a |
| `ProxyParams` | (Params struct, `pub(crate)` fields) | n/a — consumed by `ForgeGuardProxy::new` | n/a |
| `ForgeGuardIdentity` | tuple-struct, `pub` field | n/a — destructured | n/a |

## Related

- [params-struct-rule.md](./params-struct-rule.md) — when to introduce a Params struct, the `clippy.toml` threshold, the `xtask lint` enforcement.
- [linting-and-clippy.md](./linting-and-clippy.md) — workspace lint config and how it maps to patterns.
- `~/.claude/patterns/parse-dont-validate.md` — why constructors should be the validation seam.
- `~/.claude/patterns/type-driven-development.md` — types as specification.
