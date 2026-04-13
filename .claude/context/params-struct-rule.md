# Params Struct Rule

**Rule:** Never `#[allow(clippy::too_many_arguments)]`. Always replace wide-arity
signatures with a `Params` / `Config` struct.

## Why

Our `clippy.toml` sets `too-many-arguments-threshold = 5`. When a constructor or
function grows past five arguments, the right move is to name the arguments — not
to suppress the lint. Positional arguments at wide arity are error-prone: swapping
two `Option<T>` of the same type compiles silently; `Params` structs force each
call site to use field names.

This aligns with two project patterns:

- **Parse Don't Validate** — each Params field already carries its invariants
  through its type (e.g. `UserId`, `TenantId`, `ProjectId`), so the struct is a
  named bag of validated values, not a second validation surface.
- **Make Impossible States Impossible** — named fields make call-site omissions
  a compiler error rather than a silent swap.

## Shape

Params structs are the one carve-out from "no `pub` struct fields" (see
CLAUDE.md). They carry no invariants beyond those of their field types, so the
constructor-function requirement doesn't apply.

```rust
pub struct IdentityParams {
    pub user_id: UserId,
    pub tenant_id: Option<TenantId>,
    pub groups: Vec<GroupName>,
    pub expiry: Option<DateTime<Utc>>,
    pub resolver: &'static str,
    pub extra: Option<serde_json::Value>,
}

impl Identity {
    pub fn new(params: IdentityParams) -> Self { /* ... */ }
}
```

Use `pub(crate)` fields when the Params struct is crate-internal (see
`AwsConfigParams`, `CliTestFlags`, `ProxyParams`).

## Enforcement

`cargo xtask lint` runs a check named `forbid #[allow(clippy::too_many_arguments)]`
that scans workspace Rust source and fails on any occurrence of the attribute —
singleton, grouped, or inner (`#![allow(...)]`). Doc comments and string literals
are not false-matched because the check anchors on
`trim_start().starts_with("#[" | "#![")`.

**Scope**: `crates/*/src/**/*.rs`, `lib/*/src/**/*.rs`, `xtask/src/**/*.rs`.

**Test-code exemption**: lines inside a `#[cfg(test)]`-gated `mod { ... }` (or
any `#[cfg(test)]`-gated item with a brace body) are exempt. Tracked via a
brace-depth stack in the scanner. Integration tests under `tests/**` are not in
scope and therefore inherently exempt.

**Skip flag**: `cargo xtask lint --no-too-many-args` (consistent with other skip
flags; intended for local debugging, never for CI).

## If You Hit the Check

You added a function with six or more arguments. Two refactors work:

- **Plain Params struct**: one field per argument, named at the call site.
  Prefer this when the arguments have no internal relationships.
- **Grouped sub-structs**: when several arguments naturally cluster (e.g. all
  cache settings), extract a sub-struct and nest it inside the top-level Params.

Do not reach for builders just to satisfy this rule — builders add complexity
(state machines, partial construction) that a Params struct does not.

## Examples in the Workspace

| Constructor | Params struct |
| --- | --- |
| `Identity::new` | `IdentityParams` (`crates/authn-core/src/identity.rs`) |
| `PipelineConfig::new` | `PipelineConfigParams` (`crates/proxy-core/src/pipeline_config.rs`) |
| `ForgeGuardProxy::new` | `ProxyParams` (`crates/proxy/src/proxy.rs`) |
| `build_sdk_config` | `AwsConfigParams<'_>` (`crates/cli/src/aws.rs`) |

## Related

- `clippy.toml` — threshold is 5, not clippy's default 7.
- `.claude/context/linting-and-clippy.md` — how the lint config maps to project patterns.
- `.claude/context/xtask-lint.md` — the lint pipeline, how to add a new check.
