# Linting and Clippy Configuration

## Overview

ForgeGate enforces code quality through three layers:

1. **`clippy.toml`** — threshold configuration
2. **`[workspace.lints.clippy]`** in `Cargo.toml` — lint levels
3. **Source-level denials** — `#![deny(...)]` in each crate's lib.rs/main.rs

## clippy.toml Thresholds

| Setting | Value | Default | Rationale |
|---------|-------|---------|-----------|
| `too-many-arguments-threshold` | `5` | `7` | Forces config/options structs instead of long parameter lists |
| `max-fn-params-bools` | `1` | `3` | Multiple bool params → use an enum. Maps to **Make Impossible States Impossible** |
| `cognitive-complexity-threshold` | `15` | `25` | Encourages smaller, testable pure functions. Maps to **Functional Core** |

## Workspace Lint Levels

Configured in `Cargo.toml` under `[workspace.lints.clippy]`:

### Denied (compile error)

| Lint | Pattern | Why |
|------|---------|-----|
| `enum_glob_use` | Make Impossible States Impossible | Force explicit variant names; ensures exhaustive matching is meaningful |
| `wildcard_imports` | Make Impossible States Impossible | Explicit imports prevent accidentally using the wrong type |

### Warned

| Lint | Pattern | Why |
|------|---------|-----|
| `manual_let_else` | Parse Don't Validate | Encourages `let Some(x) = expr else { return }` for cleaner boundary parsing |
| `large_enum_variant` | Algebraic Data Types | Catches enums with huge size disparity between variants — consider boxing |
| `implicit_clone` | Clarity | Makes `.clone()` calls visible rather than hidden behind method resolution |
| `cloned_instead_of_copied` | Clarity | Use `.copied()` for Copy types to signal intent |
| `redundant_closure_for_method_calls` | Clarity | Prefer `iter.map(ToString::to_string)` over `iter.map(\|x\| x.to_string())` |
| `needless_pass_by_value` | Clarity | Prefer borrowing unless ownership is actually needed |

## Source-Level Denials

In every `lib.rs` and `main.rs`:

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]
```

These live in source (not workspace config) so test code can still use `.unwrap()` for brevity. The `#[cfg(test)]` module is not subject to these denials.

## Why This Split?

- **Thresholds** in `clippy.toml` — these are numeric values, not lint on/off switches
- **Lint levels** in `Cargo.toml` — workspace-wide, inherited by all crates via `[lints] workspace = true`
- **Source denials** — per-crate, scoped to production code (not tests)
