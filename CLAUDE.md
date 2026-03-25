# ForgeGuard — Development Guidelines

## Quick Reference

- **Error handling:** `thiserror` (libraries), `color-eyre` (binaries)
- **Logging:** `tracing` + `tracing-subscriber` — structured, span-based
- **Task runner:** `xtask` only — no Makefile, justfile, or scripts/
- **Dev watcher:** `bacon` — see `bacon.toml`
- **Pre-commit hooks:** `cargo xtask lint --install-hooks`
- **Commits:** Conventional Commits — see [commit-and-release.md](./.claude/context/commit-and-release.md)
- **Releases:** `cargo xtask release` — see [commit-and-release.md](./.claude/context/commit-and-release.md)

## Unnegotiables

### Crate Boundary FCIS (MUST)

Crate boundaries enforce the Functional Core / Imperative Shell split.

**The rule:** Any crate with `tokio`, AWS SDKs, `reqwest`, or any I/O dependency is an **I/O crate**. I/O crates MUST NOT be depended on by pure crates. If a type in an I/O crate is needed elsewhere, it MUST move down to a pure crate.

- **Pure crates** — types, traits, pure functions. No I/O deps. Any crate can depend on them.
- **I/O crates** — consume pure crate types, add side effects. Depend downward only.
- **Why** — SDK must compile to `wasm32-unknown-unknown`. This is a compiler requirement.
- **Naming** — pure: `forgeguard{domain}_core`. I/O: `forgeguard{domain}` (no `_core` suffix).

### Visibility (MUST)

- `pub(crate)` default for internal functions and types
- `pub` only for public API surface
- No `pub` struct fields — use constructor functions (Parse Don't Validate)

### Error Types (MUST)

Each crate defines `Error` and `Result<T> = std::result::Result<T, Error>`. No domain-prefixed error names (no `AuthnError`). Disambiguate with `forgeguardauthn_core::Error`.

### Clippy (MUST)

- `#![deny(clippy::unwrap_used, clippy::expect_used)]` in every lib.rs and main.rs
- Workspace lints enforce pattern compliance — see [linting-and-clippy.md](./.claude/context/linting-and-clippy.md)
- Test code may use `.unwrap()`

### Verification (MUST)

**`cargo xtask lint` is the single source of truth for code quality.** Run it to validate all changes. Do NOT run `cargo fmt`, `cargo clippy`, `cargo test`, or `cargo check` individually — `xtask lint` runs them all in the correct order and with the correct flags.

- **Before claiming work is done:** run `cargo xtask lint` and confirm exit code 0 (zero output = pass)
- **To auto-fix:** `cargo xtask lint --fix` (applies formatting + clippy fixes)
- Pipeline details: see [xtask-lint.md](./.claude/context/xtask-lint.md)

### Code Quality

- No dead code
- No file over 1000 lines (enforced by xtask) — split at ~300 lines
- `cargo-rail` for dependency unification, dead feature detection, MSRV enforcement
- `cargo-deny` for license and advisory auditing

### Module Organization

Start flat (`src/error.rs`). Promote to directory module when a file exceeds ~300 lines.

### Git Commits (MUST)

Conventional Commits required for `git-cliff`. Full reference: [commit-and-release.md](./.claude/context/commit-and-release.md)

Format: `<type>(<scope>): <description>`. Breaking changes: add `!`. Scopes: crate suffix (e.g., `authn-core`, `sdk`, `cli`).

## Patterns

See `~/.claude/patterns/` for architectural patterns:

- **Functional Core / Imperative Shell** — enforced at crate boundaries
- **Type-Driven Development** — types are the spec; typestate for auth flows
- **Make Impossible States Impossible** — enum variants, not boolean flags
- **Parse Don't Validate** — at system boundaries
- **CQRS** — command/query separation

## Workspace Structure

```
crates/
│  Pure (no I/O)
├── core/              forgeguardcore — shared primitives, traits, error types
├── authn-core/        forgeguardauthn_core — identity resolution types and traits
├── authz-core/        forgeguardauthz_core — Cedar policy types, permission types
├── audit-core/        forgeguardaudit_core — event log types, audit trail schema
├── sdk/               forgeguardsdk — Guard, WebhookHandler (WASM-compatible)
│  I/O
├── authn/             forgeguardauthn — Cognito adapter, SES/SNS
├── authz/             forgeguardauthz — Verified Permissions, caching
├── audit/             forgeguardaudit — DynamoDB/S3 event log, CloudTrail
├── ffi-python/        forgeguardffi_python — PyO3 bindings
├── ffi-wasm/          forgeguardffi_wasm — wasm-bindgen bindings
│  Binaries
├── control-plane/     forgeguardcontrol_plane — dashboard API
├── agent/             forgeguardagent — self-hosted data plane
├── cli/               forgeguardcli — developer CLI (binary: forgeguard)
├── proxy/             forgeguardproxy — request interception
└── back-office/       forgeguardback_office — internal ops API
```

Each crate's `README.md` describes what it owns and its pure/I/O classification.

## Context Documents

| Document                                                           | Purpose                                                                 |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| [Linting and Clippy](./.claude/context/linting-and-clippy.md)      | Clippy thresholds, workspace lints, and how they map to design patterns |
| [Commit and Release](./.claude/context/commit-and-release.md)      | Conventional commits, version bump logic, release flow                  |
| [xtask lint](./.claude/context/xtask-lint.md)                      | Lint pipeline checks, flags, architecture, adding new checks            |
| [Scaffolding Decisions](./.claude/designs/scaffolding-patterns.md) | All 36 design decisions with rationale                                  |
| [Design Documents](./.claude/context/)                             | Full ForgeGuard architecture and technical specifications               |
