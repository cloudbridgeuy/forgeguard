# ForgeGate — Development Guidelines

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
- **Naming** — pure: `forgegate_{domain}_core`. I/O: `forgegate_{domain}` (no `_core` suffix).

### Visibility (MUST)

- `pub(crate)` default for internal functions and types
- `pub` only for public API surface
- No `pub` struct fields — use constructor functions (Parse Don't Validate)

### Error Types (MUST)

Each crate defines `Error` and `Result<T> = std::result::Result<T, Error>`. No domain-prefixed error names (no `AuthnError`). Disambiguate with `forgegate_authn_core::Error`.

### Clippy (MUST)

- `#![deny(clippy::unwrap_used, clippy::expect_used)]` in every lib.rs and main.rs
- Workspace lints enforce pattern compliance — see [linting-and-clippy.md](./.claude/context/linting-and-clippy.md)
- Test code may use `.unwrap()`

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
├── core/              forgegate_core — shared primitives, traits, error types
├── authn-core/        forgegate_authn_core — typestate flows, transition types
├── authz-core/        forgegate_authz_core — Cedar policy types, permission types
├── audit-core/        forgegate_audit_core — event log types, audit trail schema
├── sdk/               forgegate_sdk — Guard, WebhookHandler (WASM-compatible)
│  I/O
├── authn/             forgegate_authn — Cognito adapter, SES/SNS
├── authz/             forgegate_authz — Verified Permissions, caching
├── audit/             forgegate_audit — DynamoDB/S3 event log, CloudTrail
├── ffi-python/        forgegate_ffi_python — PyO3 bindings
├── ffi-wasm/          forgegate_ffi_wasm — wasm-bindgen bindings
│  Binaries
├── control-plane/     forgegate_control_plane — dashboard API
├── agent/             forgegate_agent — self-hosted data plane
├── cli/               forgegate_cli — developer CLI (binary: forgegate)
├── proxy/             forgegate_proxy — request interception
└── back-office/       forgegate_back_office — internal ops API
```

Each crate's `README.md` describes what it owns and its pure/I/O classification.

## Context Documents

| Document | Purpose |
|----------|---------|
| [Linting and Clippy](./.claude/context/linting-and-clippy.md) | Clippy thresholds, workspace lints, and how they map to design patterns |
| [Commit and Release](./.claude/context/commit-and-release.md) | Conventional commits, version bump logic, release flow |
| [Scaffolding Decisions](./.claude/designs/scaffolding-patterns.md) | All 36 design decisions with rationale |
| [Design Documents](./.claude/context/) | Full ForgeGate architecture and technical specifications |
