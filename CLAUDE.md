# ForgeGate — Development Guidelines

## Unnegotiables

### Crate Boundary FCIS (MUST)

Crate boundaries enforce the Functional Core / Imperative Shell split. This is not optional.

**The rule:** Any crate that has `tokio`, an AWS SDK, `reqwest`, or any I/O dependency is an **I/O crate**. I/O crates MUST NOT be depended on by pure crates. If you find a type in an I/O crate that another crate needs, that type MUST move down to a pure crate.

**Pure crates:**
- Export types, traits, and pure functions
- No I/O dependencies (`tokio`, `reqwest`, AWS SDKs, database drivers, etc.)
- Can be depended on by any crate (pure or I/O)

**I/O crates:**
- Consume types from pure crates and add side effects
- Depend downward into pure crates, never the reverse
- MUST NOT export types that other crates need

**Why:** The SDK crate must compile to `wasm32-unknown-unknown`. It literally cannot depend on I/O crates. This is a compiler requirement, not a design preference. Beyond WASM, this rule keeps the dependency graph clean and prevents contamination — no crate should be forced to pull in AWS SDKs just to use a domain type.

**Naming convention:** Pure crates use `forgegate_{domain}_core` (e.g., `forgegate_identity_core`). The shared primitives crate is `forgegate_core`. I/O crates drop the `_core` suffix (e.g., `forgegate_identity`).

### Error Handling

- `thiserror` for all library crates (structured error types)
- `color-eyre` for binary crates (rich error reports)

### Clippy

- `clippy.toml` with `too-many-arguments-threshold = 5`
- `#![deny(clippy::unwrap_used, clippy::expect_used)]` in every lib.rs and main.rs
- Test code may use `.unwrap()` (denials are in source, not workspace config)

### Code Quality

- No dead code
- No file over 1000 lines (enforced by xtask) — split immediately when approaching limit
- `cargo-rail` for dependency unification, dead feature detection, MSRV enforcement
- `cargo-deny` for license, advisory, and ban auditing

### Visibility (MUST)

- `pub(crate)` is the default visibility for internal functions and types
- `pub` only for the crate's public API surface
- No `pub` on struct fields unless necessary — use constructor functions (Parse Don't Validate)

### Error Types (MUST)

Each crate defines its own `Error` type and `Result` alias:

```rust
// In each crate's error.rs or lib.rs:
pub type Result<T> = std::result::Result<T, Error>;
```

Use `forgegate_authn_core::Error` at call sites if disambiguation is needed. Do NOT prefix error types with the domain name (no `AuthnError`).

### Module Organization

- Start flat (`src/error.rs`, `src/config.rs`)
- Promote to directory module (`src/chunk/mod.rs`) when a file exceeds ~300 lines or needs sub-modules
- The 1000-line xtask lint check is the hard limit; split well before that

### Logging

- `tracing` + `tracing-subscriber` (not `env_logger`)
- Structured, span-based logging for auth flows, metrics, and observability

## Patterns

See `~/.claude/patterns/` for architectural patterns. Key ones for this project:

- **Functional Core / Imperative Shell** — enforced at crate boundaries (see above)
- **Type-Driven Development** — types are the spec; typestate for auth flows
- **Make Impossible States Impossible** — enum variants, not boolean flags
- **Parse Don't Validate** — at system boundaries
- **CQRS** — command/query separation

### Git Commits (MUST)

All commits MUST follow [Conventional Commits](https://www.conventionalcommits.org/) for git-cliff changelog generation.

**Format:**
```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat` — new feature or capability
- `fix` — bug fix
- `refactor` — code change that neither fixes a bug nor adds a feature
- `docs` — documentation only
- `test` — adding or updating tests
- `ci` — CI/CD changes
- `chore` — maintenance (deps, tooling, config)
- `perf` — performance improvement
- `style` — formatting, whitespace (no logic change)

**Scopes** — use the crate name suffix (not the full `forgegate_` prefix):
- `core`, `authn-core`, `authz-core`, `audit-core`
- `authn`, `authz`, `audit`
- `sdk`, `ffi-python`, `ffi-wasm`
- `control-plane`, `agent`, `cli`, `proxy`, `back-office`
- `xtask`, `ci`, `docker`

**Examples:**
```
feat(authn-core): add MagicLinkFlow typestate definitions
fix(authz): handle expired Cedar policy cache gracefully
refactor(sdk): extract Guard trait into separate module
docs(cli): add installation instructions
ci: add WASM build check to CI pipeline
chore(deps): bump aws-sdk-dynamodb to 1.x
```

**Rules:**
- Scope is optional but strongly encouraged
- Description is imperative mood, lowercase, no period
- Breaking changes: add `!` after type/scope (e.g., `feat(sdk)!: change Guard API`)
- Multi-crate changes: use the most relevant scope, mention others in body

## Workspace Structure

```
forgegate/
├── crates/
│   │  # Pure crates (no I/O dependencies)
│   ├── core/              # forgegate_core — shared primitives, traits, error types
│   ├── authn-core/        # forgegate_authn_core — typestate flows, transition types
│   ├── authz-core/        # forgegate_authz_core — Cedar policy types, permission types
│   ├── audit-core/        # forgegate_audit_core — event log types, audit trail schema
│   ├── sdk/               # forgegate_sdk — Guard, WebhookHandler (WASM-compatible)
│   │
│   │  # I/O crates (depend on pure crates)
│   ├── authn/             # forgegate_authn — Cognito adapter, SES/SNS side effects
│   ├── authz/             # forgegate_authz — Verified Permissions client, caching
│   ├── audit/             # forgegate_audit — DynamoDB/S3 event log, CloudTrail
│   ├── ffi-python/        # forgegate_ffi_python — PyO3 bindings
│   ├── ffi-wasm/          # forgegate_ffi_wasm — wasm-bindgen bindings
│   │
│   │  # Binary crates
│   ├── control-plane/     # forgegate_control_plane — dashboard API server
│   ├── agent/             # forgegate_agent — self-hosted data plane
│   ├── cli/               # forgegate_cli — developer CLI
│   ├── proxy/             # forgegate_proxy — request interception proxy
│   └── back-office/       # forgegate_back_office — internal ops API
├── xtask/                 # build automation (lint, conformance)
└── conformance/           # conformance test fixtures (JSON)
```

## Tooling

- **Task runner:** `xtask` only (no Makefile, justfile, or scripts/ directory)
- **Dev watcher:** `bacon` (see bacon.toml)
- **Typo checker:** `typos` (see _typos.toml)
- **CI change detection:** `cargo-rail` (selective crate testing)
- **Pre-commit hooks:** `cargo xtask lint --install-hooks`
- **Changelog:** `git-cliff` (configured via `cliff.toml`)
- **Release:** `cargo xtask release` (auto version bump from commit history, `--major` override)
