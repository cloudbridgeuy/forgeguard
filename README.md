# ForgeGuard

Multi-tenant authorization for B2B applications: one enforcement point where "who can do what, on which part of the tenant tree, under which entitlement" lives. Hierarchy-aware policy over an organizational spine, a signed header contract, entitlements unified with permissions, and audit as free exhaust of enforcement.

The product specification is [`docs/brief.md`](docs/brief.md) (Brief v1.4). The execution plan against this repository is [`docs/repo-reconciliation.md`](docs/repo-reconciliation.md); the candidate engineering design is [`docs/design-a1.md`](docs/design-a1.md). See [ADR-0004](docs/adr/0004-brief-v1.4-supersedes-resolution-engine-framing.md) for why this framing supersedes earlier ones.

## Architecture

ForgeGuard uses a Control Plane + Data Plane split:

- **Control Plane** — Dashboard API for managing schemas, users, permissions, policies, feature flags, and webhooks
- **Data Plane** — Self-hosted agent deployed in customer AWS accounts for local authorization decisions
- **SDK** — Rust core with FFI wrappers (Python via PyO3, TypeScript via WASM)
- **CLI** — Developer tooling for schema validation, policy testing, and local development

## Workspace Structure

```
crates/
│  Pure crates (no I/O dependencies)
├── core/              forgeguard_core — shared primitives, traits, error types
├── authn-core/        forgeguard_authn_core — typestate flows, transition types
├── authz-core/        forgeguard_authz_core — Cedar policy types, permission types
├── audit-core/        forgeguard_audit_core — event log types, audit trail schema
├── sdk/               forgeguard_sdk — Guard, WebhookHandler (WASM-compatible)
│
│  I/O crates (depend on pure crates)
├── authn/             forgeguard_authn — Cognito adapter, SES/SNS side effects
├── authz/             forgeguard_authz — Verified Permissions client, caching
├── audit/             forgeguard_audit — DynamoDB/S3 event log, CloudTrail
├── ffi-python/        forgeguard_ffi_python — PyO3 bindings
├── ffi-wasm/          forgeguard_ffi_wasm — wasm-bindgen bindings
│
│  Binary crates
├── control-plane/     forgeguard_control_plane — dashboard API server
├── cli/               forgeguard_cli — developer CLI (binary: forgeguard)
├── proxy/             forgeguard_proxy — request interception proxy
└── back-office/       forgeguard_back_office — internal ops API
```

Crate boundaries enforce the Functional Core / Imperative Shell pattern. Pure crates contain types, traits, and deterministic logic. I/O crates add side effects. Pure crates never depend on I/O crates.

## Getting Started

### Prerequisites

- Rust (stable, see `rust-version` in `Cargo.toml` for MSRV)
- [bacon](https://github.com/Canop/bacon) — development task runner
- [cargo-rail](https://github.com/nickel-org/cargo-rail) — dependency analysis and CI change detection
- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/) — required for infrastructure commands
- Docker — for LocalStack integration tests

### Build

```bash
cargo check --workspace
```

### Development

```bash
# Interactive development (check on save)
bacon

# Run all lint checks
cargo xtask lint

# Install pre-commit hooks
cargo xtask lint --install-hooks
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Start LocalStack for integration tests
docker compose up -d
```

## Infrastructure

Manage control-plane infrastructure with `cargo xtask control-plane infra`:

```bash
cargo xtask control-plane infra deploy [--env <ENV>]   # Deploy CDK infrastructure
cargo xtask control-plane infra diff [--env <ENV>]     # Preview changes
cargo xtask control-plane infra destroy [--env <ENV>]  # Destroy (requires confirmation)
cargo xtask control-plane infra status [--env <ENV>]   # Show stack status
```

Requires 1Password CLI (`op`) and `bun`. Environment defaults to `prod`; override with `--env` or `FORGEGUARD_ENV`.

## Demo

See [`examples/todo-app/`](examples/todo-app/) for a working end-to-end demonstration: a Python/FastAPI TODO app running behind the ForgeGuard proxy with JWT auth, API keys, public routes, feature flags, policy evaluation, and header injection.

## License

MIT
