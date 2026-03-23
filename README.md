# ForgeGate

Authorization-as-a-service platform built on AWS. Smithy-based schema language, typestate authentication flows, Cedar-based authorization, and multi-language SDKs.

## Architecture

ForgeGate uses a Control Plane + Data Plane split:

- **Control Plane** — Dashboard API for managing schemas, users, permissions, policies, feature flags, and webhooks
- **Data Plane** — Self-hosted agent deployed in customer AWS accounts for local authorization decisions
- **SDK** — Rust core with FFI wrappers (Python via PyO3, TypeScript via WASM)
- **CLI** — Developer tooling for schema validation, policy testing, and local development

## Workspace Structure

```
crates/
│  Pure crates (no I/O dependencies)
├── core/              forgegate_core — shared primitives, traits, error types
├── authn-core/        forgegate_authn_core — typestate flows, transition types
├── authz-core/        forgegate_authz_core — Cedar policy types, permission types
├── audit-core/        forgegate_audit_core — event log types, audit trail schema
├── sdk/               forgegate_sdk — Guard, WebhookHandler (WASM-compatible)
│
│  I/O crates (depend on pure crates)
├── authn/             forgegate_authn — Cognito adapter, SES/SNS side effects
├── authz/             forgegate_authz — Verified Permissions client, caching
├── audit/             forgegate_audit — DynamoDB/S3 event log, CloudTrail
├── ffi-python/        forgegate_ffi_python — PyO3 bindings
├── ffi-wasm/          forgegate_ffi_wasm — wasm-bindgen bindings
│
│  Binary crates
├── control-plane/     forgegate_control_plane — dashboard API server
├── agent/             forgegate_agent — self-hosted data plane
├── cli/               forgegate_cli — developer CLI (binary: forgegate)
├── proxy/             forgegate_proxy — request interception proxy
└── back-office/       forgegate_back_office — internal ops API
```

Crate boundaries enforce the Functional Core / Imperative Shell pattern. Pure crates contain types, traits, and deterministic logic. I/O crates add side effects. Pure crates never depend on I/O crates.

## Getting Started

### Prerequisites

- Rust (stable, see `rust-version` in `Cargo.toml` for MSRV)
- [bacon](https://github.com/Canop/bacon) — development task runner
- [cargo-rail](https://github.com/nickel-org/cargo-rail) — dependency analysis and CI change detection
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

## License

MIT
