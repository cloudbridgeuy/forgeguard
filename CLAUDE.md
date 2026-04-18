# ForgeGuard — Development Guidelines

## Quick Reference

- **Error handling:** `thiserror` (libraries), `color-eyre` (binaries)
- **Logging:** `tracing` + `tracing-subscriber` — structured, span-based
- **Task runner:** `xtask` only — no Makefile, justfile, or scripts/
- **Dev watcher:** `bacon` — see `bacon.toml`
- **Pre-commit hooks:** `cargo xtask lint --install-hooks`
- **Commits:** Conventional Commits — see [commit-and-release.md](./.claude/context/commit-and-release.md)
- **Releases:** `cargo xtask release` — see [commit-and-release.md](./.claude/context/commit-and-release.md)
- **Rust toolchain:** pinned in `rust-toolchain.toml` (channel + required `components`) — see [ci.md](./.claude/context/ci.md)
- **CI:** GitHub Actions in `.github/workflows/ci.yml` — see [ci.md](./.claude/context/ci.md) for toolchain/typos/deny/rail rules
- **Container images:** distroless, multi-stage — see [container-builds.md](./.claude/context/container-builds.md)
- **Request signing:** optional Ed25519 outbound header signing — `[signing]` config, see [request-signing.md](./.claude/context/request-signing.md)
- **Cluster mode:** optional Redis-backed shared authz cache — `[cluster]` config, see [cluster.md](./.claude/context/cluster.md)
- **Metrics:** Prometheus via Pingora's `PrometheusServer` — `[metrics] enabled = true` in config
- **Control plane:** Axum service, `--store=memory` (dev) or `--store=dynamodb` (prod) — see [control-plane.md](./.claude/context/control-plane.md)
- **Optimistic locking:** `PUT /api/v1/organizations/{org_id}` honours RFC 7232 `If-Match` / `412` on proxy-config updates — see [optimistic-locking.md](./.claude/context/optimistic-locking.md)
- **CP auth:** optional Cognito JWT via `--jwks-url` + `--issuer`; omit for dev mode (no auth) — see [control-plane.md](./.claude/context/control-plane.md)
- **Infrastructure:** `cargo xtask control-plane infra {deploy,diff,destroy,status}` — CDK + 1Password, see [infra-control-plane.md](./.claude/context/infra-control-plane.md)
- **Cedar sync:** `cargo xtask control-plane cedar {status,diff,sync}` — VP policy management, see [verified-permissions.md](./.claude/context/verified-permissions.md)
- **Dogfooding config:** `forgeguard.toml` is the control plane's own authorization model; `forgeguard.example.toml` is the proxy reference config
- **DynamoDB tests:** `cargo xtask control-plane test` — auto-starts dynamodb-local via docker/podman
- **Integration tests:** `cargo test -p forgeguard_proxy` — see [demo-app.md](./.claude/context/demo-app.md)
- **Demo app:** native or Docker Compose — see [demo-app.md](./.claude/context/demo-app.md)
- **AWS defaults:** region `us-east-2`, profile `admin` — e.g. `--region us-east-2 --profile admin`
- **Environment:** only `prod` exists — do NOT use `--env dev` or `FORGEGUARD_ENV=dev`
- **GitHub CLI:** always use `gh auth switch --user cloudbridgeuy` before any `gh` command

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
- **Never `#[allow(clippy::too_many_arguments)]`** — use a `Params` / `Config` struct instead. Enforced by `cargo xtask lint`. See [params-struct-rule.md](./.claude/context/params-struct-rule.md)

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
lib/                   Published to crates.io — independent semver, full rustdocs
└── forgeguard-axum/   forgeguard-axum — Axum middleware (uses proxy-core)

crates/
│  Pure (no I/O) — published to crates.io as transitive deps (lock-step version)
├── core/              forgeguard_core — shared primitives, traits, error types
├── authn-core/        forgeguard_authn_core — identity resolution types and traits
├── authz-core/        forgeguard_authz_core — Cedar policy types, permission types
├── proxy-core/        forgeguard_proxy_core — auth pipeline, PipelineConfig, PipelineSource
│  Pure (no I/O) — not published (publish = false)
├── audit-core/        forgeguard_audit_core — event log types, audit trail schema
├── sdk/               forgeguard_sdk — Guard, WebhookHandler (WASM-compatible)
│  I/O — not published (publish = false)
├── authn/             forgeguard_authn — Cognito JWT resolver, JWKS caching
├── authz/             forgeguard_authz — Verified Permissions client, decision caching
├── http/              forgeguard_http — route matching, config, HTTP adapter (no Pingora)
├── audit/             forgeguard_audit — DynamoDB/S3 event log, CloudTrail
├── ffi-python/        forgeguard_ffi_python — PyO3 bindings
├── ffi-wasm/          forgeguard_ffi_wasm — wasm-bindgen bindings
│  Binaries — not published (publish = false)
├── control-plane/     forgeguard_control_plane — control plane API (Axum, file-backed org config)
├── worker/            forgeguard_worker — background Lambda jobs (reconciler, future jobs)
├── cli/               forgeguard_cli — developer CLI (binary: forgeguard)
├── proxy/             forgeguard_proxy — BYOC proxy: static + connected modes
├── proxy-saas/        forgeguard_proxy_saas — SaaS proxy: multi-org, lazy cache
└── back-office/       forgeguard_back_office — internal ops API

infra/
└── control-plane/     CDK v2 project (TypeScript + Bun) — DynamoDB Global Table

ui/
└── dashboard/         React + Vite SPA, built with Bun, hosted on CloudFront+S3
```

Each crate's `README.md` describes what it owns and its pure/I/O classification.

### Publishing Rules

- **`lib/` crates** — independent semver, own CHANGELOG.md, comprehensive rustdocs, separate GitHub release tags (`forgeguard-axum-v{version}`). Released via `cargo xtask release-lib`.
- **Published `crates/` deps** (`core`, `authn-core`, `authz-core`, `proxy-core`) — lock-step versioning (all share the same version). Published only when a `lib/` crate releases. Not promoted as standalone products.
- **Unpublished `crates/`** — `publish = false`, `version = "0.0.0"`. Everything else.

## Glossary

| Term | Definition |
| --- | --- |
| **Organization** | A ForgeGuard customer — the company that subscribes to ForgeGuard to protect their application. Each organization gets its own Cognito user pool and VP policy store. Identified by `OrganizationId`. |
| **Tenant** | An end-user partition within an organization's application. ForgeGuard helps organizations enforce tenant isolation via Cedar policies. Identified by `TenantId`. |
| **Control Plane** | ForgeGuard-operated SaaS: organization management, policy authoring, dashboard, billing. Contains no customer user data. |
| **Data Plane** | The runtime enforcement layer: proxy, identity resolution, authorization decisions. In SaaS mode, operated by ForgeGuard. In BYOC mode, deployed in the organization's AWS account. |
| **BYOC (Bring Your Own Cloud)** | Deployment model where the data plane runs in the organization's AWS account while the control plane remains ForgeGuard SaaS. |
| **Proxy (local — static)** | Single-organization proxy binary in static mode. Reads TOML config, fully self-contained. No control plane dependency. |
| **Proxy (local — connected)** | Single-organization proxy binary in connected mode. Fetches routes, flags, and upstream config from the control plane. Organization provides local AWS resource IDs (Cognito pool, VP store) at startup. The control plane syncs Cedar policies to the org's VP store. |
| **Proxy (SaaS)** | Multi-organization proxy binary operated by ForgeGuard. Resolves organization from request, lazy-loads per-org config via L1 in-memory cache, L2 CloudFront/S3 (SaaS) or authenticated Lambda API (BYOC). |
| **Worker** | Background Lambda binary (`forgeguard_worker`). Dispatches jobs by `FORGEGUARD_WORKER_JOB` env var. Currently: `reconciler` (sync pending DynamoDB records to S3). |

## Context Documents

| Document                                                           | Purpose                                                                 |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| [Linting and Clippy](./.claude/context/linting-and-clippy.md)      | Clippy thresholds, workspace lints, and how they map to design patterns |
| [Params Struct Rule](./.claude/context/params-struct-rule.md)      | Why we ban `#[allow(clippy::too_many_arguments)]` and how the lint enforces it |
| [Commit and Release](./.claude/context/commit-and-release.md)      | Conventional commits, version bump logic, release flow                  |
| [xtask lint](./.claude/context/xtask-lint.md)                      | Lint pipeline checks, flags, architecture, adding new checks            |
| [Feature Flags](./.claude/context/feature-flags.md)                | Flag types, evaluation order, overrides, debug endpoint, proxy wiring   |
| [Verified Permissions](./.claude/context/verified-permissions.md)   | VP integration: action format, Cedar types, CLI, config, infrastructure |
| [Container Builds](./.claude/context/container-builds.md)          | Distroless images, multi-stage builds, SSL strategy, health checks      |
| [CORS](./.claude/context/cors.md)                                  | CORS config, origin matching, request flow, crate placement             |
| [Proxy Shaping](./.claude/designs/proxy-shaping.md)                | Proxy design: requirements, shape, breadboard, slices                   |
| [SaaS Architecture](./.claude/context/saas-architecture.md)        | Control/data plane split, infra stack, worker saga, org domain model    |
| [Authn Wiring](./.claude/context/authn-wiring.md)                  | JWT + API key config, resolver construction, FCIS split                 |
| [CLI](./.claude/context/cli.md)                                    | `check`, `routes`, `policies`, `keygen` subcommands, FCIS architecture  |
| [Request Signing](./.claude/context/request-signing.md)            | Ed25519 signing: canonical payload, config, key rotation, crate layout  |
| [Demo App](./.claude/context/demo-app.md)                          | E2E demo: Python TODO app, native proxy, demo config, running instructions |
| [Control Plane](./.claude/context/control-plane.md)                | CP scaffold, proxy-config endpoint, OrgStore trait, auth, ETag, Draft / `ConfiguredConfig` lifecycle, testing |
| [Optimistic Locking](./.claude/context/optimistic-locking.md)      | `If-Match` / 412 on `PUT /organizations/{id}`: semantics, pure `etag.rs` core, error variant, V3 memory + Dynamo parity, V4 wildcard + POST ETag + 412 metrics |
| [Infra: Control Plane](./.claude/context/infra-control-plane.md)   | CDK project, 1Password integration, DynamoDB Global Table, xtask infra  |
| [Cluster Mode](./.claude/context/cluster.md)                       | TieredCache, Redis wiring, config, health stats, future slices          |
| [Dependency Constraints](./.claude/context/dependency-constraints.md) | Pingora version pins (rand, prometheus), jsonwebtoken crypto, reqwest TLS |
| [CI](./.claude/context/ci.md)                                      | GH Actions jobs, toolchain pinning rules, typos / cargo-deny / cargo-rail allowlists |
| [Design Documents](./.claude/context/)                             | Full ForgeGuard architecture and technical specifications               |

### Local-Only Documents (MUST NOT commit)

Plans (`.claude/plans/`) and designs (`.claude/designs/`) are **local-only** working documents. They are gitignored and must never be pushed to origin. Only `.claude/context/` and `.claude/commands/` are tracked in git.
