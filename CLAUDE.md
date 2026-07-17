# ForgeGuard — Development Guidelines

## Quick Reference

- **Error handling:** `thiserror` (libraries), `color-eyre` (binaries)
- **Logging:** `tracing` + `tracing-subscriber` — structured, span-based
- **Task runner:** `xtask` only — install wrapper once with `cargo install --path xtask/cargo-xtask --locked`; no Makefile, justfile, or scripts/
- **xtask wrapper:** `cargo-xtask` skips cargo's fingerprint on the hot path; force rebuild with `cargo xtask --rebuild <subcommand>` — see [xtask/cargo-xtask/README.md](./xtask/cargo-xtask/README.md)
- **Dev watcher:** `bacon` — see `bacon.toml`
- **Pre-commit hooks:** `cargo xtask lint --install-hooks`
- **Commits:** Conventional Commits — see [commit-and-release.md](./.claude/context/commit-and-release.md)
- **Newtypes:** wrap primitives at deserialize boundaries (`Percentage`, `ConfigVersion`, `SagaId`, `Etag`, `KeyId`, `UserId`, `TenantId`, …) — never `etag: String` / `version: String` / `rollout_percentage: u8` in domain types. See [newtypes.md](./.claude/context/newtypes.md)
- **Releases:** `cargo xtask release` — see [commit-and-release.md](./.claude/context/commit-and-release.md)
- **Rust toolchain:** pinned in `rust-toolchain.toml` (channel + required `components`) — see [ci.md](./.claude/context/ci.md)
- **CI:** GitHub Actions in `.github/workflows/ci.yml` — see [ci.md](./.claude/context/ci.md) for toolchain/typos/deny/rail rules
- **Container images:** distroless, multi-stage — see [container-builds.md](./.claude/context/container-builds.md)
- **Request signing:** optional Ed25519 outbound header signing — `[signing]` config, see [request-signing.md](./.claude/context/request-signing.md)
- **Cluster mode:** optional Redis-backed shared authz cache — `[cluster]` config, see [cluster.md](./.claude/context/cluster.md)
- **Metrics:** Prometheus via Pingora's `PrometheusServer` — `[metrics] enabled = true` in config
- **Control plane:** Axum service, `--store=memory` (dev) or `--store=dynamodb` (prod). `OrgStore` is object-safe via `#[async_trait]`; runtime carries `Arc<dyn OrgStore>`. Handlers take `State<Arc<dyn OrgStore>>` (or `State<AppState<V>>` for VP-aware group writes via `FromRef`) — never `<S: OrgStore>` — see [control-plane.md](./.claude/context/control-plane.md)
- **Optimistic locking:** groups/user-schema `PUT`/`DELETE` honour RFC 7232 `If-Match` / `412`; org `PUT` is revision-tokened instead (`X-Fg-If-Revision`, #113 V1) — see the superseded-banner in [optimistic-locking.md](./.claude/context/optimistic-locking.md)
- **CP auth:** optional Cognito JWT via `--jwks-url` + `--issuer`; omit for dev mode (no auth) — see [control-plane.md](./.claude/context/control-plane.md)
- **CP authz (V4):** `VpPolicyEngine` with `DefaultPolicy::Deny` when `--jwks-url` + `--policy-store-id` are set; `cp:*` action mapping — see [control-plane.md](./.claude/context/control-plane.md)
- **CP role model:** RBAC roles `member` → `admin` → `owner`, auto tenant-scoped via `principal.org_id == resource.org_id`; single machine permit `machine-proxy-config-read` for proxy config reads — see [verified-permissions.md](./.claude/context/verified-permissions.md)
- **Groups CRUD (#102 V3 Active-org VP push, #113 V4 push-then-append):** group writes materialise compiled Cedar permits into the org's VP store as part of the same request, VP push **first**, event-sourced append second (D6); `X-Fg-If-Revision` replaces ETag/If-Match on group PUT/DELETE; F-VP/F-VP-mid/F-append failure modes + `forgeguard_cp_group_rollback_failed_total` rollback metric — see [groups-v3.md](./.claude/context/groups-v3.md)
- **Principal kinds:** Cognito JWT → `PrincipalKind::User` → Cedar `User`; Ed25519 signed → `PrincipalKind::Machine` → Cedar `Machine` — see [authn-wiring.md](./.claude/context/authn-wiring.md)
- **Membership model:** JWT is identity-only (`sub`); org + groups resolved per-request from `X-ForgeGuard-Org-Id` header + DynamoDB `PK=USER#{sub}, SK=ORG#{org_id}` lookup (pipeline Phase 5b). Inverted GSI1 lists users per org — see [authn-wiring.md](./.claude/context/authn-wiring.md) and [control-plane.md](./.claude/context/control-plane.md)
- **Infrastructure:** `cargo xtask control-plane infra {deploy,diff,destroy,status}` — CDK + 1Password, see [infra-control-plane.md](./.claude/context/infra-control-plane.md)
- **CP Lambda runtime contract:** the CP function needs `FORGEGUARD_CP_{JWKS_URL,ISSUER,AUDIENCE,POLICY_STORE_ID}` env vars + DynamoDB grant + `verifiedpermissions:IsAuthorized` IAM scoped to the policy-store ARN — env-and-IAM are coupled because the Rust binary panics at parse-time when JWT auth is on without VP wiring. V3 group writes also need `verifiedpermissions:{CreatePolicy,DeletePolicy,ListPolicies,GetPolicy}` on `*` (per-org store ARNs are unknowable to CDK). See [infra-control-plane.md § Control-plane Lambda runtime contract](./.claude/context/infra-control-plane.md#control-plane-lambda-runtime-contract)
- **Cedar sync:** `cargo xtask control-plane cedar {status,diff,sync}` — VP policy management, see [verified-permissions.md](./.claude/context/verified-permissions.md)
- **Manual QA tools:** `cargo xtask control-plane {seed,token,curl}` — seed Cognito/DynamoDB, mint JWTs, send signed requests — see [xtask-control-plane-tools.md](./.claude/context/xtask-control-plane-tools.md)
- **Seed QA playbook:** end-to-end validation scenarios for `cargo xtask control-plane seed` (lint, unit, DDB integration, loader, local e2e) + the prod-VP template-linked survival fixture — see [seed-qa.md](./.claude/context/seed-qa.md) and the V5 plan at `.claude/plans/2026-05-06-issue-102-cp-groups-v5/v5-plan-qa.md`
- **Local dev stack:** `cargo xtask control-plane dev` — dynamodb-local + CP child; needs `AWS_PROFILE=admin` + fresh SSO, uses `AWS_ENDPOINT_URL_DYNAMODB` so only DynamoDB is redirected locally; the `dev` pre-load step still maps `config` presence to `OrgStatus` (no config → Draft, with config → Active), but the dedicated `seed` command always writes Draft after V5 of issue #102 — see [xtask-control-plane-dev.md](./.claude/context/xtask-control-plane-dev.md)
- **Dogfooding config:** `forgeguard.toml` is the control plane's own authorization model; `forgeguard.example.toml` is the proxy reference config
- **DynamoDB tests:** `cargo xtask control-plane test` — auto-starts dynamodb-local via docker/podman
- **Integration tests:** `cargo test -p forgeguard_proxy` — see [demo-app.md](./.claude/context/demo-app.md)
- **Demo app:** native or Docker Compose — see [demo-app.md](./.claude/context/demo-app.md)
- **AWS defaults:** region `us-east-2`, profile `admin` — e.g. `--region us-east-2 --profile admin`
- **AWS ARN formats:** prefer CDK CFN attribute getters (`construct.attrArn`) over `cdk.Stack.formatArn`; some services (e.g. Verified Permissions) use empty region segments — see [aws-arn-formats.md](./.claude/context/aws-arn-formats.md)
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
- **xtask deps** — `xtask` is a binary that intentionally minimizes workspace path deps to keep the cached binary fresh. **Exception:** pure leaf crates (currently `crates/authz-core`) may be consumed by `xtask` to share canonical types and pure functions across consumers (e.g. the RBAC compiler used by both `cargo xtask cedar sync` and the V2+ control-plane Groups handlers). Keep this list small and pure-only.

### Visibility (MUST)

- `pub(crate)` default for internal functions and types
- `pub` only for public API surface
- No `pub` struct fields on domain types — use `Type::new(...)` + `&self` accessors (Parse Don't Validate). Params structs are the carve-out, see [params-struct-rule.md](./.claude/context/params-struct-rule.md).
- Cross-crate test fixtures ship behind a `testing` Cargo feature on the producing crate, gated with `cfg(any(test, feature = "testing"))`. See [visibility-conventions.md](./.claude/context/visibility-conventions.md).
- Axum tuple-struct extractors (e.g. `ForgeGuardIdentity(pub Identity)`) keep public fields with a documented PDV exception so handler destructuring compiles.

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
- **Parse Don't Validate** — at system boundaries; project-specific catalog and conventions in [newtypes.md](./.claude/context/newtypes.md)
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

## Context Documents

See [CONTEXT.md](./CONTEXT.md) for the project-wide agentic context index.

**ALL** context references MUST be included in `CONTEXT.md`, not duplicated here. Actual agentic context documents MUST be kept under `.claude/context/`.
