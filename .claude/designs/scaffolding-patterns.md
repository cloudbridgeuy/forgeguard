---
shaping: true
---

# ForgeGate Repository Scaffolding — Shaping

## ForgeGate Context Summary

ForgeGate is an authorization-as-a-service platform built on AWS (Cognito, Verified Permissions, DynamoDB, S3, SES, SNS). It uses a Smithy-based schema language with custom traits (`@authorize`, `@authResource`, `@featureGate`) and a three-layer design: Design time (Schema), Admin time (AdminClient), Runtime (Guard).

**Architecture scope:**
- **Control Plane** — Dashboard UI (Model Studio, Operations, Webhooks, God Mode)
- **Identity Engine** — Typestate-based authentication flows (Password, MagicLink, SMS, OIDC, Passkey, MFA, PasswordReset, SignUp) with event logging, metrics, and Cognito adapter
- **Data Plane Agent** — Self-hosted customer deployment
- **SDK** — Rust core + FFI wrappers (PyO3/Python, WASM/TypeScript, CGo/Go) with conformance test suite (~90 JSON fixtures)
- **Back Office** — Internal operations dashboard (customer management, analytics, support)
- **CLI** — Developer tooling
- **Proxy/Wrapper** — Request interception layer

**Build targets needed:** Native Rust binaries, WASM (wasm32-unknown-unknown), PyO3 wheels (maturin), Docker images, conformance test fixtures.

**AWS integrations:** Cognito, Verified Permissions, DynamoDB, S3, SES, SNS, CloudTrail, CloudWatch, ElastiCache, Lambda, EventBridge, AWS Marketplace.

**Key design patterns from `~/.claude/patterns/`:**
- Functional Core / Imperative Shell (separate pure logic from I/O)
- Type-Driven Development (types are the spec, phantom types for state)
- Make Impossible States Impossible (typestate pattern for auth flows)
- Parse Don't Validate (at system boundaries)
- Algebraic Data Types (sum/product types for domain modeling)
- CQRS (command/query separation)

---

## Requirements (R)

| ID    | Requirement | Status |
|-------|-------------|--------|
| R0    | Repository structure follows established conventions from existing projects | Core goal |
| R1    | Cargo workspace supports 8+ crates with shared metadata and dependencies | Must-have |
| R2    | CI/CD pipeline handles multi-target builds (native, WASM, PyO3, Docker) | Must-have |
| R3    | Linting, formatting, and code quality tooling matches existing standards | Must-have |
| R4    | Testing infrastructure supports unit tests, integration tests, and conformance fixtures | Must-have |
| R5    | Release process handles multi-crate versioning and multi-artifact publishing | Must-have |
| R6    | Docker builds use established cargo-chef multi-stage pattern | Must-have |
| R7    | xtask automation covers build, lint, test, and project-specific tasks | Must-have |
| R8    | Development tooling (bacon, typos, pre-commit hooks) matches existing setup | Must-have |

---

## Common Patterns (found in 2+ projects)

### Repository Structure

All three projects share this top-level layout:

```
project/
├── .cargo/config.toml          # cargo aliases (xtask)
├── .github/workflows/          # CI/CD (calendsync, mcptools only)
├── crates/                     # workspace members
│   ├── core/                   # shared library crate
│   └── {binary}/               # main binary crate
├── xtask/                      # build automation
│   ├── Cargo.toml
│   └── src/
├── docs/                       # documentation
├── Cargo.toml                  # workspace root
├── Cargo.lock                  # always committed
├── bacon.toml                  # dev task runner
├── _typos.toml                 # typo checker config
├── rust-analyzer.json          # IDE config
├── LICENSE                     # MIT
├── README.md
└── CLAUDE.md                   # dev guidelines (mcptools, ralph)
```

**Convention:** `crates/` for workspace members, `xtask/` at root level (not inside `crates/`).

### Cargo Workspace

All three use identical workspace structure:

```toml
[workspace]
members = ["xtask/", "crates/*"]
resolver = "2"

[workspace.package]
edition = "2021"
license = "MIT"
authors = ["Guzmán Monné"]

[profile.dev]
debug = 0            # faster builds

[profile.release]
incremental = true
debug = 0
```

**Shared metadata:** edition, license, authors inherited by all crates via `{field}.workspace = true`.

**Workspace dependencies:** All dependencies centralized in `[workspace.dependencies]` and referenced via `{ workspace = true }` in member crates.

**Internal crates:** Referenced as `crate_name = { version = "0.0.0", path = "crates/name" }` in workspace deps.

### .cargo/config.toml

Identical across all three:

```toml
[alias]
xtask = "run --package xtask --bin xtask --"

[env]
CARGO_WORKSPACE_DIR = { value = "", relative = true }
```

### xtask Pattern

All three projects use the cargo-xtask pattern with at minimum a `lint` command:

**Common xtask commands:**
- `lint` — runs fmt, check, clippy, test, dependency analysis, file length checks
- `lint --install-hooks` / `--uninstall-hooks` — git pre-commit hook management

**Lint sequence (from ralph/mcptools):**
1. `cargo fmt` (auto-fix with --fix flag)
2. `cargo check`
3. `cargo clippy -- -D warnings`
4. `cargo test`
5. Dependency unification check
6. File length check (max 1000 lines per .rs file)

### bacon.toml

Identical across all three (same jobs, same keybindings):

```toml
default_job = "check"

[jobs.check]
command = ["cargo", "check", "--color", "always"]
need_stdout = false

[jobs.check-all]
command = ["cargo", "check", "--all-targets", "--color", "always"]
need_stdout = false

[jobs.clippy]
command = ["cargo", "clippy", "--all-targets", "--color", "always"]
need_stdout = false

[jobs.test]
command = ["cargo", "test", "--color", "always", "--", "--color", "always"]
need_stdout = true
default_watch = false
watch = ["crates"]

[jobs.doc]
command = ["cargo", "doc", "--color", "always", "--no-deps"]
need_stdout = false

[jobs.doc-open]
command = ["cargo", "doc", "--color", "always", "--no-deps", "--open"]
need_stdout = false
on_success = "back"

[jobs.run]
command = ["cargo", "run", "--color", "always"]
need_stdout = true
allow_warnings = true

[keybindings]
j = "scroll-lines(1)"
k = "scroll-lines(-1)"
ctrl-d = "scroll-pages(1)"
ctrl-u = "scroll-pages(-1)"
g = "scroll-to-top"
shift-g = "scroll-to-bottom"
```

### _typos.toml

Identical across all three:

```toml
[default]
extend-ignore-identifiers-re = [
  "AttributeID.*Supress.*",
]

[default.extend-identifiers]
AttributeIDSupressMenu = "AttributeIDSupressMenu"
```

### .gitignore

Core pattern shared:

```
/target/
**/*.rs.bk
/archive/
.DS_Store
.claude/*
!.claude/context/
!.claude/commands/
.local/
```

### CI/CD (calendsync + mcptools)

Both use GitHub Actions with this structure:

**ci.yml** — triggered on push/PR to main/develop:
- Skips `chore: bump version` commits
- **test** job: checkout → rust toolchain (stable, +clippy +rustfmt) → cache cargo+target → test → clippy → fmt check
- **build** job: checkout → rust toolchain → cache → `cargo check --workspace --exclude xtask`
- **unused-deps** job: checks for unused dependencies
- **typos** job: `crate-ci/typos@master`

**release.yml** — triggered on `v*` tags + manual dispatch:
- Matrix build for macOS Intel + Apple Silicon
- `cargo build --release --target ${{ matrix.target }}`
- Strip binary, upload artifact
- Create GitHub Release with auto-generated changelog (git log diff)
- Uses `softprops/action-gh-release@v2`

**Caching strategy:**
```yaml
- uses: actions/cache@v4
  with:
    path: |
      ~/.cargo/registry/index/
      ~/.cargo/registry/cache/
      ~/.cargo/git/db/
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
- uses: actions/cache@v4
  with:
    path: target/
    key: ${{ runner.os }}-target-${{ hashFiles('**/Cargo.lock') }}
```

**Actions used:** `actions/checkout@v5`, `dtolnay/rust-toolchain@stable`, `actions/cache@v4`, `actions/upload-artifact@v4`, `actions/download-artifact@v5`, `softprops/action-gh-release@v2`, `crate-ci/typos@master`.

### Docker (mcptools + ralph)

Identical Dockerfile pattern using cargo-chef:

```dockerfile
FROM lukemathwalker/cargo-chef:latest-rust-1.86.0 AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates/ crates/
COPY xtask/ xtask/
RUN cargo chef prepare --recipe-path recipe.json --bin {binary}

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates/ crates/
COPY xtask/ xtask/

RUN cargo build --release --bin {binary}

FROM debian:bookworm-slim AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/{binary} /usr/local/bin
ENTRYPOINT ["/usr/local/bin/{binary}"]
```

### Testing

All three projects use inline `#[cfg(test)]` modules — no dedicated `tests/` directory.

Test naming convention: `module_name_tests.rs` files or `tests/` subdirectories within a module (see ralph's `chunk/tests/`).

### Crate Naming Convention

- Core library: `{project}_core` (e.g., `ralph_core`, `mcptools_core`, `calendsync_core`)
- Main binary: `{project}` (e.g., `ralph`, `mcptools`, `calendsync`)
- Explicit `[lib] name = "{project}_core"` and `path = "src/lib.rs"` declarations
- Binary crates use `autobins = false` with explicit `[[bin]]` sections

### Dependencies (common across 2+ projects)

| Dependency | Projects | Notes |
|------------|----------|-------|
| `serde` + `serde_json` | all 3 | `features = ["derive"]` |
| `tokio` | all 3 | `features = ["full"]` |
| `clap` | all 3 | `features = ["derive", "string", "env"]` (calendsync/mcptools) or `["derive", "env"]` (ralph) |
| `thiserror` | all 3 | Library error types |
| `chrono` | all 3 | Date/time |
| `reqwest` | all 3 | HTTP client, `features = ["json"]` |
| `tracing` + `tracing-subscriber` | calendsync | Structured logging |
| `env_logger` | mcptools, ralph | Simple logging |
| `anstream` | all 3 | Terminal output |
| `uuid` | calendsync, ralph | `features = ["v4", "serde"]` |
| `regex` | mcptools, ralph | Pattern matching |
| `rand` | all 3 | Random generation |
| `axum` | calendsync, mcptools | HTTP framework |
| `tower-http` | calendsync, mcptools | HTTP middleware |

---

## Per-Project Specifics

### calendsync

- **8 crates** in workspace (largest): core, calendsync, client, auth, frontend, ssr, ssr_core, src-tauri
- Uses **cargo-rail** for CI change detection (only runs affected crates)
- Has **dependabot.yml** with detailed config (reviewers, labels, commit prefixes)
- Has **Tauri** desktop app crate
- Has **frontend** crate with Bun-based TypeScript/React build
- Uses **build.rs** scripts for asset manifest generation and frontend builds
- Uses **feature flags** extensively for storage backends (sqlite, dynamodb, inmemory), cache backends (memory, redis), auth backends (auth-sqlite, auth-redis, auth-mock)
- MSRV: 1.88.0
- Has `.config/rail.toml` for cargo-rail configuration
- Error handling: `anyhow` (binary) + `thiserror` (libraries)
- xtask commands: dev, lint, dynamodb, integration, seed

### mcptools

- **3 crates**: core, mcptools, pdf
- Uses **cargo-machete** for unused dependency detection in CI
- Has **scripts/** directory with install.sh, release.sh, hooks/pre-commit
- Has **Dockerfile** (cargo-chef pattern)
- Has **CLAUDE.md**
- Error handling: `color-eyre` (binary) + `thiserror` (libraries)
- xtask commands: install, release, install-binary, lint
- Has `typos.toml` (additional typo config beyond `_typos.toml`)

### ralph

- **2 crates** + xtask: core, ralph
- **No GitHub Actions CI** (youngest project?)
- Has **clippy.toml** with `too-many-arguments-threshold = 5`
- Has **`[workspace.lints.clippy]`** section (empty, with comment about deny in source)
- Has **CLAUDE.md** with documented "Unnegotiables" (no dead code, no unwrap/expect, max 5 args, no file over 1000 lines, FCIS pattern)
- Has **assets/** directory for bundled persona/strategy files
- Uses **cargo-rail** for dependency unification (in xtask)
- Error handling: `color-eyre` (binary) + `thiserror` (libraries)
- MSRV: 1.87.0
- xtask commands: lint (with hook management)

---

## Divergences Requiring Discussion

### Divergence 1: Error Handling in Binary Crates

| Project | Binary error lib | Library error lib |
|---------|-----------------|-------------------|
| calendsync | `anyhow` | `thiserror` |
| mcptools | `color-eyre` | `thiserror` |
| ralph | `color-eyre` | `thiserror` |

**Tradeoffs:**
- `anyhow`: Simpler, lighter, more widely used. Context via `.context()`.
- `color-eyre`: Richer error reports with colored backtraces, span traces, custom sections. Heavier. `.wrap_err()` instead of `.context()`.

**Recommendation for ForgeGate:** `color-eyre` for binary crates (2 of 3 projects use it, richer debugging for a complex system), `thiserror` for all library crates (unanimous). **Needs confirmation.**

### Divergence 2: Unused Dependency Detection

| Project | Tool | Where |
|---------|------|-------|
| calendsync | `cargo-rail unify --check` | CI + xtask |
| mcptools | `cargo-machete` (GitHub Action) | CI only |
| ralph | `cargo-rail unify --check` | xtask only |

**Tradeoffs:**
- `cargo-rail`: More comprehensive (also checks dead features, MSRV, dependency unification). Requires installation.
- `cargo-machete`: Simpler, single-purpose, has a GitHub Action. Faster.

**Recommendation for ForgeGate:** `cargo-rail` (2 of 3 projects, more features including dead feature detection which matters for a workspace with many feature flags). **Needs confirmation.**

### Divergence 3: CI Change Detection

| Project | Approach |
|---------|----------|
| calendsync | `cargo-rail-action@v1` detects affected crates, runs tests selectively |
| mcptools | Runs all tests on every push |

**Tradeoffs:**
- Selective: Faster CI on large workspaces, but more complex setup.
- Full: Simpler, catches cross-crate breakage, but slower on large workspaces.

**Recommendation for ForgeGate:** Selective via cargo-rail (ForgeGate will have 8+ crates; running all tests on every change will be slow). **Needs confirmation.**

### Divergence 4: Logging/Tracing

| Project | Library |
|---------|---------|
| calendsync | `tracing` + `tracing-subscriber` (structured) |
| mcptools | `env_logger` + `log` (simple) |
| ralph | `env_logger` + `log` (simple) |

**Tradeoffs:**
- `tracing`: Structured, span-based, async-aware, integrates with OpenTelemetry. More setup.
- `env_logger`: Simple, env-var driven. No structure, no spans.

**Recommendation for ForgeGate:** `tracing` + `tracing-subscriber` (ForgeGate needs structured logging for event logs, metrics, God Mode, and will benefit from span-based context for auth flows). Despite being used in only 1 project, it's the right choice here. **Needs confirmation.**

### Divergence 5: Clippy Configuration

| Project | clippy.toml | workspace.lints | Source-level denials |
|---------|-------------|-----------------|---------------------|
| calendsync | None | None | Unknown |
| mcptools | None | None | Unknown |
| ralph | `too-many-arguments-threshold = 5` | `[workspace.lints.clippy]` (empty, comment) | `#![deny(clippy::unwrap_used, clippy::expect_used)]` in lib.rs/main.rs |

**Recommendation for ForgeGate:** Adopt ralph's approach (clippy.toml + source-level denials). The 5-arg threshold and unwrap/expect denials align with ForgeGate's need for robust, production-quality code. **Needs confirmation.**

### Divergence 6: MSRV Policy

| Project | MSRV |
|---------|------|
| calendsync | 1.88.0 |
| ralph | 1.87.0 |
| mcptools | Not set |

**Recommendation for ForgeGate:** Set MSRV to current stable at project creation time. Pin it in `workspace.package.rust-version`. **Needs confirmation.**

### Divergence 7: Dependabot Configuration

| Project | Config |
|---------|--------|
| calendsync | Full (cargo + github-actions, reviewers, labels, commit prefixes) |
| mcptools | Minimal (cargo only, weekly) |
| ralph | None |

**Recommendation for ForgeGate:** calendsync's full config (reviewers, labels, commit message prefixes). ForgeGate has more dependencies and needs organized dependency updates. **Needs confirmation.**

### Divergence 8: scripts/ Directory vs xtask-Only

| Project | scripts/ | xtask |
|---------|----------|-------|
| calendsync | None | Yes (dev, lint, dynamodb, integration, seed) |
| mcptools | Yes (install.sh, release.sh, hooks/) | Yes (install, release, lint, install-binary) |
| ralph | None | Yes (lint) |

**Recommendation for ForgeGate:** xtask-only for Rust-based automation. Shell scripts for distribution/installation (install.sh) if needed. Keep hooks in xtask. **Needs confirmation.**

---

## Recommendations for ForgeGate

### Workspace Structure

Based on the design documents and existing patterns:

```
forgegate/
├── .cargo/config.toml
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   └── release.yml
│   └── dependabot.yml
├── crates/
│   ├── core/                  # forgegate_core — shared types, traits, error types
│   ├── identity/              # forgegate_identity — typestate auth flows, event log
│   ├── model/                 # forgegate_model — Smithy schema → Verified Permissions
│   ├── control-plane/         # forgegate_control_plane — axum API, dashboard backend
│   ├── sdk/                   # forgegate_sdk — Rust SDK core (Guard, WebhookHandler)
│   ├── ffi/                   # forgegate_ffi — PyO3 + WASM bindings
│   ├── cli/                   # forgegate_cli — developer CLI
│   ├── proxy/                 # forgegate_proxy — request interception proxy
│   ├── agent/                 # forgegate_agent — self-hosted data plane agent
│   └── back-office/           # forgegate_back_office — internal ops API
├── xtask/
├── docs/
├── conformance/               # conformance test fixtures (JSON)
├── Cargo.toml
├── Cargo.lock
├── bacon.toml
├── clippy.toml
├── _typos.toml
├── rust-analyzer.json
├── Dockerfile
├── LICENSE
├── README.md
└── CLAUDE.md
```

**Open questions:**
- Should `ffi` be split into `ffi-python` and `ffi-wasm`?
- Does `back-office` share enough with `control-plane` to merge?
- Where does the conformance test runner live (xtask? its own crate?)

### CI/CD Adaptations

Existing CI covers single-binary native builds. ForgeGate needs:

1. **Native builds** — existing pattern works
2. **WASM target** — add `wasm32-unknown-unknown` to matrix, use `wasm-pack` or `cargo build --target wasm32-unknown-unknown`
3. **PyO3 wheels** — add `maturin` build step, publish to PyPI
4. **Docker images** — extend existing cargo-chef pattern, multi-platform (`linux/amd64`, `linux/arm64`)
5. **Conformance tests** — dedicated CI job that runs fixtures against all SDK implementations

**Gap:** None of the existing projects build WASM, PyO3, or multi-platform Docker. These are new capabilities to add.

### Testing Strategy

Existing pattern: inline `#[cfg(test)]` modules. ForgeGate additionally needs:

1. **Unit tests** — per-crate, inline modules (existing pattern)
2. **Integration tests** — against AWS services (LocalStack or feature-gated real AWS)
3. **Conformance fixtures** — `conformance/` directory with ~90 JSON test cases
4. **Conformance runner** — validates fixtures against Rust core (and later FFI wrappers)
5. **Authorization test generation** — auto-generates positive/negative/isolation tests from Smithy schema

**Gap:** No existing project has conformance test infrastructure or AWS integration testing.

### Release Strategy

Existing: tag-based GitHub releases with binary artifacts. ForgeGate needs:

1. **Multi-crate versioning** — decision needed: unified version or independent
2. **crates.io** — publish SDK crate
3. **PyPI** — publish Python SDK wheel
4. **npm** — publish TypeScript SDK (WASM)
5. **Docker Hub / ECR** — control plane and agent images
6. **GitHub Releases** — CLI binaries

**Gap:** No existing project publishes to crates.io, PyPI, or npm. No multi-crate versioning strategy exists.

### Tooling Gaps

| Need | Existing Coverage | Gap |
|------|-------------------|-----|
| WASM compilation | None | Need `wasm-pack` or `wasm-bindgen`, CI target |
| PyO3/maturin | None | Need `maturin` for Python wheel builds |
| Multi-platform Docker | None | Need `docker buildx` for linux/amd64 + linux/arm64 |
| Conformance test runner | None | Need custom test harness or xtask command |
| AWS integration tests | None | Need LocalStack or test AWS account |
| Cross-compilation | macOS-only currently | Need Linux targets for Docker/deployment |
| CDK/Terraform | None | Infrastructure-as-code for self-hosted deployment |
| cargo-deny | None of the 3 projects use it | License/advisory auditing (important for enterprise) |

---

## Decision Log

(Will be populated as we resolve divergences and open questions)

| # | Topic | Decision | Rationale |
|---|-------|----------|-----------|
| D1 | Binary error handling | `color-eyre` | 2/3 projects, richer debugging for complex auth system |
| D2 | Library error handling | `thiserror` | Unanimous across all 3 projects |
| D3 | Unused dep detection | `cargo-rail` | 2/3 projects, covers dead features + dep unification |
| D4 | CI change detection | `cargo-rail` selective | ForgeGate has 8+ crates, full suite too slow |
| D5 | Logging | `tracing` + `tracing-subscriber` | Structured spans for auth flows, metrics, God Mode |
| D6 | Clippy config | ralph's approach (clippy.toml + source denials) | Strictest; auth platform cannot panic |
| D7 | MSRV | Current stable, unified, cargo-rail enforced | All crates track latest |
| D8 | Dependabot | calendsync's full config | Labels, reviewers, commit prefixes |
| D9 | scripts/ directory | None — xtask only | 2/3 projects are xtask-only; no duplication |
| D10 | Crate boundary FCIS | Pure crates (no I/O deps) vs I/O crates, strict | WASM target requires it; prevents dep contamination |
| D11 | Pure domain split | Three pure domain crates: authn_core, authz_core, audit_core | Distinct domains with different consumers |
| D12 | Crate naming | `forgegate_` prefix + terse industry suffix (authn, authz, audit) | Short names compound across codebase |
| D13 | FFI split | Two crates: `ffi_python` (PyO3) and `ffi_wasm` (wasm-bindgen) | Different compilation targets, can't coexist cleanly |
| D14 | Control plane vs back office | Separate binaries | Independent scaling and security boundaries |
| D15 | Scaffolding scope | All 15 crates + xtask, minimal files (main.rs/lib.rs, Cargo.toml, README.md) | Get pure/I/O split right early |
| D16 | CI platforms | macOS (Intel+ARM) + Linux (x86_64+ARM). No Windows. | Docker images run Linux; macOS for CLI/dev |
| D17 | Docker registry | ghcr.io for now, ECR later for Marketplace | Free, no extra setup |
| D18 | SDK publishing | GitHub Releases only at scaffolding time | PyPI/npm when SDK is ready |
| D19 | CLI Docker image | Yes — escape hatch for Windows devs | Avoids cross-compilation to Windows |
| D20 | Docker images | 5 total: control-plane, agent, proxy, back-office, cli | Each follows cargo-chef pattern |
| D21 | Conformance runner | xtask command (`cargo xtask conformance`) | Orchestrates multiple SDK targets |
| D22 | AWS integration tests | LocalStack first | Free, deterministic, needs docker-compose.yml |
| D23 | docker-compose.yml | Yes — for LocalStack (dev/CI) | New pattern for ForgeGate, not in existing projects |
| D24 | Versioning | Unified — all crates share one version | Tightly coupled product, one tag triggers all |
| D25 | Changelog | git-cliff with conventional commits | Categorized changelogs from day one |
| D26 | Commit convention | Conventional Commits (type(scope): desc) | Required for git-cliff; scopes = crate suffixes |
| D27 | Version bump logic | Auto: `!` → minor (pre-1.0) or major (post-1.0), `feat` → patch (pre-1.0) or minor (post-1.0), else patch. `--major` override. | xtask release command, regime detected from current version |
| D28 | AWS SDK pinning | Pin all AWS crates to same minor, bump together | Dependabot handles PRs |
| D29 | HTTP framework | axum | Unanimous in existing projects |
| D30 | HTTP client | reqwest for I/O; trait-based in SDK (pure) | reqwest supports WASM via features; SDK stays pure |
| D31 | cargo-deny | Yes — license, advisory, and ban auditing | Enterprise auth product; can't ship GPL or CVE deps |
| D32 | Module organization | Start flat, promote to directory at ~300 lines, hard limit 1000 | Organic growth, xtask enforces |
| D33 | Error type naming | `Error` per crate + `Result<T>` alias | Idiomatic Rust, disambiguate with crate path |
| D34 | Visibility default | `pub(crate)` default, `pub` only for API surface, no pub fields | Parse Don't Validate at struct boundaries |
| D35 | Prelude modules | Yes, minimal — Error, Result, 2-3 most-used types | Not kitchen-sink re-exports |
| D36 | Per-crate README.md | Yes — one paragraph, what it owns, pure/I/O classification | READMEs for humans, .claude/context/ for agents |
