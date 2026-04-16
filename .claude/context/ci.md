# CI Pipeline

`.github/workflows/ci.yml` is the single authoritative CI workflow. It runs on
every push/PR to `main` and `develop` and gates merges.

## Jobs

| Job                       | Purpose                                                                 |
| ------------------------- | ----------------------------------------------------------------------- |
| CI Plan                   | Runs `cargo rail plan`; produces surface gates, mode, and crates list consumed by all downstream jobs. Also skipped on `chore: bump version` commits. |
| Formatting                | `cargo fmt -- --check`; always runs (no `needs:`, no surface gate) |
| Test Suite                | `cargo test --workspace`, clippy |
| Build Check               | `cargo check --workspace --exclude xtask` on ubuntu + macos |
| WASM Build Check          | `cargo check -p forgeguard_sdk -p forgeguard_ffi_wasm --target wasm32-unknown-unknown` |
| Rustdoc Build             | `cargo doc --workspace --no-deps --document-private-items`; `RUSTDOCFLAGS: "-D warnings"` is set, so doc-comment errors fail the job |
| Check Typos               | `crate-ci/typos` against the repo, config in `_typos.toml`; always runs |
| Check Unused Dependencies | `cargo rail unify --check` — enforces workspace dep hygiene; always runs |
| Dependency Audit          | `cargo-deny check` — licenses + advisories, config in `deny.toml`; always runs |

The workflow skips gated jobs when `head_commit.message` starts with
`chore: bump version` (release commits). `typos`, `unused-deps`, and `deny` are
always relevant and cheap, so they remain ungated.

## Toolchain Pinning and CI Actions

`rust-toolchain.toml` pins the channel **and** must list every component or
target CI uses. Rationale: `dtolnay/rust-toolchain@stable` installs into the
`stable` toolchain, but the rust-toolchain file overrides the *active*
toolchain to the pinned version — so components/targets added via the action's
`components:` / `targets:` inputs land in the wrong toolchain and CI fails with
`'cargo-clippy' is not installed for the toolchain '<pinned>'` or
`can't find crate for 'core'`.

**The rule:** anything CI needs has to be in `rust-toolchain.toml`.

```toml
[toolchain]
channel = "1.91.1"
components = ["clippy", "rustfmt"]
```

Non-default targets (e.g. `wasm32-unknown-unknown`) are still installed via a
`rustup target add` step *after* checkout, since it runs under the active
(pinned) toolchain.

## Typos Allowlist (`_typos.toml`)

The `typos` check flags identifiers that look like misspellings. When the flag
is a false positive — a third-party API name or a deliberate test fixture —
extend the allowlist rather than renaming.

Current entries and why:
- `esource` — Pingora `pingora_core::Error::esource()` accessor name
- `inh` — substring of the test-fixture Verified Permissions policy store id
  `ps-inh` in `xtask/src/control_plane/cedar_core/desired.rs`

## cargo-deny Allowlist (`deny.toml`)

Each ignored advisory or license pair should tie back to a constraint we
cannot act on. Explain *why* in a comment so the entry can be removed once the
constraint lifts.

### Licenses
- `CDLA-Permissive-2.0` — `webpki-root-certs` bundles the Mozilla CA list
  under this license (pulled in by rustls via `reqwest`'s rustls backend).

### Advisories (pinned until the root constraint lifts)
- `RUSTSEC-2025-0069` / `daemonize` — transitive via Pingora
- `RUSTSEC-2024-0388` / `derivative` — transitive, unmaintained
- `RUSTSEC-2024-0437` / `protobuf 2.28` — transitive via `prometheus 0.13`,
  which is pinned by Pingora (see
  [dependency-constraints.md](./dependency-constraints.md))
- `RUSTSEC-2026-0097` / `rand 0.8 unsound` — pinned by Pingora and
  `ed25519-dalek` (see dependency-constraints.md). The unsound path requires a
  custom logger calling `rand::rng()`; not applicable here.
- `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099` / `rustls-webpki` name-constraint
  bugs — only affect TLS clients that rely on name constraints; our paths do
  not.

When bumping Pingora or other pinned transitives, revisit this list and remove
entries whose root cause has been resolved.

## Workspace Dep Hygiene

`cargo rail unify --check` runs in CI and fails if any workspace member uses a
plain `path = "..."` dependency for a crate that already lives in
`[workspace.dependencies]`, or if an internal crate is duplicated across
member `Cargo.toml`s instead of unified at the workspace level.

Run `cargo rail unify` (without `--check`) locally to auto-apply the plan.
Requires `cargo-rail >= 0.11`.

## Change Detection

`cargo rail plan` (cargo-rail 0.11, via `cargo-binstall --locked --version 0.11.0`) runs first, resolves a base ref, and exports surface gates consumed by all downstream jobs.

### BASE_REF resolution (priority order)

1. `inputs.since` — workflow_dispatch override
2. `origin/$GITHUB_BASE_REF` — pull request base branch
3. `github.event.before` — push event preceding SHA (skipped if null/all-zeros)
4. `origin/main` — fallback for pushes to main
5. `HEAD~1` — last-resort fallback if none of the above resolve

### Plan outputs

`cargo rail plan --quiet --since "$BASE_REF" --json -o "$RUNNER_TEMP/plan.json"`
produces a JSON plan. The `plan` job parses it with jq and exports:

- `mode` — `workspace` | `crates` | `noop`
- `crates` — space-separated list (only meaningful when `mode == crates`)
- `test`, `docs`, `build` — boolean surface gates (`true` / `false`)
- `base_ref` — the resolved base ref used for the plan

The jq fallback for mode is `// "workspace"`: if the schema drifts, CI fails
closed to a full workspace run rather than silently skipping work.

### `.config/rail.toml` — infrastructure paths

The `[change-detection].infrastructure` list forces `mode: workspace` whenever
any of these paths are touched: `.github/**`, `Cargo.lock`, `Cargo.toml`,
`deny.toml`, `rust-toolchain.toml`, `xtask/**`, `_typos.toml`.

### Per-job dispatch

The `test` and `build` jobs dispatch on `$MODE` via a `case` statement:

- `workspace` — runs the job against the full workspace
- `crates` — loops `$CRATES` and appends `-p $c` flags per crate
- `noop` — prints a skip message and exits 0
- `*)` — unknown mode; fails loudly with `exit 1`

The `build` job's `crates` arm filters out `xtask` and guards against an empty
arg list (skips rather than falling back to a full workspace check).

`build-wasm` has a compound gate: `plan.outputs.build == 'true'` AND
(`mode == workspace` OR `$CRATES` contains `forgeguard_sdk` or
`forgeguard_ffi_wasm`). It does not have an internal `case` dispatch — the gate
itself is the only dispatch mechanism.

The `docs` job has no internal `case` dispatch at all. Once its `if:` gate
passes (`plan.outputs.docs == 'true'`), it runs
`cargo doc --workspace --no-deps --document-private-items` unconditionally.

### Reproducibility artifact

After generating the plan, the `plan` job also runs
`cargo rail hash --since "$BASE_REF" --json > rail-hash.json` and uploads it as
artifact `rail-hash-${{ github.run_id }}` (14-day retention). This lets you
audit which inputs drove a given plan.

### Local reproduction

```sh
cargo rail plan --quiet --since HEAD~1 --json
```

To inspect the hash:

```sh
cargo rail hash --since HEAD~1 --json
```

## GitHub Actions Runtime

All reusable actions must run on Node.js 24 (GitHub forces this by default
from 2026-06-02). Use `actions/cache@v5` (not `@v4`), `actions/checkout@v5`,
`actions/upload-artifact@v5` (not `@v4`), etc. When bumping a major: skim the
release notes for input schema changes before merging.
