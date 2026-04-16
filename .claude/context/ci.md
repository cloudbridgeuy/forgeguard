# CI Pipeline

`.github/workflows/ci.yml` is the single authoritative CI workflow. It runs on
every push/PR to `main` and `develop` and gates merges.

## Jobs

| Job                       | Purpose                                                                 |
| ------------------------- | ----------------------------------------------------------------------- |
| Test Suite                | `cargo test --workspace`, clippy, rustfmt                               |
| Build Check               | `cargo check --workspace --exclude xtask` on ubuntu + macos             |
| WASM Build Check          | `cargo check -p forgeguard_sdk -p forgeguard_ffi_wasm --target wasm32-unknown-unknown` |
| Check Typos               | `crate-ci/typos` against the repo, config in `_typos.toml`              |
| Check Unused Dependencies | `cargo rail unify --check` — enforces workspace dep hygiene             |
| Dependency Audit          | `cargo-deny check` — licenses + advisories, config in `deny.toml`       |

The workflow skips every job when `head_commit.message` starts with
`chore: bump version` (release commits).

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

The `Detect Changes` job (which gated tests to only affected crates) was
removed. `loadingalias/cargo-rail-action@v1` invokes `cargo rail affected`,
which was removed in cargo-rail 0.11 in favor of the `plan` subcommand and a
completely new output schema (`scope-json`, surface gates). The `@v4` of the
action is a rewrite that needs `.config/rail.toml` plus workflow changes to
consume the new outputs.

Until the migration lands, CI runs tests + build on the full workspace every
time. If this becomes a bottleneck, port the workflow to
`loadingalias/cargo-rail-action@v4` following the v4 README.

## GitHub Actions Runtime

All reusable actions must run on Node.js 24 (GitHub forces this by default
from 2026-06-02). Use `actions/cache@v5` (not `@v4`), `actions/checkout@v5`,
etc. When bumping a major: skim the release notes for input schema changes
before merging.
