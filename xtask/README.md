# xtask

Workspace task runner. Hosts the `cargo xtask` subcommands (`lint`, `release`,
`control-plane`, etc.) as a standard Rust binary.

## Running

Install the wrapper once (see `xtask/cargo-xtask/README.md`), then:

    cargo xtask lint
    cargo xtask release ...
    cargo xtask control-plane curl ...

The wrapper skips cargo's fingerprint when the cached xtask binary is fresh.

## Dependencies

xtask minimizes workspace path dependencies to keep its cached binary fresh
(see `xtask/cargo-xtask/README.md` for the wrapper's mtime-based staleness
check). Exceptions:

- `forgeguard_authz_core` (pure leaf crate, no I/O deps) — provides the
  shared RBAC compiler used by seed's group validation and
  by the V2+ control-plane Groups handlers. See
  `crates/authz-core/README.md`. Note: `cedar_core::rbac` no longer exists
  as a separate module — the lone I/O-edge adapter `policy_entries_to_rbac`
  was inlined into `cedar_core::desired` (its only caller) in V6 of
  issue #102.

xtask still inlines the narrow Ed25519 signing surface it needs in
`src/signing.rs` rather than depending on `forgeguard_authn_core`. The
integration test at `tests/signing_compat.rs` verifies this copy stays
byte-compatible with `forgeguard_authn_core::signing`, which sits as a
dev-dep only.

If you edit either the inlined code or the upstream, run:

    cargo test -p xtask --test signing_compat
