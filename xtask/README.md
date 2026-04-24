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

xtask intentionally carries **no workspace path dependencies**. It inlines the
narrow Ed25519 signing surface it needs in `src/signing.rs`. The integration
test at `tests/signing_compat.rs` verifies this copy stays byte-compatible with
`forgeguard_authn_core::signing`, which sits as a dev-dep only.

If you edit either the inlined code or the upstream, run:

    cargo test -p xtask --test signing_compat
