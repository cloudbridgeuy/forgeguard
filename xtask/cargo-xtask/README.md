# cargo-xtask

Thin wrapper for `cargo xtask` that skips cargo's fingerprint overhead when the
cached `target/debug/xtask` binary is newer than every file under `xtask/src/**`
and `xtask/Cargo.toml`. When the binary is fresh, the wrapper `execvp`s it
directly; when stale or missing, it runs `cargo build -p xtask --quiet`
and then execs the fresh binary.

## Install (once per machine)

    cargo install --path xtask/cargo-xtask --locked

This drops `cargo-xtask` into `~/.cargo/bin/`. From that point, `cargo xtask ...`
routes to the installed wrapper.

## Design

The wrapper follows Functional Core — Imperative Shell at crate scope:

- `staleness.rs` — pure decider over mtimes.
- `args.rs` — pure argv parser into `Dispatch`.
- `main.rs` — shell: env read, mtime collection, cargo spawn, `execvp` via `std::os::unix::process::CommandExt::exec`.

Only `std` is required. No workspace dependencies, so edits anywhere
else in the workspace never trigger a wrapper rebuild.

## Force a rebuild

    cargo xtask --rebuild <subcommand>

The `--rebuild` flag is consumed by the wrapper and forces the cold path
(runs `cargo build -p xtask`) regardless of mtime state. Useful after a
branch switch when git's checkout mtimes land out of order.

## Troubleshooting

- `cargo-xtask: could not locate workspace root` — run the command from inside
  the repository, or set `CARGO_WORKSPACE_DIR` to the repo root.
- `cargo build failed` — the underlying cargo error prints directly; fix the
  xtask source and re-run.
