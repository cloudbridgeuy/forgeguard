# xtask Wrapper (`cargo-xtask`)

A thin, std-only binary installed at `~/.cargo/bin/cargo-xtask`. When the user types `cargo xtask <args>`, cargo dispatches to this wrapper via its "external subcommand" mechanism (no alias needed). The wrapper compares the mtime of the cached `target/debug/xtask` binary against every file under `xtask/src/**` and `xtask/Cargo.toml`; when fresh, it `execvp`s the cached binary directly, skipping cargo's fingerprint overhead. When stale, it runs `cargo build -p xtask --quiet` first.

The wrapper lives at `xtask/cargo-xtask/` with no workspace path dependencies. Edits anywhere else in the workspace — crates, lib, tests — never invalidate the wrapper itself.

## Why the wrapper exists

`cargo xtask ...` via a cargo alias runs cargo's full fingerprint machinery. Any edit to the workspace (a crate the xtask binary doesn't even depend on) can invalidate the fingerprint and trigger a relink. On this workspace, hot-path invocations paid hundreds of milliseconds to multiple seconds before printing help. With the wrapper, the hot path drops to ~50–100 ms.

## Architecture

Functional Core — Imperative Shell at crate scope.

- `staleness.rs` — pure decider. `is_stale(binary_mtime: Option<SystemTime>, source_mtimes: &[SystemTime]) -> Staleness`. Returns `Stale` when the binary is missing or any source mtime exceeds the binary mtime. Equal mtimes tie-break as `Fresh`, matching cargo's own fingerprint semantics.
- `args.rs` — pure argv parser. Produces a `Dispatch { forwarded, force_rebuild }` from `argv`. Validates that `argv[1] == "xtask"` (cargo passes the subcommand name as the first argument to an external subcommand) and extracts `--rebuild` if present.
- `main.rs` — the shell. Walks `xtask/src/**`, collects mtimes, reads the `CARGO_WORKSPACE_DIR` env var for the fast path, shells out to `cargo build` on stale, and calls `std::os::unix::process::CommandExt::exec` to replace this process with the cached binary. No `unsafe`, no `libc`.

## Hot path vs cold path

- **Hot path:** `Fresh` → `exec()` the cached binary. Zero cargo invocation. Zero recompilation.
- **Cold path:** `Stale` → run `cargo build -p xtask --quiet`, then `exec()`. The `-p xtask` scope keeps the build narrow; cargo compiles only xtask and its deps, never the whole workspace.
- **Force path:** `--rebuild` is consumed by the wrapper (stripped from forwarded args) and forces the cold path regardless of mtime state. Useful after a branch switch when git's checkout mtimes land out of order.

## Locating the workspace root

The wrapper looks in two places, in order:

1. `CARGO_WORKSPACE_DIR` env var (set by `.cargo/config.toml`).
2. Walk upward from `cwd` searching for a `Cargo.toml` containing `[workspace]`.

Both paths verify the manifest actually declares a workspace — an env var pointing at a non-workspace directory falls through to the walk. If neither path finds a workspace, the wrapper prints `could not locate workspace root` and exits with status 2.

## Installation

```sh
cargo install --path xtask/cargo-xtask --locked
```

The `[alias] xtask` entry that used to live in `.cargo/config.toml` is gone — cargo dispatches `cargo xtask` to `cargo-xtask` on PATH automatically when no alias matches.

## Platform

Unix only. The wrapper uses `std::os::unix::process::CommandExt::exec` for the replace-this-process semantics that `execvp` provides in C. A Windows port would need to branch on target family and use `CreateProcess` with the wrapper terminating after the child exits.

## Relation to xtask's inlined signing

The wrapper philosophy — zero workspace path deps — also drove the decision to inline `forgeguard_authn_core::signing` into `xtask/src/signing.rs`. With that dep removed, a random edit to `crates/authn-core/` cannot invalidate the cached xtask binary. See [request-signing.md](./request-signing.md) for the drift-prevention integration test that keeps the inlined copy byte-compatible with upstream.

## Troubleshooting

- **`cargo-xtask: could not locate workspace root`** — run the command from inside the repository or set `CARGO_WORKSPACE_DIR` explicitly.
- **First invocation on a fresh clone takes tens of seconds** — expected. The wrapper detects the missing binary and runs the cold path (xtask + deps, no workspace cascade). Subsequent invocations hit the hot path.
- **`cargo xtask` still feels slow after install** — run `which cargo-xtask` to confirm the binary is on PATH. `~/.cargo/bin` must come before any stale shim.
- **Lint caught a rebuild when nothing in xtask changed** — check `git status` for stray touches under `xtask/src/`. The wrapper treats mtime, not content, so `touch` alone is enough.

## Extending the wrapper

- New flag consumed by the wrapper (not forwarded): extend `args.rs::dispatch` and add a unit test.
- New staleness signal (e.g. watch a vendored config): extend `collect_source_mtimes` in `main.rs` and add a test against `is_stale` with the new slice.
- Never add a workspace path dep to the wrapper — that defeats its entire purpose. Std-only.
