# xtask lint — Pipeline Reference

## Overview

`cargo xtask lint` is the **single command** for all code quality validation. It runs a sequential pipeline of checks, stops at the first failure, and produces zero output on success (exit code 0) or error output + exit code 1 on failure.

All output is logged to `target/xtask-lint.log` regardless of outcome.

## Pipeline

Checks run in this order:

| # | Check | Command | Optional | Fix mode |
|---|-------|---------|----------|----------|
| 1 | Fmt | `cargo fmt --check` | no | `cargo fmt` |
| 2 | Check | `cargo check --workspace --all-targets` | no | unchanged |
| 3 | Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | no | adds `--fix --allow-dirty` |
| 4 | Test | `cargo test --workspace --all-targets` | no | unchanged |
| 5 | Rail | `cargo rail unify --check` | yes | `cargo rail unify` |
| 6 | FileLength | custom: all `.rs` files under `crates/*/src/` must be <= 1000 lines | no | unchanged |
| 7 | TypeScript | `npx tsc --noEmit` in `infra/control-plane/` | no | unchanged |

Optional checks are gracefully skipped if the tool is not installed.

## CLI Flags

| Flag | Purpose |
|------|---------|
| `--verbose` | Print output from passing checks (default: silent) |
| `--fix` | Auto-fix: fmt applies formatting, clippy applies fixes, rail applies unification |
| `--no-fmt` | Skip format check |
| `--no-check` | Skip compilation check |
| `--no-clippy` | Skip clippy |
| `--no-test` | Skip tests |
| `--no-rail` | Skip cargo-rail unify |
| `--no-file-length` | Skip file length check |
| `--no-typescript` | Skip TypeScript compilation check |
| `--install-hooks` | Install git pre-commit hook |
| `--uninstall-hooks` | Remove git pre-commit hook |
| `--hooks-status` | Show hook installation status |

## Architecture

The lint module follows **Functional Core / Imperative Shell**:

- **Functional Core** (`lint/mod.rs` top half): `CheckId`, `CheckOutcome`, `CheckResult` types, plus pure functions (`should_skip`, `fix_args`, `determine_outcome`, `evaluate_file_lengths`, `format_log_entry`, `is_tool_not_found`). All unit-tested.
- **Imperative Shell** (`lint/mod.rs` bottom half): `run()` orchestration, `run_check()` process execution via `duct`, file I/O, git operations.
- **Hooks** (`lint/hooks.rs`): Git pre-commit hook install/uninstall/status.

The pipeline is defined as a static `CHECKS` array — adding or removing a check is a one-line change.

## Pre-commit Hook

`cargo xtask lint --install-hooks` writes a pre-commit hook that runs `cargo xtask lint --staged-only`. The `--staged-only` flag implies `--fix` and re-stages modified `.rs` files after the pipeline passes.

## Adding a New Check

1. Add a variant to `CheckId`
2. Add a `Check` entry to `CHECKS`
3. Add a skip flag to `LintArgs` and wire it in `should_skip()`
4. If fix mode differs, add a branch in `fix_args()`
5. If it's a builtin (not a subprocess), handle it in the `run()` loop like `FileLength`
