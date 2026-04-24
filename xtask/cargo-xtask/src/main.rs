#![deny(clippy::unwrap_used, clippy::expect_used)]

//! cargo-xtask — thin wrapper that skips cargo's fingerprint overhead when
//! `target/debug/xtask` is newer than every file under `xtask/src/**` and
//! `xtask/Cargo.toml`. Installed via `cargo install --path xtask/cargo-xtask`.

mod args;
mod staleness;

use std::env;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::SystemTime;

use crate::args::{dispatch, Dispatch};
use crate::staleness::{is_stale, Staleness};

const WORKSPACE_ENV: &str = "CARGO_WORKSPACE_DIR";
const BINARY_REL: &str = "target/debug/xtask";
const SOURCE_DIR_REL: &str = "xtask/src";
const MANIFEST_REL: &str = "xtask/Cargo.toml";

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    match run(&argv) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("cargo-xtask: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(argv: &[String]) -> io::Result<u8> {
    let parsed =
        dispatch(argv).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let workspace_root = find_workspace_root()?;
    let binary_path = workspace_root.join(BINARY_REL);

    let staleness = if parsed.force_rebuild() {
        Staleness::Stale
    } else {
        let binary_mtime = mtime(&binary_path).ok();
        let source_mtimes = collect_source_mtimes(&workspace_root)?;
        is_stale(binary_mtime, &source_mtimes)
    };

    if staleness == Staleness::Stale {
        cargo_build(&workspace_root)?;
    }

    exec_xtask(&binary_path, &parsed)
}

/// Returns `true` when `path` names a file whose contents include `[workspace]`.
fn is_workspace_manifest(path: &Path) -> bool {
    path.is_file()
        && fs::read_to_string(path)
            .map(|s| s.contains("[workspace]"))
            .unwrap_or(false)
}

/// Locate the workspace root by reading `CARGO_WORKSPACE_DIR`, then walking
/// upward from `cwd` looking for a `Cargo.toml` with a `[workspace]` table.
fn find_workspace_root() -> io::Result<PathBuf> {
    if let Ok(dir) = env::var(WORKSPACE_ENV) {
        if !dir.is_empty() {
            let p = PathBuf::from(dir);
            if is_workspace_manifest(&p.join("Cargo.toml")) {
                return Ok(p);
            }
        }
    }

    let mut cur = env::current_dir()?;
    loop {
        let manifest = cur.join("Cargo.toml");
        if is_workspace_manifest(&manifest) {
            return Ok(cur);
        }
        if !cur.pop() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "could not locate workspace root — run cargo xtask from within the repo",
            ));
        }
    }
}

fn mtime(path: &Path) -> io::Result<SystemTime> {
    fs::metadata(path)?.modified()
}

fn collect_source_mtimes(workspace_root: &Path) -> io::Result<Vec<SystemTime>> {
    let src_dir = workspace_root.join(SOURCE_DIR_REL);
    let manifest = workspace_root.join(MANIFEST_REL);

    let mut out = Vec::with_capacity(64);
    walk(&src_dir, &mut out)?;
    out.push(mtime(&manifest)?);
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<SystemTime>) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(&path, out)?;
        } else if ft.is_file() {
            if let Ok(m) = mtime(&path) {
                out.push(m);
            }
        }
    }
    Ok(())
}

fn cargo_build(workspace_root: &Path) -> io::Result<()> {
    let status = Command::new("cargo")
        .current_dir(workspace_root)
        .args(["build", "-p", "xtask", "--quiet"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "cargo build failed with exit status {status}"
        )));
    }
    Ok(())
}

/// Replace this process with the cached xtask binary, passing the forwarded args.
fn exec_xtask(binary_path: &Path, parsed: &Dispatch) -> io::Result<u8> {
    // CommandExt::exec replaces this process (execvp semantics) without unsafe.
    // On success it never returns; on failure it returns the OS error.
    let err = Command::new(binary_path).args(parsed.forwarded()).exec();
    Err(err)
}
