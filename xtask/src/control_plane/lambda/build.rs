use color_eyre::eyre::{self, Result};

use crate::control_plane::lambda_core;
use crate::control_plane::op;

pub(crate) fn run(target_name: &str) -> Result<()> {
    let target = lambda_core::find_target(target_name)
        .ok_or_else(|| eyre::eyre!("unknown target: {target_name}"))?;

    op::run_preflight()?;

    println!("Building {} for aarch64...", target.binary_name);

    duct::cmd(
        "cargo",
        [
            "lambda",
            "build",
            "--release",
            "--arm64",
            "--bin",
            target.binary_name,
        ],
    )
    .run()
    .map_err(|e| eyre::eyre!("cargo-lambda build failed: {e}"))?;

    let bootstrap_path = format!("target/lambda/{}/bootstrap", target.binary_name);
    let metadata = std::fs::metadata(&bootstrap_path)
        .map_err(|e| eyre::eyre!("bootstrap not found at {bootstrap_path}: {e}"))?;

    let size_mb = metadata.len() as f64 / 1_048_576.0;
    println!("  {bootstrap_path} ({size_mb:.1} MB)");

    Ok(())
}
