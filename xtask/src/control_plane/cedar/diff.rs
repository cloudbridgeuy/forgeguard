use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{self, Result};

use crate::control_plane::cedar_core;
use crate::control_plane::cedar_io;
use crate::control_plane::op;

#[derive(Args)]
pub(crate) struct DiffArgs {
    /// Path to the forgeguard.toml configuration file.
    #[arg(long)]
    config: PathBuf,
}

pub(crate) async fn run(
    args: &DiffArgs,
    op_account: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    // 1. Preflight
    op::run_cedar_preflight()?;
    let region = region.ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = profile.ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;

    // 2. Parse config, resolve store ID, build desired state
    let pipeline = cedar_io::prepare_pipeline(&args.config, op_account)?;

    // 3. Build AWS config and VP client
    let aws_config = op::build_aws_config(profile, region).await?;
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

    // 4. Read current VP state and compute diff
    let current = cedar_io::read_vp_state(&vp_client, &pipeline.store_id).await?;
    let plan = cedar_core::compute_sync_plan(&pipeline.desired, &current);

    // 5. Format and print
    let output = cedar_core::format_sync_plan(&plan);
    print!("{output}");

    // 6. Exit with code (0 = no changes, 1 = changes pending)
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(cedar_core::exit_code_from_plan(&plan));
}
