use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{self, Result};

use crate::control_plane::cedar_core;
use crate::control_plane::cedar_io;
use crate::control_plane::op;

#[derive(Args)]
pub(crate) struct SyncArgs {
    /// Path to the forgeguard.toml configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Dry-run mode: show what would be synced without making changes.
    #[arg(long)]
    dry_run: bool,
}

pub(crate) async fn run(
    args: &SyncArgs,
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
    println!("Parsed config from {}", args.config.display());
    println!("Policy store: {}", pipeline.store_id);

    // 3. Build AWS config and VP client
    let aws_config = op::build_aws_config(profile, region).await?;
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

    // 4. Read current VP state and compute diff
    println!("Reading current VP state...");
    let current = cedar_io::read_vp_state(&vp_client, &pipeline.store_id).await?;
    let plan = cedar_core::compute_sync_plan(&pipeline.desired, &current);

    if plan.is_empty() {
        println!("\nNo changes.");
        return Ok(());
    }

    // 5. Dry-run gate
    if args.dry_run {
        println!("\n--- Dry-run mode ---");
        print!("{}", cedar_core::format_sync_plan(&plan));
        return Ok(());
    }

    // 6. Apply sync plan
    println!("Applying {} action(s)...", plan.actions.len());
    let result = cedar_io::apply_sync_plan(&vp_client, &pipeline.store_id, &plan).await?;

    // 7. Print summary
    println!("\n{}", cedar_core::format_summary(&result));

    Ok(())
}
