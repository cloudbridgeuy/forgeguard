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

    // 2. Parse config
    let config = cedar_io::parse_cedar_config(&args.config)?;
    println!("Parsed config from {}", args.config.display());

    // 3. Resolve policy store ID (op:// or plain)
    let store_id = cedar_io::resolve_policy_store_id(&config.policy_store_id, op_account)?;
    println!("Policy store: {store_id}");

    // 4. Read schema file if [schema] section present
    let schema_content = match &config.schema {
        Some(schema_cfg) => {
            let content = cedar_io::read_schema_file(&args.config, &schema_cfg.path)?;
            println!("Schema: loaded from {}", schema_cfg.path);
            Some(content)
        }
        None => {
            println!("Schema: none configured");
            None
        }
    };

    // 5. Build desired state
    let desired = cedar_core::build_desired_state(&config, schema_content)?;

    // 6. Build AWS config and VP client
    let aws_config = op::build_aws_config(profile, region).await?;
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

    // 7. Read current VP state
    println!("Reading current VP state...");
    let current = cedar_io::read_vp_state(&vp_client, &store_id).await?;

    // 8. Compute diff
    let plan = cedar_core::compute_sync_plan(&desired, &current);

    if plan.is_empty() {
        println!("\nNo changes.");
        return Ok(());
    }

    // 9. Dry-run gate
    if args.dry_run {
        println!("\n--- Dry-run mode ---");
        println!("{} action(s) planned.", plan.actions.len());
        println!("No changes synced to AWS.");
        return Ok(());
    }

    // 10. Apply sync plan
    println!("Applying {} action(s)...", plan.actions.len());
    let result = cedar_io::apply_sync_plan(&vp_client, &store_id, &plan).await?;

    // 11. Print summary
    println!("\n{}", cedar_core::format_summary(&result));

    Ok(())
}
