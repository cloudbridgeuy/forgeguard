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

    // 2. Parse config
    let config = cedar_io::parse_cedar_config(&args.config)?;

    // 3. Resolve policy store ID (op:// or plain)
    let store_id = cedar_io::resolve_policy_store_id(&config.policy_store_id, op_account)?;

    // 4. Read schema file if [schema] section present
    let schema_content = match &config.schema {
        Some(schema_cfg) => Some(cedar_io::read_schema_file(&args.config, &schema_cfg.path)?),
        None => None,
    };

    // 5. Build desired state
    let desired = cedar_core::build_desired_state(&config, schema_content)?;

    // 6. Build AWS config and VP client
    let aws_config = op::build_aws_config(profile, region).await?;
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

    // 7. Read current VP state
    let current = cedar_io::read_vp_state(&vp_client, &store_id).await?;

    // 8. Compute diff
    let plan = cedar_core::compute_sync_plan(&desired, &current);

    // 9. Format and print
    let output = cedar_core::format_sync_plan(&plan);
    print!("{output}");

    // 10. Exit with code (0 = no changes, 1 = changes pending)
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(cedar_core::exit_code_from_plan(&plan));
}
