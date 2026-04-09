use color_eyre::eyre::{self, Result};

use crate::control_plane::cedar_core;
use crate::control_plane::cedar_io;
use crate::control_plane::op;
use crate::control_plane::op_core::ForgeguardEnv;

pub(crate) async fn run(
    env: ForgeguardEnv,
    op_account: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    // 1. Preflight
    op::run_preflight()?;
    let region = region.ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = profile.ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;

    // 2. Resolve policy store ID from 1Password
    let op_ref = format!("op://forgeguard-{env}/verified-permissions/policy-store-id");
    let store_id = cedar_io::resolve_policy_store_id(&op_ref, op_account)?;

    // 3. Build AWS config and VP client
    let aws_config = op::build_aws_config(profile, region).await?;
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

    // 4. Read store state
    let state = cedar_io::read_vp_state(&vp_client, &store_id).await?;

    // 5. Format and print
    println!("{}", cedar_core::format_status(&store_id, &state));

    Ok(())
}
