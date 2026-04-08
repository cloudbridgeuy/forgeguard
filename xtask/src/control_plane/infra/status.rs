use color_eyre::eyre::{self, Context, Result};

use crate::control_plane::op;
use crate::control_plane::op_core::{self, ForgeguardEnv};

pub(crate) async fn run(
    env: ForgeguardEnv,
    _op_account: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    // 1. Preflight
    op::run_preflight()?;

    // 2. Build AWS config
    let region = region.ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = profile.ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;

    let stack_name = op_core::build_stack_name(env);
    let aws_config = op::build_aws_config(profile, region).await;
    let cf_client = aws_sdk_cloudformation::Client::new(&aws_config);

    let describe = cf_client
        .describe_stacks()
        .stack_name(&stack_name)
        .send()
        .await
        .context("DescribeStacks failed")?;

    let stack = describe
        .stacks()
        .first()
        .ok_or_else(|| eyre::eyre!("stack `{stack_name}` not found"))?;

    let status = stack
        .stack_status()
        .map(|s| s.as_str())
        .unwrap_or("UNKNOWN");
    let outputs = stack.outputs();

    // 3. Format and display
    let output_pairs: Vec<(&str, &str)> = outputs
        .iter()
        .filter_map(|o| Some((o.output_key()?, o.output_value()?)))
        .collect();

    println!(
        "{}",
        op_core::format_status_output(&stack_name, status, &output_pairs)
    );

    Ok(())
}
