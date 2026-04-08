use color_eyre::eyre::{self, Result};

use crate::control_plane::op;
use crate::control_plane::op_core::{self, ForgeguardEnv};

pub(crate) async fn run(
    env: ForgeguardEnv,
    op_account: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    // 1. Preflight
    op::run_preflight()?;

    // 2. Ensure node_modules
    op::ensure_node_modules("infra/control-plane")?;

    // 3. Run CDK deploy
    let stack_name = op_core::build_stack_name(env);
    println!("Deploying {stack_name}...");
    op::run_cdk_with_op(
        ".env",
        env,
        &["deploy", "--require-approval", "never"],
        op_account,
    )?;

    // 4. Read CloudFormation outputs
    let region = region.ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = profile.ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;

    let aws_config = op::build_aws_config(profile, region).await;
    let cf_client = aws_sdk_cloudformation::Client::new(&aws_config);
    let outputs = op::read_stack_outputs(&cf_client, &stack_name).await?;

    let table_name = op::find_stack_output(&outputs, "TableName")?;
    let table_arn = op::find_stack_output(&outputs, "TableArn")?;

    // 5. Store outputs in 1Password
    let vault = op_core::build_vault_name(env);
    op::store_in_op(&vault, "dynamodb", "table-name", &table_name, op_account)?;
    op::store_in_op(&vault, "dynamodb", "table-arn", &table_arn, op_account)?;

    println!("Deploy complete.");
    println!("  Table name: {table_name}");
    println!("  Table ARN:  {table_arn}");

    Ok(())
}
