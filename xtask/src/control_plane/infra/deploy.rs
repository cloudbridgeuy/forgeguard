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
    let region = region.ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = profile.ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;
    op::ensure_aws_session(profile)?;

    // 2. Ensure node_modules
    op::ensure_node_modules("infra/control-plane")?;

    // 3. Run CDK deploy (deploys all stacks)
    let stack_name = op_core::build_stack_name(env);
    let lambda_stack_name = op_core::build_lambda_stack_name(env);
    let vp_stack_name = op_core::build_vp_stack_name(env);
    println!("Deploying {stack_name}, {lambda_stack_name}, {vp_stack_name}...");
    op::run_cdk_with_op(
        ".env",
        env,
        &["deploy", "--all", "--require-approval", "never"],
        op_account,
    )?;

    // 4. Read CloudFormation outputs
    let aws_config = op::build_aws_config(profile, region).await?;
    let cf_client = aws_sdk_cloudformation::Client::new(&aws_config);

    // DynamoDB outputs
    let outputs = op::read_stack_outputs(&cf_client, &stack_name).await?;
    let table_name = op::find_stack_output(&outputs, "TableName")?;
    let table_arn = op::find_stack_output(&outputs, "TableArn")?;

    // Lambda outputs
    let lambda_outputs = op::read_stack_outputs(&cf_client, &lambda_stack_name).await?;
    let cp_arn = op::find_stack_output(&lambda_outputs, "ControlPlaneFunctionArn")?;
    let cp_url = op::find_stack_output(&lambda_outputs, "ControlPlaneFunctionUrl")?;
    let saga_arn = op::find_stack_output(&lambda_outputs, "SagaTriggerFunctionArn")?;
    let dlq_arn = op::find_stack_output(&lambda_outputs, "DlqArn")?;

    // VP outputs
    let vp_outputs = op::read_stack_outputs(&cf_client, &vp_stack_name).await?;
    let policy_store_id = op::find_stack_output(&vp_outputs, "PolicyStoreId")?;

    // 5. Store outputs in 1Password
    let vault = op_core::build_vault_name(env);
    op::store_in_op(&vault, "dynamodb", "table-name", &table_name, op_account)?;
    op::store_in_op(&vault, "dynamodb", "table-arn", &table_arn, op_account)?;
    op::store_in_op(&vault, "lambda", "control-plane-arn", &cp_arn, op_account)?;
    op::store_in_op(&vault, "lambda", "control-plane-url", &cp_url, op_account)?;
    op::store_in_op(&vault, "lambda", "saga-trigger-arn", &saga_arn, op_account)?;
    op::store_in_op(&vault, "lambda", "dlq-arn", &dlq_arn, op_account)?;
    op::store_in_op(
        &vault,
        "verified-permissions",
        "policy-store-id",
        &policy_store_id,
        op_account,
    )?;

    println!("Deploy complete.");
    println!("  Table name:    {table_name}");
    println!("  Table ARN:     {table_arn}");
    println!("  CP function:   {cp_arn}");
    println!("  CP URL:        {cp_url}");
    println!("  Saga trigger:  {saga_arn}");
    println!("  DLQ ARN:       {dlq_arn}");
    println!("  Policy store:  {policy_store_id}");

    Ok(())
}
