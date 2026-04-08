use color_eyre::eyre::{self, Context, Result};

use super::op_core::{self, ForgeguardEnv};

/// Check whether a program exists on `PATH`.
pub(crate) fn tool_exists(name: &str) -> bool {
    duct::cmd("which", [name])
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Store a value in 1Password.
pub(crate) fn store_in_op(
    vault: &str,
    item: &str,
    field: &str,
    value: &str,
    op_account: Option<&str>,
) -> Result<()> {
    let field_assignment = format!("{field}={value}");
    let mut args = vec![
        "item".to_string(),
        "edit".to_string(),
        item.to_string(),
        field_assignment,
        "--vault".to_string(),
        vault.to_string(),
    ];
    if let Some(account) = op_account {
        args.push("--account".to_string());
        args.push(account.to_string());
    }
    duct::cmd("op", &args)
        .stdout_capture()
        .stderr_capture()
        .run()
        .context(format!("failed to store {field} in 1Password item {item}"))?;
    Ok(())
}

/// Ensure CDK `node_modules` are installed. Runs `bun install` if missing.
pub(crate) fn ensure_node_modules(dir: &str) -> Result<()> {
    let modules_path = std::path::Path::new(dir).join("node_modules");
    if !modules_path.exists() {
        println!("Installing node_modules...");
        duct::cmd("bun", ["install"])
            .dir(dir)
            .run()
            .context("bun install failed")?;
    }
    Ok(())
}

/// Run a CDK command wrapped with `op run` for secret resolution.
///
/// `op run --env-file=<path>` resolves `op://` references in the env file and
/// passes the resolved values as environment variables to the subprocess.
pub(crate) fn run_cdk_with_op(
    env_file: &str,
    env: ForgeguardEnv,
    cdk_args: &[&str],
    op_account: Option<&str>,
) -> Result<()> {
    let env_file_arg = format!("--env-file={env_file}");
    let mut cmd_args = vec!["run".to_string(), env_file_arg];
    if let Some(account) = op_account {
        cmd_args.push("--account".to_string());
        cmd_args.push(account.to_string());
    }
    cmd_args.extend([
        "--".to_string(),
        "bun".to_string(),
        "run".to_string(),
        "cdk".to_string(),
    ]);
    cmd_args.extend(cdk_args.iter().map(|s| s.to_string()));

    duct::cmd("op", &cmd_args)
        .env("FORGEGUARD_ENV", env.to_string())
        .dir("infra/control-plane")
        .run()
        .context("CDK command failed")?;
    Ok(())
}

/// Run preflight checks: verify `bun` and `op` are on `PATH`.
pub(crate) fn run_preflight() -> Result<()> {
    let checks = op_core::PreflightChecks {
        bun_exists: tool_exists("bun"),
        op_exists: tool_exists("op"),
    };
    let errors = op_core::validate_preflight(&checks);
    if !errors.is_empty() {
        let msg = errors.join("\n  - ");
        eyre::bail!("preflight checks failed:\n  - {msg}");
    }
    Ok(())
}

/// Build an AWS SDK config using explicit profile and region.
pub(crate) async fn build_aws_config(profile: &str, region: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .profile_name(profile)
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await
}

/// Read CloudFormation stack outputs for the given stack name.
pub(crate) async fn read_stack_outputs(
    cf_client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<Vec<aws_sdk_cloudformation::types::Output>> {
    let describe = cf_client
        .describe_stacks()
        .stack_name(stack_name)
        .send()
        .await
        .context("DescribeStacks failed")?;

    let stacks = describe.stacks();
    let stack = stacks
        .first()
        .ok_or_else(|| eyre::eyre!("stack `{stack_name}` not found"))?;

    Ok(stack.outputs().to_vec())
}

/// Extract a specific output value from CloudFormation stack outputs.
pub(crate) fn find_stack_output(
    outputs: &[aws_sdk_cloudformation::types::Output],
    key: &str,
) -> Result<String> {
    outputs
        .iter()
        .find(|o| o.output_key.as_deref() == Some(key))
        .and_then(|o| o.output_value.clone())
        .ok_or_else(|| eyre::eyre!("stack output `{key}` not found in CloudFormation outputs"))
}
