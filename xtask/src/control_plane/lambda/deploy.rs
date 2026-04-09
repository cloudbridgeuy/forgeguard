use std::io::Write;

use color_eyre::eyre::{self, Result};

use crate::control_plane::lambda_core::{self, LambdaTarget};
use crate::control_plane::op;
use crate::control_plane::op_core::{self, ForgeguardEnv};

pub(crate) struct DeployOpts<'a> {
    pub(crate) target_name: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) dry_run: bool,
    pub(crate) env: ForgeguardEnv,
    pub(crate) op_account: Option<&'a str>,
    pub(crate) region: Option<&'a str>,
    pub(crate) profile: Option<&'a str>,
}

pub(crate) async fn run(opts: DeployOpts<'_>) -> Result<()> {
    let targets: Vec<&LambdaTarget> = if opts.all {
        lambda_core::TARGETS.iter().collect()
    } else {
        let name = opts
            .target_name
            .ok_or_else(|| eyre::eyre!("specify a <TARGET> or use --all"))?;
        let t =
            lambda_core::find_target(name).ok_or_else(|| eyre::eyre!("unknown target: {name}"))?;
        vec![t]
    };

    if opts.dry_run {
        for target in &targets {
            print_dry_run_plan(target, opts.env);
        }
        return Ok(());
    }

    op::run_preflight()?;

    let region = opts
        .region
        .ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = opts
        .profile
        .ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;
    let aws_config = op::build_aws_config(profile, region).await?;
    let lambda_client = aws_sdk_lambda::Client::new(&aws_config);
    let vault = op_core::build_vault_name(opts.env);
    let env_str = opts.env.to_string();

    for target in &targets {
        deploy_target(target, &env_str, &lambda_client, &vault, opts.op_account).await?;
    }

    if opts.all {
        println!("All targets deployed.");
    }

    Ok(())
}

fn print_dry_run_plan(target: &LambdaTarget, env: ForgeguardEnv) {
    let env_str = env.to_string();
    println!("Dry run: would deploy {}", target.name);
    println!("  Binary:   target/lambda/{}/bootstrap", target.binary_name);
    println!("  Function: {}", target.function_name(&env_str));
    println!("  No changes made.");
    println!();
}

async fn deploy_target(
    target: &LambdaTarget,
    env: &str,
    client: &aws_sdk_lambda::Client,
    vault: &str,
    op_account: Option<&str>,
) -> Result<()> {
    let function_name = target.function_name(env);

    // 1. Build
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

    // 2. Package
    let bootstrap_path = format!("target/lambda/{}/bootstrap", target.binary_name);
    let zip_bytes = zip_bootstrap(&bootstrap_path)?;
    println!(
        "Packaging bootstrap ({:.1} MB)...",
        zip_bytes.len() as f64 / 1_048_576.0
    );

    // 3. Upload
    println!("Updating {function_name}...");
    client
        .update_function_code()
        .function_name(&function_name)
        .zip_file(aws_sdk_lambda::primitives::Blob::new(zip_bytes))
        .send()
        .await
        .map_err(|e| eyre::eyre!("UpdateFunctionCode failed for {function_name}: {e}"))?;

    // 4. Wait for update
    println!("Waiting for update to complete...");
    poll_update_status(client, &function_name).await?;

    // 5. Read final state
    let config = client
        .get_function_configuration()
        .function_name(&function_name)
        .send()
        .await
        .map_err(|e| eyre::eyre!("GetFunctionConfiguration failed: {e}"))?;

    let arn = config.function_arn().unwrap_or("unknown");
    let code_size = config.code_size();
    let last_modified = config.last_modified().unwrap_or("unknown");

    println!("Deploy complete.");
    println!("  ARN:       {arn}");
    println!("  Code size: {code_size} bytes");
    println!("  Modified:  {last_modified}");

    // 6. Store in 1Password
    op::store_in_op(
        vault,
        "lambda",
        &format!("{}-arn", target.name),
        arn,
        op_account,
    )?;

    Ok(())
}

fn zip_bootstrap(bootstrap_path: &str) -> Result<Vec<u8>> {
    let bootstrap_bytes = std::fs::read(bootstrap_path)
        .map_err(|e| eyre::eyre!("failed to read {bootstrap_path}: {e}"))?;

    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);
        writer
            .start_file("bootstrap", options)
            .map_err(|e| eyre::eyre!("zip start_file failed: {e}"))?;
        writer
            .write_all(&bootstrap_bytes)
            .map_err(|e| eyre::eyre!("zip write failed: {e}"))?;
        writer
            .finish()
            .map_err(|e| eyre::eyre!("zip finish failed: {e}"))?;
    }

    Ok(buf)
}

async fn poll_update_status(client: &aws_sdk_lambda::Client, function_name: &str) -> Result<()> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(60);

    loop {
        if start.elapsed() > timeout {
            eyre::bail!("timed out waiting for {function_name} update to complete");
        }

        let config = client
            .get_function_configuration()
            .function_name(function_name)
            .send()
            .await
            .map_err(|e| eyre::eyre!("GetFunctionConfiguration failed: {e}"))?;

        match config.last_update_status() {
            Some(aws_sdk_lambda::types::LastUpdateStatus::Successful) => return Ok(()),
            Some(aws_sdk_lambda::types::LastUpdateStatus::Failed) => {
                let reason = config.last_update_status_reason().unwrap_or("unknown");
                eyre::bail!("function update failed: {reason}");
            }
            _ => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}
