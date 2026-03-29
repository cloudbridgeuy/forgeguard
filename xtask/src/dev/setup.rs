use clap::Args;
use color_eyre::eyre::{bail, Context, Result};

use super::setup_core::{
    derive_issuer, derive_jwks_url, format_dry_run, format_vp_dry_run, merge_authn_jwt_toml,
    merge_authz_toml, merge_env_vars, validate_preflight, PreflightChecks, SetupParams,
    VpSetupParams,
};
use super::users;

// ---------------------------------------------------------------------------
// CLI Arguments
// ---------------------------------------------------------------------------

/// CLI arguments for the `dev setup` subcommand.
#[derive(Args)]
pub(crate) struct SetupArgs {
    /// Deploy Cognito user pool and seed test users
    #[arg(long)]
    cognito: bool,
    /// Deploy Verified Permissions policy store
    #[arg(long)]
    vp: bool,
    /// Run all setup steps (cognito + vp)
    #[arg(long)]
    all: bool,
    /// Delete and recreate test users
    #[arg(long)]
    force: bool,
    /// Destroy the CDK stack(s) and all their resources
    #[arg(long)]
    destroy: bool,
    /// Print what would happen without executing
    #[arg(long)]
    dry_run: bool,
}

// ---------------------------------------------------------------------------
// Resolved flags (after --all expansion)
// ---------------------------------------------------------------------------

/// Resolved setup targets after expanding `--all`.
struct ResolvedTargets {
    cognito: bool,
    vp: bool,
}

impl ResolvedTargets {
    fn from_args(args: &SetupArgs) -> Self {
        if args.all {
            Self {
                cognito: true,
                vp: true,
            }
        } else {
            Self {
                cognito: args.cognito,
                vp: args.vp,
            }
        }
    }

    fn any(&self) -> bool {
        self.cognito || self.vp
    }
}

// ---------------------------------------------------------------------------
// Env config loading (no global env mutation)
// ---------------------------------------------------------------------------

/// Configuration values read from `infra/dev/.env`.
struct EnvConfig {
    stack_prefix: String,
    region: String,
    aws_profile: String,
    password: String,
}

/// Read configuration from `infra/dev/.env` without polluting the process
/// environment. Values are parsed from the file directly.
fn load_env_config() -> Result<EnvConfig> {
    let content =
        std::fs::read_to_string("infra/dev/.env").context("failed to read infra/dev/.env")?;

    let mut stack_prefix = None;
    let mut region = None;
    let mut aws_profile = None;
    let mut password = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            match key.trim() {
                "STACK_PREFIX" => stack_prefix = Some(value.trim().to_string()),
                "AWS_REGION" => region = Some(value.trim().to_string()),
                "AWS_PROFILE" => aws_profile = Some(value.trim().to_string()),
                "DEV_PASSWORD" => password = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }

    Ok(EnvConfig {
        stack_prefix: stack_prefix
            .ok_or_else(|| color_eyre::eyre::eyre!("STACK_PREFIX not set in infra/dev/.env"))?,
        region: region
            .ok_or_else(|| color_eyre::eyre::eyre!("AWS_REGION not set in infra/dev/.env"))?,
        aws_profile: aws_profile.unwrap_or_else(|| "admin".to_string()),
        password: password
            .ok_or_else(|| color_eyre::eyre::eyre!("DEV_PASSWORD not set in infra/dev/.env"))?,
    })
}

/// Build an AWS SDK config using explicit profile and region (no env vars).
async fn build_aws_config(profile: &str, region: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .profile_name(profile)
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await
}

// ---------------------------------------------------------------------------
// Imperative Shell -- I/O, side effects, orchestration
// ---------------------------------------------------------------------------

/// Check whether a program exists on PATH.
fn tool_exists(name: &str) -> bool {
    duct::cmd("which", [name])
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract a specific output value from CloudFormation stack outputs.
fn find_stack_output(
    outputs: &[aws_sdk_cloudformation::types::Output],
    key: &str,
) -> Result<String> {
    outputs
        .iter()
        .find(|o| o.output_key.as_deref() == Some(key))
        .and_then(|o| o.output_value.clone())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!("stack output `{key}` not found in CloudFormation outputs")
        })
}

/// Ensure CDK node_modules are installed.
fn ensure_node_modules() -> Result<()> {
    if !std::path::Path::new("infra/dev/node_modules").exists() {
        println!("Installing node_modules...");
        duct::cmd("bun", ["install"])
            .dir("infra/dev")
            .run()
            .context("bun install failed")?;
    }
    Ok(())
}

/// Bootstrap the CDK environment (idempotent).
fn bootstrap_cdk(profile: &str) -> Result<()> {
    println!("Ensuring CDK environment is bootstrapped...");
    duct::cmd!("bun", "run", "cdk", "bootstrap", "--profile", profile)
        .dir("infra/dev")
        .run()
        .context("CDK bootstrap failed")?;
    Ok(())
}

/// Read CloudFormation stack outputs for the given stack name.
async fn read_stack_outputs(
    cf_client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<Vec<aws_sdk_cloudformation::types::Output>> {
    println!("Reading CloudFormation stack outputs for {stack_name}...");
    let describe = cf_client
        .describe_stacks()
        .stack_name(stack_name)
        .send()
        .await
        .context("DescribeStacks failed")?;

    let stacks = describe.stacks();
    let stack = stacks
        .first()
        .ok_or_else(|| color_eyre::eyre::eyre!("stack `{stack_name}` not found"))?;

    Ok(stack.outputs().to_vec())
}

// ---------------------------------------------------------------------------
// Destroy mode
// ---------------------------------------------------------------------------

/// Destroy one or more CDK stacks.
async fn run_destroy(args: &SetupArgs, targets: &ResolvedTargets) -> Result<()> {
    if !std::path::Path::new("infra/dev/.env").exists() {
        std::fs::copy("infra/dev/.env.example", "infra/dev/.env")
            .context("failed to copy .env.example to .env")?;
    }
    let env = load_env_config()?;

    let mut stack_names = Vec::new();
    if targets.cognito {
        stack_names.push(format!("{}-cognito", env.stack_prefix));
    }
    if targets.vp {
        stack_names.push(format!("{}-verified-permissions", env.stack_prefix));
    }

    if args.dry_run {
        for name in &stack_names {
            println!("Dry run -- would destroy CDK stack: {name}");
        }
        return Ok(());
    }

    ensure_node_modules()?;

    for stack_name in &stack_names {
        println!("Destroying CDK stack: {stack_name}...");
        duct::cmd!(
            "bun",
            "run",
            "cdk",
            "destroy",
            stack_name,
            "--force",
            "--profile",
            &env.aws_profile
        )
        .dir("infra/dev")
        .run()
        .context("CDK destroy failed")?;
        println!("Stack {stack_name} destroyed.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Cognito setup
// ---------------------------------------------------------------------------

/// Deploy Cognito stack, seed users, and update config files.
async fn run_cognito_setup(args: &SetupArgs, env: &EnvConfig) -> Result<()> {
    let users_content = std::fs::read_to_string("infra/dev/users.toml")
        .context("failed to read infra/dev/users.toml")?;
    let user_config = users::parse_users_toml(&users_content)?;
    let groups_context = users::build_groups_context(&user_config);

    let params = SetupParams {
        stack_prefix: env.stack_prefix.clone(),
        region: env.region.clone(),
        groups_context,
        password: env.password.clone(),
        force: args.force,
    };

    if args.dry_run {
        print!("{}", format_dry_run(&params));
        return Ok(());
    }

    ensure_node_modules()?;
    bootstrap_cdk(&env.aws_profile)?;

    // -- Deploy CDK stack -------------------------------------------------

    println!("Deploying CDK stack: {}-cognito...", params.stack_prefix);
    duct::cmd!(
        "bun",
        "run",
        "cdk",
        "deploy",
        "--require-approval",
        "never",
        "--profile",
        &env.aws_profile,
        "--context",
        format!("stackPrefix={}", params.stack_prefix),
        "--context",
        format!("groups={}", params.groups_context)
    )
    .dir("infra/dev")
    .run()
    .context("CDK deploy failed")?;

    // -- Read CloudFormation outputs --------------------------------------

    let aws_config = build_aws_config(&env.aws_profile, &env.region).await;
    let cf_client = aws_sdk_cloudformation::Client::new(&aws_config);

    let stack_name = format!("{}-cognito", params.stack_prefix);
    let outputs = read_stack_outputs(&cf_client, &stack_name).await?;

    let user_pool_id = find_stack_output(&outputs, "UserPoolId")?;
    let app_client_id = find_stack_output(&outputs, "AppClientId")?;

    let jwks_url = derive_jwks_url(&params.region, &user_pool_id);
    let issuer = derive_issuer(&params.region, &user_pool_id);

    // -- Seed users -------------------------------------------------------

    let cognito_client = aws_sdk_cognitoidentityprovider::Client::new(&aws_config);

    for user in user_config.users() {
        let username = user.username();

        // Optionally force-delete first.
        if params.force {
            println!("Deleting user (--force): {username}");
            let delete_result = cognito_client
                .admin_delete_user()
                .user_pool_id(&user_pool_id)
                .username(username)
                .send()
                .await;

            if let Err(err) = delete_result {
                let service_err = err.into_service_error();
                if !service_err.is_user_not_found_exception() {
                    return Err(color_eyre::eyre::eyre!(service_err))
                        .context(format!("failed to delete user {username}"));
                }
            }
        }

        // Create user.
        println!("Creating user: {username}");
        let create_result = cognito_client
            .admin_create_user()
            .user_pool_id(&user_pool_id)
            .username(username)
            .temporary_password(&params.password)
            .message_action(aws_sdk_cognitoidentityprovider::types::MessageActionType::Suppress)
            .user_attributes(
                aws_sdk_cognitoidentityprovider::types::AttributeType::builder()
                    .name("custom:org_id")
                    .value(user.tenant())
                    .build()
                    .context("failed to build org_id attribute")?,
            )
            .send()
            .await;

        match create_result {
            Ok(_) => {}
            Err(err) => {
                let service_err = err.into_service_error();
                if service_err.is_username_exists_exception() && !params.force {
                    println!("  user {username} already exists, skipping creation");
                } else {
                    return Err(color_eyre::eyre::eyre!(service_err))
                        .context(format!("failed to create user {username}"));
                }
            }
        }

        // Set permanent password.
        println!("  setting password for {username}");
        cognito_client
            .admin_set_user_password()
            .user_pool_id(&user_pool_id)
            .username(username)
            .password(&params.password)
            .permanent(true)
            .send()
            .await
            .context(format!("failed to set password for {username}"))?;

        // Assign groups.
        for group in user.groups() {
            println!("  adding {username} to group {group}");
            cognito_client
                .admin_add_user_to_group()
                .user_pool_id(&user_pool_id)
                .username(username)
                .group_name(group)
                .send()
                .await
                .context(format!("failed to add {username} to group {group}"))?;
        }
    }

    // -- Update config files ----------------------------------------------

    // .env
    let existing_env =
        std::fs::read_to_string("infra/dev/.env").context("failed to read infra/dev/.env")?;
    let updated_env = merge_env_vars(
        &existing_env,
        &[
            ("COGNITO_USER_POOL_ID", &user_pool_id),
            ("COGNITO_APP_CLIENT_ID", &app_client_id),
            ("COGNITO_JWKS_URL", &jwks_url),
            ("COGNITO_ISSUER", &issuer),
        ],
    );
    std::fs::write("infra/dev/.env", &updated_env).context("failed to write infra/dev/.env")?;
    println!("Updated infra/dev/.env");

    // forgeguard.dev.toml
    let existing_toml = std::fs::read_to_string("forgeguard.dev.toml").unwrap_or_default();
    let updated_toml = merge_authn_jwt_toml(&existing_toml, &jwks_url, &issuer)?;
    std::fs::write("forgeguard.dev.toml", &updated_toml)
        .context("failed to write forgeguard.dev.toml")?;
    println!("Updated forgeguard.dev.toml");

    println!("\nCognito setup complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// VP setup
// ---------------------------------------------------------------------------

/// Deploy Verified Permissions stack and update config files.
async fn run_vp_setup(args: &SetupArgs, env: &EnvConfig) -> Result<()> {
    let params = VpSetupParams {
        stack_prefix: env.stack_prefix.clone(),
        region: env.region.clone(),
    };

    if args.dry_run {
        print!("{}", format_vp_dry_run(&params));
        return Ok(());
    }

    ensure_node_modules()?;
    bootstrap_cdk(&env.aws_profile)?;

    // -- Deploy CDK stack -------------------------------------------------

    let stack_name = format!("{}-verified-permissions", params.stack_prefix);
    println!("Deploying CDK stack: {stack_name}...");
    duct::cmd!(
        "bun",
        "run",
        "cdk",
        "deploy",
        &stack_name,
        "--require-approval",
        "never",
        "--profile",
        &env.aws_profile,
        "--context",
        format!("stackPrefix={}", params.stack_prefix)
    )
    .dir("infra/dev")
    .run()
    .context("CDK deploy failed")?;

    // -- Read CloudFormation outputs --------------------------------------

    let aws_config = build_aws_config(&env.aws_profile, &env.region).await;
    let cf_client = aws_sdk_cloudformation::Client::new(&aws_config);

    let outputs = read_stack_outputs(&cf_client, &stack_name).await?;
    let policy_store_id = find_stack_output(&outputs, "PolicyStoreId")?;

    // -- Update config files ----------------------------------------------

    // .env
    let existing_env =
        std::fs::read_to_string("infra/dev/.env").context("failed to read infra/dev/.env")?;
    let updated_env = merge_env_vars(&existing_env, &[("VP_POLICY_STORE_ID", &policy_store_id)]);
    std::fs::write("infra/dev/.env", &updated_env).context("failed to write infra/dev/.env")?;
    println!("Updated infra/dev/.env");

    // forgeguard.dev.toml
    let existing_toml = std::fs::read_to_string("forgeguard.dev.toml").unwrap_or_default();
    let updated_toml = merge_authz_toml(&existing_toml, &policy_store_id)?;
    std::fs::write("forgeguard.dev.toml", &updated_toml)
        .context("failed to write forgeguard.dev.toml")?;
    println!("Updated forgeguard.dev.toml");

    println!("\nVP setup complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the `dev setup` subcommand.
pub(crate) async fn run(args: &SetupArgs) -> Result<()> {
    let targets = ResolvedTargets::from_args(args);

    if !targets.any() {
        bail!(
            "specify at least one target: --cognito, --vp, or --all\n\
             example: cargo xtask dev setup --cognito"
        );
    }

    // -- Destroy mode -----------------------------------------------------

    if args.destroy {
        return run_destroy(args, &targets).await;
    }

    // -- Auto-copy example files if missing -------------------------------

    if !std::path::Path::new("infra/dev/.env").exists() {
        std::fs::copy("infra/dev/.env.example", "infra/dev/.env")
            .context("failed to copy .env.example to .env")?;
        println!("Created infra/dev/.env from .env.example");
    }

    if targets.cognito && !std::path::Path::new("infra/dev/users.toml").exists() {
        std::fs::copy("infra/dev/users.example.toml", "infra/dev/users.toml")
            .context("failed to copy users.example.toml to users.toml")?;
        println!("Created infra/dev/users.toml from users.example.toml");
    }

    // -- Preflight: check tools -------------------------------------------

    let checks = PreflightChecks {
        bun_exists: tool_exists("bun"),
        bunx_exists: tool_exists("bunx"),
        env_file_exists: true,
        users_file_exists: !targets.cognito
            || std::path::Path::new("infra/dev/users.toml").exists(),
    };

    let tool_errors = validate_preflight(&checks);
    if !tool_errors.is_empty() {
        let msg = tool_errors.join("\n  - ");
        bail!("preflight checks failed:\n  - {msg}");
    }

    // -- Load config (no global env mutation) ------------------------------

    let env = load_env_config()?;

    // -- Run selected targets in sequence ---------------------------------

    if targets.cognito {
        run_cognito_setup(args, &env).await?;
    }

    if targets.vp {
        run_vp_setup(args, &env).await?;
    }

    if targets.cognito && targets.vp {
        println!("\nAll setup complete.");
    }

    Ok(())
}
