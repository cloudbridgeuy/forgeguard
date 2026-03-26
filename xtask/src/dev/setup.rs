use clap::Args;
use color_eyre::eyre::{bail, Context, Result};

use super::setup_core::{
    derive_issuer, derive_jwks_url, format_dry_run, merge_authn_jwt_toml, merge_env_vars,
    validate_preflight, PreflightChecks, SetupParams,
};
use super::users;

// ---------------------------------------------------------------------------
// CLI Arguments
// ---------------------------------------------------------------------------

/// CLI arguments for the `dev setup` subcommand.
#[derive(Args)]
pub struct SetupArgs {
    /// Deploy Cognito user pool and seed test users
    #[arg(long)]
    pub cognito: bool,
    /// Delete and recreate test users
    #[arg(long)]
    pub force: bool,
    /// Print what would happen without executing
    #[arg(long)]
    pub dry_run: bool,
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

/// Run the `dev setup` subcommand.
pub async fn run(args: &SetupArgs) -> Result<()> {
    if !args.cognito {
        bail!(
            "currently only `--cognito` setup is supported; run: cargo xtask dev setup --cognito"
        );
    }

    // -- Auto-copy example files if missing --------------------------------

    if !std::path::Path::new("infra/dev/.env").exists() {
        std::fs::copy("infra/dev/.env.example", "infra/dev/.env")
            .context("failed to copy .env.example to .env")?;
        println!("Created infra/dev/.env from .env.example");
    }

    if !std::path::Path::new("infra/dev/users.toml").exists() {
        std::fs::copy("infra/dev/users.example.toml", "infra/dev/users.toml")
            .context("failed to copy users.example.toml to users.toml")?;
        println!("Created infra/dev/users.toml from users.example.toml");
    }

    // -- Preflight: check tools -------------------------------------------

    let checks = PreflightChecks {
        bun_exists: tool_exists("bun"),
        bunx_exists: tool_exists("bunx"),
        env_file_exists: true,
        users_file_exists: true,
    };

    let tool_errors = validate_preflight(&checks);
    if !tool_errors.is_empty() {
        let msg = tool_errors.join("\n  - ");
        bail!("preflight checks failed:\n  - {msg}");
    }

    // -- Load config ------------------------------------------------------

    dotenvy::from_path("infra/dev/.env").context("failed to load infra/dev/.env")?;

    let stack_prefix =
        std::env::var("STACK_PREFIX").context("STACK_PREFIX not set in infra/dev/.env")?;
    let region = std::env::var("AWS_REGION").context("AWS_REGION not set in infra/dev/.env")?;
    let password =
        std::env::var("DEV_PASSWORD").context("DEV_PASSWORD not set in infra/dev/.env")?;

    let users_content = std::fs::read_to_string("infra/dev/users.toml")
        .context("failed to read infra/dev/users.toml")?;
    let user_config = users::parse_users_toml(&users_content)?;
    let groups_context = users::build_groups_context(&user_config);

    let params = SetupParams {
        stack_prefix,
        region,
        groups_context,
        password,
        force: args.force,
    };

    // -- Dry run ----------------------------------------------------------

    if args.dry_run {
        print!("{}", format_dry_run(&params));
        return Ok(());
    }

    // -- Install node_modules if missing ----------------------------------

    if !std::path::Path::new("infra/dev/node_modules").exists() {
        println!("Installing node_modules...");
        duct::cmd("bun", ["install"])
            .dir("infra/dev")
            .run()
            .context("bun install failed")?;
    }

    // -- Deploy CDK stack -------------------------------------------------

    println!("Deploying CDK stack: {}-cognito...", params.stack_prefix);
    duct::cmd!(
        "bun",
        "run",
        "cdk",
        "deploy",
        "--require-approval",
        "never",
        "--context",
        format!("stackPrefix={}", params.stack_prefix),
        "--context",
        format!("groups={}", params.groups_context)
    )
    .dir("infra/dev")
    .run()
    .context("CDK deploy failed")?;

    // -- Read CloudFormation outputs --------------------------------------

    println!("Reading CloudFormation stack outputs...");
    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let cf_client = aws_sdk_cloudformation::Client::new(&aws_config);

    let stack_name = format!("{}-cognito", params.stack_prefix);
    let describe = cf_client
        .describe_stacks()
        .stack_name(&stack_name)
        .send()
        .await
        .context("DescribeStacks failed")?;

    let stacks = describe.stacks();
    let stack = stacks
        .first()
        .ok_or_else(|| color_eyre::eyre::eyre!("stack `{stack_name}` not found"))?;

    let outputs = stack.outputs();

    let user_pool_id = find_stack_output(outputs, "UserPoolId")?;
    let app_client_id = find_stack_output(outputs, "AppClientId")?;

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

    println!("\nSetup complete.");
    Ok(())
}
