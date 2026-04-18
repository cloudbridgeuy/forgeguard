//! `cargo xtask control-plane token` — retrieve a JWT for a seeded test user.
//!
//! Reads the user's password from 1Password and calls Cognito's
//! `AdminInitiateAuth` to obtain tokens. Default output is the raw
//! `id_token` on stdout (pipe-friendly). Use `--verbose` for full JSON.

use clap::Args;
use color_eyre::eyre::{self, Context, Result};

use super::op::{build_aws_config, read_op};
use super::op_core::{build_vault_name, ForgeguardEnv};

/// CLI arguments for the token subcommand.
#[derive(Args)]
pub(crate) struct TokenArgs {
    /// Cognito username (as defined in seed.toml).
    #[arg(long)]
    user: String,

    /// Print full JSON with id_token, access_token, expires_in, and token_type.
    #[arg(long)]
    verbose: bool,

    /// Environment.
    #[arg(long, default_value = "prod", env = "FORGEGUARD_ENV")]
    env: ForgeguardEnv,

    /// 1Password account ID.
    #[arg(
        long,
        default_value = "YYN6IHBFRRD5RCLU63J46WPKMA",
        env = "FORGEGUARD_OP_ACCOUNT"
    )]
    op_account: String,

    /// AWS region.
    #[arg(long, default_value = "us-east-2", env = "AWS_REGION")]
    region: String,

    /// AWS profile.
    #[arg(long, default_value = "admin", env = "AWS_PROFILE")]
    profile: String,
}

pub(crate) async fn run(args: &TokenArgs) -> Result<()> {
    use aws_sdk_cognitoidentityprovider::types::AuthFlowType;

    let vault = build_vault_name(args.env);
    let op_account = Some(args.op_account.as_str());

    let pool_id = read_op(&vault, "cognito", "user-pool-id", op_account)?;
    let client_id = read_op(&vault, "cognito", "app-client-id", op_account)?;
    let password = read_op(
        &vault,
        &format!("test-user-{}", args.user),
        "password",
        op_account,
    )?;

    let sdk_config = build_aws_config(&args.profile, &args.region).await?;
    let client = aws_sdk_cognitoidentityprovider::Client::new(&sdk_config);

    let resp = client
        .admin_initiate_auth()
        .user_pool_id(&pool_id)
        .client_id(&client_id)
        .auth_flow(AuthFlowType::AdminUserPasswordAuth)
        .auth_parameters("USERNAME", &args.user)
        .auth_parameters("PASSWORD", &password)
        .send()
        .await
        .with_context(|| format!("failed to authenticate user '{}'", args.user))?;

    let result = resp
        .authentication_result()
        .ok_or_else(|| eyre::eyre!("no authentication result returned"))?;

    let id_token = result
        .id_token()
        .ok_or_else(|| eyre::eyre!("no id_token in authentication result"))?;

    if args.verbose {
        let output = serde_json::json!({
            "id_token": id_token,
            "access_token": result.access_token().unwrap_or_default(),
            "expires_in": result.expires_in(),
            "token_type": result.token_type().unwrap_or_default(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("failed to serialize token output")?
        );
    } else {
        print!("{id_token}");
    }

    Ok(())
}
