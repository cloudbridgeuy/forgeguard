mod deploy;
mod destroy;
mod diff;
mod status;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

use crate::control_plane::op_core::ForgeguardEnv;

#[derive(Args)]
pub(crate) struct InfraArgs {
    #[command(subcommand)]
    command: InfraCommands,
    /// Target environment.
    #[arg(long, global = true, env = "FORGEGUARD_ENV", default_value = "prod")]
    env: ForgeguardEnv,
    /// 1Password account identifier (email or UUID) for multi-account setups.
    #[arg(
        long,
        global = true,
        env = "FORGEGUARD_OP_ACCOUNT",
        default_value = "YYN6IHBFRRD5RCLU63J46WPKMA"
    )]
    op_account: Option<String>,
    /// AWS region for CloudFormation queries.
    #[arg(long, global = true, env = "AWS_REGION", default_value = "us-east-2")]
    region: Option<String>,
    /// AWS CLI profile name.
    #[arg(long, global = true, env = "AWS_PROFILE", default_value = "admin")]
    profile: Option<String>,
}

#[derive(Subcommand)]
enum InfraCommands {
    /// Deploy infrastructure via CDK
    Deploy,
    /// Preview infrastructure changes
    Diff,
    /// Destroy infrastructure (requires confirmation)
    Destroy,
    /// Show current infrastructure status
    Status,
}

pub(crate) async fn run(args: &InfraArgs) -> Result<()> {
    let env = args.env;
    let op_account = args.op_account.as_deref();
    let region = args.region.as_deref();
    let profile = args.profile.as_deref();

    match &args.command {
        InfraCommands::Deploy => deploy::run(env, op_account, region, profile).await,
        InfraCommands::Diff => diff::run(env, op_account).await,
        InfraCommands::Destroy => destroy::run(env, op_account).await,
        InfraCommands::Status => status::run(env, op_account, region, profile).await,
    }
}
