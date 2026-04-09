mod status;
mod sync;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

use crate::control_plane::op_core::ForgeguardEnv;

#[derive(Args)]
pub(crate) struct CedarArgs {
    #[command(subcommand)]
    command: CedarCommands,
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
    /// AWS region.
    #[arg(long, global = true, env = "AWS_REGION", default_value = "us-east-2")]
    region: Option<String>,
    /// AWS CLI profile name.
    #[arg(long, global = true, env = "AWS_PROFILE", default_value = "admin")]
    profile: Option<String>,
}

#[derive(Subcommand)]
enum CedarCommands {
    /// Show the current VP policy store state
    Status,
    /// Sync Cedar schema, policies, and templates to VP
    Sync(sync::SyncArgs),
}

pub(crate) async fn run(args: &CedarArgs) -> Result<()> {
    match &args.command {
        CedarCommands::Status => {
            status::run(
                args.env,
                args.op_account.as_deref(),
                args.region.as_deref(),
                args.profile.as_deref(),
            )
            .await
        }
        CedarCommands::Sync(sync_args) => {
            sync::run(
                sync_args,
                args.env,
                args.op_account.as_deref(),
                args.region.as_deref(),
                args.profile.as_deref(),
            )
            .await
        }
    }
}
