mod build;
mod deploy;
mod list;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

use crate::control_plane::op_core::ForgeguardEnv;

#[derive(Args)]
pub(crate) struct LambdaArgs {
    #[command(subcommand)]
    command: LambdaCommands,
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
enum LambdaCommands {
    /// Cross-compile a Lambda binary for ARM64
    Build {
        /// Target name (e.g. "control-plane", "saga-trigger")
        target: String,
    },
    /// Deploy a Lambda function to AWS
    Deploy {
        /// Target name (e.g. "control-plane", "saga-trigger")
        target: Option<String>,
        /// Deploy all registered targets
        #[arg(long)]
        all: bool,
        /// Show what would happen without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// List all registered Lambda targets
    List,
}

pub(crate) async fn run(args: &LambdaArgs) -> Result<()> {
    match &args.command {
        LambdaCommands::Build { target } => build::run(target),
        LambdaCommands::Deploy {
            target,
            all,
            dry_run,
        } => {
            deploy::run(deploy::DeployOpts {
                target_name: target.as_deref(),
                all: *all,
                dry_run: *dry_run,
                env: args.env,
                op_account: args.op_account.as_deref(),
                region: args.region.as_deref(),
                profile: args.profile.as_deref(),
            })
            .await
        }
        LambdaCommands::List => list::run(),
    }
}
