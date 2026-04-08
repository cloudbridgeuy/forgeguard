mod infra;
pub(crate) mod op;
pub(crate) mod op_core;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct ControlPlaneArgs {
    #[command(subcommand)]
    command: ControlPlaneCommands,
}

#[derive(Subcommand)]
enum ControlPlaneCommands {
    /// Infrastructure management
    Infra(infra::InfraArgs),
}

pub async fn run(args: &ControlPlaneArgs) -> Result<()> {
    match &args.command {
        ControlPlaneCommands::Infra(a) => infra::run(a).await,
    }
}
