mod cedar;
pub(crate) mod cedar_core;
pub(crate) mod cedar_io;
mod infra;
mod lambda;
pub(crate) mod lambda_core;
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
    /// Cedar policy store management
    Cedar(cedar::CedarArgs),
    /// Infrastructure management
    Infra(infra::InfraArgs),
    /// Lambda build and deployment
    Lambda(lambda::LambdaArgs),
}

pub async fn run(args: &ControlPlaneArgs) -> Result<()> {
    match &args.command {
        ControlPlaneCommands::Cedar(a) => cedar::run(a).await,
        ControlPlaneCommands::Infra(a) => infra::run(a).await,
        ControlPlaneCommands::Lambda(a) => lambda::run(a).await,
    }
}
