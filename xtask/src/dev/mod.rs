mod setup;
mod token;
mod users;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct DevArgs {
    #[command(subcommand)]
    command: DevCommands,
}

#[derive(Subcommand)]
enum DevCommands {
    /// Deploy development infrastructure
    Setup(setup::SetupArgs),
    /// Get a test JWT for a development user
    Token(token::TokenArgs),
    /// List configured test users
    Users(users::UsersArgs),
}

pub async fn run(args: &DevArgs) -> Result<()> {
    match &args.command {
        DevCommands::Setup(a) => setup::run(a).await,
        DevCommands::Token(a) => token::run(a).await,
        DevCommands::Users(a) => users::run(a),
    }
}
