mod release;
mod version;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct LibArgs {
    #[command(subcommand)]
    command: LibCommands,
}

#[derive(Subcommand)]
enum LibCommands {
    /// Publish a lib crate and its shared dependencies to crates.io
    Release(release::ReleaseArgs),
}

pub fn run(args: &LibArgs) -> Result<()> {
    match &args.command {
        LibCommands::Release(release_args) => release::run(release_args),
    }
}
