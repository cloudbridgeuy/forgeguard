#![deny(clippy::unwrap_used, clippy::expect_used)]

mod aws;
mod policies;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use tracing_subscriber::EnvFilter;

use crate::policies::PoliciesCommand;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// ForgeGuard developer CLI -- schema validation, policy testing, local dev.
#[derive(Debug, Parser)]
#[command(name = "forgeguard", version, about)]
struct Cli {
    /// Path to the ForgeGuard configuration file.
    #[arg(long, default_value = "forgeguard.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage Cedar policies: validate, sync, and test.
    Policies {
        #[command(subcommand)]
        command: PoliciesCommand,
    },
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Policies { command } => command.run(&cli.config).await?,
    }

    Ok(())
}
