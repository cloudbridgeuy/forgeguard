#![deny(clippy::unwrap_used, clippy::expect_used)]

mod aws;
mod check;
mod keygen;
mod policies;
mod routes;

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
        command: Box<PoliciesCommand>,
    },
    /// Validate a ForgeGuard configuration file.
    Check,
    /// Display the route table from a configuration file.
    Routes,
    /// Generate an Ed25519 signing keypair for request signing.
    Keygen {
        /// Directory to write the key files to.
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Key identifier (auto-generated if omitted).
        #[arg(long)]
        key_id: Option<String>,
        /// Overwrite existing key files.
        #[arg(long)]
        force: bool,
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
        Command::Check => check::run(&cli.config)?,
        Command::Routes => routes::run(&cli.config)?,
        Command::Keygen {
            out_dir,
            key_id,
            force,
        } => keygen::run(&out_dir, key_id.as_deref(), force)?,
    }

    Ok(())
}
