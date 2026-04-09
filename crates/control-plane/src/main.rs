#![deny(clippy::unwrap_used, clippy::expect_used)]

mod cli;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, StoreBackend};

#[tokio::main]
async fn main() {
    if let Err(e) = color_eyre::install() {
        eprintln!("failed to install color_eyre: {e}");
        std::process::exit(1);
    }

    let cli = Cli::parse();

    let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|e| {
        eprintln!(
            "invalid log level {:?}: {e}, falling back to info",
            cli.log_level
        );
        EnvFilter::new("info")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(e) = run(cli).await {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> color_eyre::Result<()> {
    let router = match cli.store {
        StoreBackend::Memory => {
            let config_path = cli.config.ok_or_else(|| {
                color_eyre::eyre::eyre!("--config is required when --store=memory")
            })?;
            tracing::info!(path = %config_path.display(), "loading organization config from file");
            forgeguard_control_plane::app::memory_router(&config_path)?
        }
        StoreBackend::DynamoDb => {
            let table_name = cli
                .dynamodb_table
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    color_eyre::eyre::eyre!("--dynamodb-table is required when --store=dynamodb")
                })?;
            tracing::info!(%table_name, "using DynamoDB store");
            forgeguard_control_plane::app::dynamodb_router(&table_name).await?
        }
    };

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!(listen = %cli.listen, "starting forgeguard-control-plane");
    axum::serve(listener, router).await?;

    Ok(())
}
