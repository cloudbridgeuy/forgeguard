#![deny(clippy::unwrap_used, clippy::expect_used)]

mod cli;

use clap::Parser;
use forgeguard_control_plane::app::AuthConfig;
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
    let auth = match (cli.jwks_url, cli.issuer) {
        (Some(jwks_url), Some(issuer)) => {
            tracing::info!("JWT authentication enabled");
            Some(AuthConfig::new(&jwks_url, issuer, cli.audience)?)
        }
        (Some(_), None) => {
            return Err(color_eyre::eyre::eyre!(
                "--issuer is required when --jwks-url is set"
            ));
        }
        (None, Some(_)) => {
            tracing::warn!("--issuer provided without --jwks-url, ignoring auth config");
            None
        }
        (None, None) => {
            tracing::warn!("no --jwks-url provided, running without auth");
            None
        }
    };

    let router = match cli.store {
        StoreBackend::Memory => {
            let config_path = cli.config.ok_or_else(|| {
                color_eyre::eyre::eyre!("--config is required when --store=memory")
            })?;
            tracing::info!(path = %config_path.display(), "loading organization config from file");
            forgeguard_control_plane::app::memory_router(&config_path, auth.as_ref())?
        }
        StoreBackend::DynamoDb => {
            let table_name = cli
                .dynamodb_table
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    color_eyre::eyre::eyre!("--dynamodb-table is required when --store=dynamodb")
                })?;
            tracing::info!(%table_name, "using DynamoDB store");
            forgeguard_control_plane::app::dynamodb_router(&table_name, auth.as_ref()).await?
        }
    };

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!(listen = %cli.listen, "starting forgeguard-control-plane");
    axum::serve(listener, router).await?;

    Ok(())
}
