#![deny(clippy::unwrap_used, clippy::expect_used)]

mod auth;
mod cli;
mod config;
mod error;
mod handlers;
mod store;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(e) = run(cli).await {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> color_eyre::Result<()> {
    color_eyre::install()?;

    let org_store: Arc<dyn store::OrgStore> = Arc::new(store::load_config_file(&cli.config)?);
    tracing::info!(path = %cli.config.display(), "loaded organization config");

    let app = Router::new()
        .route("/health", get(handlers::health_handler))
        .route(
            "/api/v1/organizations/{org_id}/proxy-config",
            get(handlers::proxy_config_handler),
        )
        .with_state(org_store)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ));

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!(listen = %cli.listen, "starting forgeguard-control-plane");
    axum::serve(listener, app).await?;

    Ok(())
}
