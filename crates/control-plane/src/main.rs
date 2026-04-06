#![deny(clippy::unwrap_used, clippy::expect_used)]

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
use forgeguard_authn_core::IdentityChain;
use forgeguard_authz_core::{PolicyDecision, StaticPolicyEngine};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{FlagConfig, ProjectId};
use forgeguard_http::{
    DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::PipelineConfig;
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

    // Build ForgeGuard pipeline config for the control plane's own routes.
    // All routes are public (anonymous) for now — no identity resolvers are
    // configured, so the pipeline can't authenticate anything. Real auth
    // comes with Cognito JWT (#41), at which point protected routes move
    // out of this list.
    let route_matcher = RouteMatcher::new(&[])?;
    let public_routes = vec![
        PublicRoute::new("GET".parse()?, "/health".to_string(), PublicAuthMode::Anonymous),
        PublicRoute::new(
            "GET".parse()?,
            "/api/v1/organizations/{org_id}/proxy-config".to_string(),
            PublicAuthMode::Anonymous,
        ),
    ];
    let public_route_matcher = PublicRouteMatcher::new(&public_routes)?;
    let pipeline_config = PipelineConfig::new(
        route_matcher,
        public_route_matcher,
        FlagConfig::default(),
        ProjectId::new("forgeguard-cp")?,
        DefaultPolicy::Passthrough,
        false,
        vec![],
    );
    let chain = IdentityChain::new(vec![]);
    let engine: Arc<dyn forgeguard_authz_core::PolicyEngine> =
        Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
    let fg = Arc::new(ForgeGuard::new(pipeline_config, chain, engine));

    let app = Router::new()
        .route("/health", get(handlers::health_handler))
        .route(
            "/api/v1/organizations/{org_id}/proxy-config",
            get(handlers::proxy_config_handler),
        )
        .with_state(org_store)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer))
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
