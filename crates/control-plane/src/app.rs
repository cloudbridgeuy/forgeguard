//! Public entry points for building the control-plane Axum application.
//!
//! These functions encapsulate store creation, ForgeGuard pipeline setup,
//! and router construction. Used by both the standalone binary (`main.rs`)
//! and the Lambda wrapper (`fg-lambdas`).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use forgeguard_authn_core::IdentityChain;
use forgeguard_authz_core::{PolicyDecision, StaticPolicyEngine};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{FlagConfig, ProjectId};
use forgeguard_http::{
    DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::dynamo_store::DynamoOrgStore;
use crate::store::{self, AnyOrgStore, OrgStore};

/// Build a control-plane `Router` backed by DynamoDB.
///
/// Creates the AWS SDK client, DynamoDB store, ForgeGuard pipeline, and
/// wires all routes. This is the entry point for Lambda deployments.
pub async fn dynamodb_router(table_name: &str) -> color_eyre::Result<Router> {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let client = aws_sdk_dynamodb::Client::new(&sdk_config);
    let s = Arc::new(AnyOrgStore::DynamoDb(DynamoOrgStore::new(
        client,
        table_name.to_string(),
    )));
    let fg = build_forgeguard()?;
    Ok(build_router(s, fg))
}

/// Build a control-plane `Router` backed by an in-memory JSON config file.
///
/// Loads organizations from the JSON file at `config_path`. Used by the
/// standalone binary with `--store=memory`.
pub fn memory_router(config_path: &Path) -> color_eyre::Result<Router> {
    let inner = store::load_config_file(config_path)?;
    let s = Arc::new(AnyOrgStore::Memory(inner));
    let fg = build_forgeguard()?;
    Ok(build_router(s, fg))
}

fn build_forgeguard() -> color_eyre::Result<Arc<ForgeGuard>> {
    let route_matcher = RouteMatcher::new(&[])?;
    let public_routes = vec![
        PublicRoute::new(
            "GET".parse()?,
            "/health".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "POST".parse()?,
            "/api/v1/organizations".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "GET".parse()?,
            "/api/v1/organizations".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "GET".parse()?,
            "/api/v1/organizations/{org_id}".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "PUT".parse()?,
            "/api/v1/organizations/{org_id}".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "DELETE".parse()?,
            "/api/v1/organizations/{org_id}".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "GET".parse()?,
            "/api/v1/organizations/{org_id}/proxy-config".to_string(),
            PublicAuthMode::Anonymous,
        ),
    ];
    let public_route_matcher = PublicRouteMatcher::new(&public_routes)?;
    let pipeline_config = PipelineConfig::new(PipelineConfigParams {
        route_matcher,
        public_route_matcher,
        flag_config: FlagConfig::default(),
        project_id: ProjectId::new("forgeguard-cp")?,
        default_policy: DefaultPolicy::Passthrough,
        debug_mode: false,
        auth_providers: vec![],
    });
    let chain = IdentityChain::new(vec![]);
    let engine: Arc<dyn forgeguard_authz_core::PolicyEngine> =
        Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
    Ok(Arc::new(ForgeGuard::new(pipeline_config, chain, engine)))
}

fn build_router<S: OrgStore + 'static>(store: Arc<S>, fg: Arc<ForgeGuard>) -> Router {
    use crate::handlers;

    Router::new()
        .route("/health", get(handlers::health_handler))
        .route(
            "/api/v1/organizations",
            post(handlers::create_handler::<S>).get(handlers::list_handler::<S>),
        )
        .route(
            "/api/v1/organizations/{org_id}",
            get(handlers::get_handler::<S>)
                .put(handlers::update_handler::<S>)
                .delete(handlers::delete_handler::<S>),
        )
        .route(
            "/api/v1/organizations/{org_id}/proxy-config",
            get(handlers::proxy_config_handler::<S>),
        )
        .with_state(store)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
}
