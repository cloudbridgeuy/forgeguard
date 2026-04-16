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
use forgeguard_authn::{CognitoJwtResolver, Ed25519SignatureResolver, JwtResolverConfig};
use forgeguard_authn_core::resolver::IdentityResolver;
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
use crate::signing_key_store::DynamoSigningKeyStore;
use crate::store::{self, AnyOrgStore, OrgStore};

/// Authentication configuration for the control plane.
///
/// When present, all API routes require a valid JWT. Only `/health` remains
/// anonymous. Constructed via [`AuthConfig::new`], which validates the JWKS
/// URL at the boundary (Parse Don't Validate).
pub struct AuthConfig {
    jwks_url: url::Url,
    issuer: String,
    audience: Option<String>,
}

impl AuthConfig {
    /// Create a new `AuthConfig`, validating the JWKS URL.
    ///
    /// # Errors
    ///
    /// Returns an error if `jwks_url` is not a valid URL.
    pub fn new(
        jwks_url: &str,
        issuer: impl Into<String>,
        audience: Option<String>,
    ) -> color_eyre::Result<Self> {
        let jwks_url: url::Url = jwks_url
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("invalid JWKS URL: {e}"))?;
        Ok(Self {
            jwks_url,
            issuer: issuer.into(),
            audience,
        })
    }
}

/// Build a control-plane `Router` backed by DynamoDB.
///
/// Creates the AWS SDK client, DynamoDB store, ForgeGuard pipeline, and
/// wires all routes. This is the entry point for Lambda deployments.
pub async fn dynamodb_router(
    table_name: &str,
    auth: Option<&AuthConfig>,
) -> color_eyre::Result<Router> {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let client = aws_sdk_dynamodb::Client::new(&sdk_config);
    let s = Arc::new(AnyOrgStore::DynamoDb(DynamoOrgStore::new(
        client.clone(),
        table_name.to_string(),
    )));
    let ed25519_resolver: Option<Arc<dyn IdentityResolver>> = if auth.is_some() {
        let key_store = DynamoSigningKeyStore::new(client, table_name.to_string());
        Some(Arc::new(Ed25519SignatureResolver::new(key_store)))
    } else {
        None
    };
    let fg = build_forgeguard(auth, ed25519_resolver)?;
    Ok(build_router(s, fg))
}

/// Build a control-plane `Router` backed by an in-memory JSON config file.
///
/// Loads organizations from the JSON file at `config_path`. Used by the
/// standalone binary with `--store=memory`.
pub fn memory_router(config_path: &Path, auth: Option<&AuthConfig>) -> color_eyre::Result<Router> {
    let inner = store::load_config_file(config_path)?;
    let s = Arc::new(AnyOrgStore::Memory(inner));
    let fg = build_forgeguard(auth, None)?;
    Ok(build_router(s, fg))
}

/// Build an anonymous public route from method and path strings.
fn anon_route(method: &str, path: &str) -> forgeguard_http::Result<PublicRoute> {
    Ok(PublicRoute::new(
        method.parse()?,
        path.to_string(),
        PublicAuthMode::Anonymous,
    ))
}

/// All API routes that the control plane serves, expressed as (method, path) pairs.
const API_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/v1/organizations"),
    ("GET", "/api/v1/organizations"),
    ("GET", "/api/v1/organizations/{org_id}"),
    ("PUT", "/api/v1/organizations/{org_id}"),
    ("DELETE", "/api/v1/organizations/{org_id}"),
    ("GET", "/api/v1/organizations/{org_id}/proxy-config"),
    ("POST", "/api/v1/organizations/{org_id}/keys"),
    ("GET", "/api/v1/organizations/{org_id}/keys"),
    ("DELETE", "/api/v1/organizations/{org_id}/keys/{key_id}"),
];

fn build_forgeguard(
    auth: Option<&AuthConfig>,
    ed25519_resolver: Option<Arc<dyn IdentityResolver>>,
) -> color_eyre::Result<Arc<ForgeGuard>> {
    let route_matcher = RouteMatcher::new(&[])?;

    let health_route = anon_route("GET", "/health")?;
    let metrics_route = anon_route("GET", "/metrics")?;

    let (public_routes, chain, auth_providers) = match auth {
        Some(auth) => {
            let mut config = JwtResolverConfig::new(auth.jwks_url.clone(), &auth.issuer);
            if let Some(ref aud) = auth.audience {
                config = config.with_audience(aud);
            }
            let cognito_resolver = CognitoJwtResolver::new(config);

            let mut resolvers: Vec<Arc<dyn IdentityResolver>> = vec![Arc::new(cognito_resolver)];
            let mut providers = vec!["jwt".to_string()];

            if let Some(resolver) = ed25519_resolver {
                resolvers.push(resolver);
                providers.push("ed25519".to_string());
            }

            let chain = IdentityChain::new(resolvers);

            (vec![health_route, metrics_route], chain, providers)
        }
        None => {
            let mut routes = vec![health_route, metrics_route];
            for &(method, path) in API_ROUTES {
                routes.push(anon_route(method, path)?);
            }
            let chain = IdentityChain::new(vec![]);

            (routes, chain, vec![])
        }
    };

    let public_route_matcher = PublicRouteMatcher::new(&public_routes)?;
    let pipeline_config = PipelineConfig::new(PipelineConfigParams {
        route_matcher,
        public_route_matcher,
        flag_config: FlagConfig::default(),
        project_id: ProjectId::new("forgeguard-cp")?,
        default_policy: DefaultPolicy::Passthrough,
        debug_mode: false,
        auth_providers,
    });
    let engine: Arc<dyn forgeguard_authz_core::PolicyEngine> =
        Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
    Ok(Arc::new(ForgeGuard::new(pipeline_config, chain, engine)))
}

fn build_router<S: OrgStore + 'static>(store: Arc<S>, fg: Arc<ForgeGuard>) -> Router {
    use crate::handlers;

    Router::new()
        .route("/health", get(handlers::health_handler))
        .route("/metrics", get(handlers::metrics_handler))
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
        .route(
            "/api/v1/organizations/{org_id}/keys",
            post(handlers::generate_key_handler::<S>).get(handlers::list_keys_handler::<S>),
        )
        .route(
            "/api/v1/organizations/{org_id}/keys/{key_id}",
            axum::routing::delete(handlers::revoke_key_handler::<S>),
        )
        .with_state(store)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
}
