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
use forgeguard_authn_core::{IdentityChain, IdentityResolver};
use forgeguard_authz::cache::AuthzCache;
use forgeguard_authz::{TieredCache, VpEngineConfig, VpPolicyEngine};
use forgeguard_authz_core::{PolicyDecision, StaticPolicyEngine};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{FlagConfig, ProjectId, QualifiedAction};
use forgeguard_http::{
    DefaultPolicy, HttpMethod, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMapping,
    RouteMatcher,
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
    policy_store_id: String,
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
        policy_store_id: impl Into<String>,
    ) -> color_eyre::Result<Self> {
        let jwks_url: url::Url = jwks_url
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("invalid JWKS URL: {e}"))?;
        Ok(Self {
            jwks_url,
            issuer: issuer.into(),
            audience,
            policy_store_id: policy_store_id.into(),
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
    let dynamo_client = aws_sdk_dynamodb::Client::new(&sdk_config);
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&sdk_config);
    let s = Arc::new(AnyOrgStore::DynamoDb(DynamoOrgStore::new(
        dynamo_client.clone(),
        table_name.to_string(),
    )));
    let ed25519_resolver: Option<Arc<dyn IdentityResolver>> = if auth.is_some() {
        let key_store = DynamoSigningKeyStore::new(dynamo_client, table_name.to_string());
        Some(Arc::new(Ed25519SignatureResolver::new(key_store)))
    } else {
        None
    };
    let fg = build_forgeguard(auth, ed25519_resolver, Some(vp_client))?;
    Ok(build_router(s, fg))
}

/// Build a control-plane `Router` backed by an in-memory JSON config file.
///
/// Loads organizations from the JSON file at `config_path`. Used by the
/// standalone binary with `--store=memory`.
pub fn memory_router(config_path: &Path, auth: Option<&AuthConfig>) -> color_eyre::Result<Router> {
    let inner = store::load_config_file(config_path)?;
    let s = Arc::new(AnyOrgStore::Memory(inner));
    // Ed25519 resolver requires DynamoDB for key lookup; memory mode has no DynamoDB client.
    // VP engine is also unavailable in memory mode — StaticPolicyEngine(Allow) is used instead.
    let fg = build_forgeguard(auth, None, None)?;
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

/// Route-to-action mappings for all control-plane API routes.
///
/// Actions follow the `namespace:entity:action` convention with the `cp`
/// (control-plane) namespace. These mirror the Cedar actions declared in
/// `forgeguard.toml`.
fn cp_route_actions() -> forgeguard_http::Result<Vec<RouteMapping>> {
    // (method, path, action, resource_param)
    let entries: &[(&str, &str, &str, Option<&str>)] = &[
        (
            "POST",
            "/api/v1/organizations",
            "cp:organization:create",
            None,
        ),
        ("GET", "/api/v1/organizations", "cp:organization:read", None),
        (
            "GET",
            "/api/v1/organizations/{org_id}",
            "cp:organization:read",
            Some("org_id"),
        ),
        (
            "PUT",
            "/api/v1/organizations/{org_id}",
            "cp:organization:update",
            Some("org_id"),
        ),
        (
            "DELETE",
            "/api/v1/organizations/{org_id}",
            "cp:organization:delete",
            Some("org_id"),
        ),
        (
            "GET",
            "/api/v1/organizations/{org_id}/proxy-config",
            "cp:proxy-config:read",
            Some("org_id"),
        ),
        (
            "POST",
            "/api/v1/organizations/{org_id}/keys",
            "cp:key:generate",
            Some("org_id"),
        ),
        (
            "GET",
            "/api/v1/organizations/{org_id}/keys",
            "cp:key:read",
            Some("org_id"),
        ),
        (
            "DELETE",
            "/api/v1/organizations/{org_id}/keys/{key_id}",
            "cp:key:revoke",
            Some("org_id"),
        ),
    ];

    entries
        .iter()
        .map(|&(method, path, action, resource_param)| {
            let method: HttpMethod = method
                .parse()
                .map_err(|e| forgeguard_http::Error::Config(format!("invalid method: {e}")))?;
            let action = QualifiedAction::parse(action)
                .map_err(|e| forgeguard_http::Error::Config(format!("invalid action: {e}")))?;
            let mapping = RouteMapping::new(
                method,
                path.to_string(),
                action,
                resource_param.map(String::from),
                None,
            )
            .with_resource_entity_type("Organization");
            if resource_param.is_none() {
                mapping.with_default_resource_id("collection")
            } else {
                Ok(mapping)
            }
        })
        .collect()
}

fn build_forgeguard(
    auth: Option<&AuthConfig>,
    ed25519_resolver: Option<Arc<dyn IdentityResolver>>,
    vp_client: Option<aws_sdk_verifiedpermissions::Client>,
) -> color_eyre::Result<Arc<ForgeGuard>> {
    let health_route = anon_route("GET", "/health")?;
    let metrics_route = anon_route("GET", "/metrics")?;
    let project_id = ProjectId::new("forgeguard")?;

    let (route_matcher, public_routes, chain, auth_providers, default_policy, engine) = match auth {
        Some(auth) => {
            // Auth-enabled branch — JWT + optional Ed25519, populated route matcher, Deny default
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
            let mappings = cp_route_actions()?;
            let route_matcher = RouteMatcher::new(&mappings)?;

            // Build the policy engine: VP when a client is available, static allow otherwise.
            let engine: Arc<dyn forgeguard_authz_core::PolicyEngine> = match vp_client {
                Some(client) => {
                    let vp_config = VpEngineConfig::new(&auth.policy_store_id);
                    let l1 = AuthzCache::new(vp_config.cache_ttl(), vp_config.cache_max_entries());
                    let cache = TieredCache::new(l1, None, vp_config.cache_ttl());
                    Arc::new(VpPolicyEngine::new(
                        client,
                        &vp_config,
                        project_id.clone(),
                        cache,
                    ))
                }
                None => Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow)),
            };

            (
                route_matcher,
                vec![health_route, metrics_route],
                chain,
                providers,
                DefaultPolicy::Deny,
                engine,
            )
        }
        None => {
            // No-auth (dev) branch — all routes public, empty route matcher, Passthrough default
            let mut routes = vec![health_route, metrics_route];
            for &(method, path) in API_ROUTES {
                routes.push(anon_route(method, path)?);
            }
            let chain = IdentityChain::new(vec![]);
            let route_matcher = RouteMatcher::new(&[])?;
            let engine: Arc<dyn forgeguard_authz_core::PolicyEngine> =
                Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));

            (
                route_matcher,
                routes,
                chain,
                vec![],
                DefaultPolicy::Passthrough,
                engine,
            )
        }
    };

    let public_route_matcher = PublicRouteMatcher::new(&public_routes)?;
    let pipeline_config = PipelineConfig::new(PipelineConfigParams {
        route_matcher,
        public_route_matcher,
        flag_config: FlagConfig::default(),
        project_id,
        default_policy,
        debug_mode: false,
        auth_providers,
        membership_resolver: None,
    });
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cp_route_actions_all_parse() {
        let mappings = cp_route_actions().expect("cp_route_actions must not fail");
        assert_eq!(
            mappings.len(),
            9,
            "expected 9 route mappings, got {}",
            mappings.len()
        );
        // Confirm each action string round-trips correctly through QualifiedAction
        let expected_actions = [
            "cp:organization:create",
            "cp:organization:read",
            "cp:organization:read",
            "cp:organization:update",
            "cp:organization:delete",
            "cp:proxy-config:read",
            "cp:key:generate",
            "cp:key:read",
            "cp:key:revoke",
        ];
        for (mapping, expected) in mappings.iter().zip(expected_actions.iter()) {
            assert_eq!(
                mapping.action().to_string(),
                *expected,
                "action mismatch for route {}",
                mapping.path_pattern()
            );
        }
    }

    #[test]
    fn cp_route_matcher_matches_all_api_routes() {
        let mappings = cp_route_actions().unwrap();
        let matcher = RouteMatcher::new(&mappings).unwrap();

        // (method, path, expected_action)
        let cases: &[(&str, &str, &str)] = &[
            ("POST", "/api/v1/organizations", "cp:organization:create"),
            ("GET", "/api/v1/organizations", "cp:organization:read"),
            (
                "GET",
                "/api/v1/organizations/org-123",
                "cp:organization:read",
            ),
            (
                "PUT",
                "/api/v1/organizations/org-123",
                "cp:organization:update",
            ),
            (
                "DELETE",
                "/api/v1/organizations/org-123",
                "cp:organization:delete",
            ),
            (
                "GET",
                "/api/v1/organizations/org-123/proxy-config",
                "cp:proxy-config:read",
            ),
            (
                "POST",
                "/api/v1/organizations/org-123/keys",
                "cp:key:generate",
            ),
            ("GET", "/api/v1/organizations/org-123/keys", "cp:key:read"),
            (
                "DELETE",
                "/api/v1/organizations/org-123/keys/key-456",
                "cp:key:revoke",
            ),
        ];

        for &(method, path, expected_action) in cases {
            let matched = matcher
                .match_request(method, path)
                .unwrap_or_else(|| panic!("{method} {path} should match a route"));
            assert_eq!(
                matched.action().to_string(),
                expected_action,
                "{method} {path}: expected action {expected_action}, got {}",
                matched.action()
            );
        }
    }
}
