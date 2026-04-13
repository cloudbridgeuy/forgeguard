//! ForgeGuard middleware function for Axum.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Response, StatusCode},
    middleware::Next,
};

use forgeguard_proxy_core::{evaluate_pipeline, PipelineOutcome, RequestInput};

use crate::{ForgeGuard, ForgeGuardFlags, ForgeGuardIdentity};

/// Axum middleware that runs the ForgeGuard auth pipeline on every request.
///
/// Translates `axum::http::Request` → [`RequestInput`], calls
/// [`evaluate_pipeline`], and maps the [`PipelineOutcome`] to an Axum response:
///
/// - **Forward** — injects identity + flags into request extensions, calls `next`
/// - **Reject** — returns an error response with the pipeline's status and body
/// - **Health** — returns the health-check response directly
/// - **Debug** — returns the debug response directly
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use forgeguard_axum::{ForgeGuard, forgeguard_layer};
/// # use forgeguard_authn_core::IdentityChain;
/// # use forgeguard_authz_core::PolicyEngine;
/// # use forgeguard_proxy_core::PipelineConfig;
/// # fn example(
/// #     config: PipelineConfig,
/// #     chain: IdentityChain,
/// #     engine: Arc<dyn PolicyEngine>,
/// # ) {
/// use axum::{Router, routing::get, middleware};
///
/// let fg = Arc::new(ForgeGuard::new(config, chain, engine));
/// let app: Router = Router::new()
///     .route("/api/items", get(handler))
///     .layer(middleware::from_fn_with_state(fg, forgeguard_layer));
/// # }
/// # async fn handler() -> &'static str { "ok" }
/// ```
pub async fn forgeguard_layer(
    State(fg): State<Arc<ForgeGuard>>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = request.method().as_str();
    let path = request.uri().path();
    let query_string = request.uri().query().map(ToString::to_string);

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    let client_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());

    let input = match RequestInput::new(method, path, headers, client_ip) {
        Ok(input) => match query_string {
            Some(qs) => input.with_query_string(qs),
            None => input,
        },
        Err(e) => {
            tracing::warn!(error = %e, "failed to build RequestInput from Axum request");
            return json_response(StatusCode::BAD_REQUEST, r#"{"error":"invalid request"}"#);
        }
    };

    let outcome = evaluate_pipeline(
        &fg.config,
        &input,
        &fg.identity_chain,
        fg.policy_engine.as_ref(),
    )
    .await;

    match outcome {
        PipelineOutcome::Forward {
            identity,
            flags,
            matched_route: _,
        } => {
            let mut request = request;
            request
                .extensions_mut()
                .insert(ForgeGuardIdentity(identity));
            request.extensions_mut().insert(ForgeGuardFlags(flags));
            next.run(request).await
        }
        PipelineOutcome::Reject { status, body } => {
            let status_code =
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            json_response(status_code, &body)
        }
        PipelineOutcome::Health(body) => json_response(StatusCode::OK, &body),
        PipelineOutcome::Debug(body) => json_response(StatusCode::OK, &body),
    }
}

fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(r#"{"error":"internal error"}"#))
                .unwrap_or_default()
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use forgeguard_authn_core::IdentityChain;
    use forgeguard_authz_core::{PolicyDecision, StaticPolicyEngine};
    use forgeguard_core::{FlagConfig, ProjectId};
    use forgeguard_http::{
        DefaultPolicy, HttpMethod, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
    };
    use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn test_forgeguard(
        debug_mode: bool,
        default_policy: DefaultPolicy,
        public_routes: &[PublicRoute],
    ) -> ForgeGuard {
        let route_matcher = RouteMatcher::new(&[]).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(public_routes).unwrap();
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test").unwrap(),
            default_policy,
            debug_mode,
            auth_providers: vec![],
        });
        let chain = IdentityChain::new(vec![]);
        let engine = Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
        ForgeGuard::new(config, chain, engine)
    }

    #[tokio::test]
    async fn health_check_returns_200() {
        let fg = Arc::new(test_forgeguard(false, DefaultPolicy::Deny, &[]));
        let app = Router::new()
            .route("/fallback", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/.well-known/forgeguard/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("status"), "expected health body, got: {text}");
    }

    #[tokio::test]
    async fn public_anonymous_route_forwards() {
        let public_routes = vec![PublicRoute::new(
            HttpMethod::Get,
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let fg = Arc::new(test_forgeguard(false, DefaultPolicy::Deny, &public_routes));
        let app = Router::new()
            .route("/public", get(|| async { "downstream" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/public")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert_eq!(text, "downstream");
    }

    #[tokio::test]
    async fn unmatched_route_with_deny_default_rejects() {
        let fg = Arc::new(test_forgeguard(false, DefaultPolicy::Deny, &[]));
        let app = Router::new()
            .route("/unknown", get(|| async { "should not reach" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        // No Authorization header, no matching route, no public route —
        // the pipeline requires a credential first and rejects with 401.
        let request = Request::builder()
            .uri("/unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn debug_endpoint_returns_200_when_enabled() {
        let fg = Arc::new(test_forgeguard(true, DefaultPolicy::Deny, &[]));
        let app = Router::new()
            .route("/fallback", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/.well-known/forgeguard/flags?user_id=alice&tenant_id=acme")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        // Debug endpoint returns JSON with flag information
        let _: serde_json::Value =
            serde_json::from_str(&text).expect("debug endpoint should return valid JSON");
    }
}
