//! ForgeGuard middleware function for Axum.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Response, StatusCode},
    middleware::Next,
};

use forgeguard_proxy_core::{evaluate_pipeline, PipelineOutcome, RequestInput};

use crate::{ForgeGuard, ForgeGuardDecision, ForgeGuardFlags, ForgeGuardIdentity};

/// The `X-Fg-*` names this middleware ever produces on `Forward` — the
/// spoofing guard strips all of these from the inbound request unconditionally
/// (even when there's no identity/record to reinsert), so a client can never
/// smuggle a forged value through on a route where nothing gets injected
/// (e.g. an anonymous/public route). `x-fg-org-id` (membership routing) and
/// the four signing/credential headers (`x-fg-trace-id`, `x-fg-timestamp`,
/// `x-fg-key-id`, `x-fg-signature`) are deliberately excluded — those are
/// either read upstream of this middleware or carry the inbound BYOC
/// signed-request credential itself.
const PROTECTED_FG_HEADERS: [&str; 8] = [
    forgeguard_core::headers::X_FG_USER_ID,
    forgeguard_core::headers::X_FG_TENANT_ID,
    forgeguard_core::headers::X_FG_GROUPS,
    forgeguard_core::headers::X_FG_AUTH_PROVIDER,
    forgeguard_core::headers::X_FG_PRINCIPAL,
    forgeguard_core::headers::X_FG_SCOPE_PATH,
    forgeguard_core::headers::X_FG_ENTITLEMENTS,
    forgeguard_core::headers::X_FG_REVISION,
];

/// Axum middleware that runs the ForgeGuard auth pipeline on every request.
///
/// Translates `axum::http::Request` → [`RequestInput`], calls
/// [`evaluate_pipeline`], and maps the [`PipelineOutcome`] to an Axum response:
///
/// - **Forward** — injects identity + flags + decision record into request extensions, calls `next`
/// - **Reject** — returns an error response with the pipeline's status and body
/// - **Health** — returns the health-check response directly
/// - **Debug** — returns the debug response directly
///
/// # Enforcement mode
///
/// The mode passed to [`evaluate_pipeline`] is resolved from the request's
/// [`crate::ModeOverride`] extension (stamped by [`crate::observe`]), falling
/// back to `fg.default_mode` when absent. The stamp must run BEFORE this
/// middleware to be seen — see the `crate::mode` module docs for the
/// ordering rules and working router shapes; getting it wrong fails safe to
/// `fg.default_mode`.
///
/// # Decision sink
///
/// Every evaluated outcome — `Forward` with an effect (`Allowed`,
/// `WouldAllow`, `WouldDeny`) and policy-denying `Reject` (`Denied`) — is
/// recorded via `fg.sink` ([`crate::DecisionSink`]). Authn/routing rejects
/// (never reached policy evaluation) and forwards where policy never ran
/// (`PolicyEffect::NotEvaluated`, e.g. unmatched or public routes) record
/// nothing.
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
    mut request: axum::http::Request<Body>,
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

    let mode = request
        .extensions()
        .get::<crate::ModeOverride>()
        .map(|m| m.0)
        .unwrap_or(fg.default_mode);

    let outcome = evaluate_pipeline(
        &fg.config,
        &input,
        &fg.identity_chain,
        fg.policy_engine.as_ref(),
        mode,
    )
    .await;

    match outcome {
        PipelineOutcome::Forward {
            identity,
            flags,
            record,
            effect,
            ..
        } => {
            let identity = identity.map(|boxed| *boxed);
            let record = record.map(|boxed| *boxed);

            if let Some(effect) = crate::outcome::effect_from_forward(effect) {
                fg.sink.record(&crate::EnforcementOutcome::new(
                    record.clone(),
                    mode,
                    effect,
                ));
            }

            let trace_id = uuid::Uuid::now_v7().to_string();
            let now = forgeguard_authn_core::signing::Timestamp::from_system_time(
                std::time::SystemTime::now(),
            );
            let fg_headers = crate::headers::build_fg_headers(&crate::headers::FgHeaderParams {
                identity: identity.as_ref(),
                record: record.as_ref(),
                signing: fg.signing.as_ref(),
                trace_id: &trace_id,
                now,
            });

            // Spoofing guard: unconditionally strip every name this middleware
            // could inject, THEN reinsert whatever `fg_headers` actually computed.
            // Stripping first (not just overwriting inside the loop below) matters
            // when `fg_headers` is empty — e.g. an anonymous/public route with no
            // identity — a client-supplied `x-fg-user-id` must not survive to
            // `next.run` unmodified just because there was nothing to overwrite it
            // with.
            for name in PROTECTED_FG_HEADERS {
                request.headers_mut().remove(name);
            }
            for (name, value) in fg_headers {
                let Ok(header_name) = axum::http::HeaderName::try_from(name.as_str()) else {
                    tracing::warn!(header = %name, "skipping invalid X-Fg header name");
                    continue;
                };
                let Ok(header_value) = axum::http::HeaderValue::try_from(value.as_str()) else {
                    tracing::warn!(header = %name, "skipping invalid X-Fg header value");
                    continue;
                };
                request.headers_mut().insert(header_name, header_value);
            }
            request
                .extensions_mut()
                .insert(ForgeGuardIdentity(identity));
            request.extensions_mut().insert(ForgeGuardFlags(flags));
            request.extensions_mut().insert(ForgeGuardDecision(record));
            next.run(request).await
        }
        PipelineOutcome::Reject {
            status,
            body,
            policy_denied,
            record,
        } => {
            if policy_denied {
                fg.sink.record(&crate::EnforcementOutcome::new(
                    record.map(|boxed| *boxed),
                    mode,
                    crate::Effect::Denied,
                ));
            }
            json_response(status, &body)
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
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use forgeguard_authn_core::signing::{
        parse_signature_header, verify, CanonicalPayload, KeyId, SigningKey, Timestamp,
        VerifyingKey,
    };
    use forgeguard_authn_core::static_api_key::ApiKeyEntry;
    use forgeguard_authn_core::{IdentityChain, IdentityResolver, StaticApiKeyResolver};
    use forgeguard_authz_core::{DenyReason, PolicyDecision, StaticPolicyEngine};
    use forgeguard_core::{FlagConfig, ProjectId, QualifiedAction, UserId};
    use forgeguard_http::{
        DefaultPolicy, HttpMethod, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMapping,
        RouteMatcher,
    };
    use forgeguard_proxy_core::{EnforcementMode, PipelineConfig, PipelineConfigParams};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::sink::test_support::TestSink;
    use crate::{Effect, SigningConfig};

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
            membership_resolver: None,
        });
        let chain = IdentityChain::new(vec![]);
        let engine = Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
        ForgeGuard::new(config, chain, engine)
    }

    /// Authenticated fixture: one matched route (`GET /items`), a static
    /// `X-API-Key` resolver mapping `valid-key` -> `alice`, and an allow-all
    /// policy engine. Used by tests that need a real `Forward` outcome with
    /// identity, since `test_forgeguard`'s empty route matcher only reaches
    /// public/health/debug-endpoint outcomes.
    fn test_forgeguard_authenticated() -> ForgeGuard {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/items".to_string(),
            QualifiedAction::parse("todo:list:user").unwrap(),
            None,
            None,
        )];
        let route_matcher = RouteMatcher::new(&routes).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(&[]).unwrap();
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test").unwrap(),
            default_policy: DefaultPolicy::Deny,
            debug_mode: false,
            auth_providers: vec![],
            membership_resolver: None,
        });

        let mut keys = HashMap::new();
        keys.insert(
            "valid-key".to_string(),
            ApiKeyEntry::new(UserId::new("alice").unwrap(), None, vec![]),
        );
        let resolver: Arc<dyn IdentityResolver> = Arc::new(StaticApiKeyResolver::new(keys));
        let chain = IdentityChain::new(vec![resolver]);
        let engine = Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
        ForgeGuard::new(config, chain, engine)
    }

    /// Same fixture as [`test_forgeguard_authenticated`], but the policy
    /// engine denies every request — for Enforce|Observe tests that need a
    /// real `WouldDeny`/`Denied` effect rather than `Allowed`.
    fn test_forgeguard_authenticated_deny() -> ForgeGuard {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/items".to_string(),
            QualifiedAction::parse("todo:list:user").unwrap(),
            None,
            None,
        )];
        let route_matcher = RouteMatcher::new(&routes).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(&[]).unwrap();
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test").unwrap(),
            default_policy: DefaultPolicy::Deny,
            debug_mode: false,
            auth_providers: vec![],
            membership_resolver: None,
        });

        let mut keys = HashMap::new();
        keys.insert(
            "valid-key".to_string(),
            ApiKeyEntry::new(UserId::new("alice").unwrap(), None, vec![]),
        );
        let resolver: Arc<dyn IdentityResolver> = Arc::new(StaticApiKeyResolver::new(keys));
        let chain = IdentityChain::new(vec![resolver]);
        let engine = Arc::new(StaticPolicyEngine::new(PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        }));
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
    async fn public_route_decision_extractor_returns_none() {
        let public_routes = vec![PublicRoute::new(
            HttpMethod::Get,
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let fg = Arc::new(test_forgeguard(false, DefaultPolicy::Deny, &public_routes));
        let app = Router::new()
            .route(
                "/public",
                get(
                    |ForgeGuardDecision(record): ForgeGuardDecision| async move {
                        assert!(record.is_none());
                        "downstream"
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/public")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
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

    #[tokio::test]
    async fn public_route_gets_no_fg_headers_without_identity() {
        let public_routes = vec![PublicRoute::new(
            HttpMethod::Get,
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let fg = Arc::new(test_forgeguard(false, DefaultPolicy::Deny, &public_routes));
        let app = Router::new()
            .route(
                "/public",
                get(|headers: axum::http::HeaderMap| async move {
                    assert!(headers.get("x-fg-user-id").is_none());
                    "downstream"
                }),
            )
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/public")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Regression test for the spoofing guard's empty-injection gap: an
    /// anonymous route has no identity, so `build_fg_headers` returns
    /// nothing — that must NOT mean a client-supplied `x-fg-user-id` (or
    /// any other protected name) passes through untouched.
    #[tokio::test]
    async fn public_route_strips_spoofed_identity_and_decision_headers() {
        let public_routes = vec![PublicRoute::new(
            HttpMethod::Get,
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let fg = Arc::new(test_forgeguard(false, DefaultPolicy::Deny, &public_routes));
        let app = Router::new()
            .route(
                "/public",
                get(|headers: axum::http::HeaderMap| async move {
                    for name in PROTECTED_FG_HEADERS {
                        assert!(headers.get(name).is_none(), "{name} was not stripped");
                    }
                    "downstream"
                }),
            )
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/public")
            .header("x-fg-user-id", "mallory")
            .header("x-fg-scope-path", "root/eng")
            .header("x-fg-entitlements", "delete")
            .header("x-fg-revision", "999")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn forward_overwrites_spoofed_identity_header() {
        let fg = Arc::new(test_forgeguard_authenticated());
        let app = Router::new()
            .route(
                "/items",
                get(|headers: axum::http::HeaderMap| async move {
                    assert_eq!(headers.get("x-fg-user-id").unwrap(), "alice");
                    "downstream"
                }),
            )
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .header("x-fg-user-id", "mallory")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn signed_headers_verify_end_to_end() {
        let key_id = KeyId::try_from("test-key".to_string()).unwrap();
        let signing = SigningConfig::new(SigningKey::from_bytes(&[42u8; 32]), key_id);
        let verifying_key = VerifyingKey::from(signing.key());

        let fg = Arc::new(test_forgeguard_authenticated().with_signing(signing));
        let app = Router::new()
            .route(
                "/items",
                get(move |headers: axum::http::HeaderMap| {
                    let verifying_key = verifying_key.clone();
                    async move {
                        let trace_id = headers
                            .get("x-fg-trace-id")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string();
                        let timestamp = headers
                            .get("x-fg-timestamp")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .parse::<u64>()
                            .unwrap();
                        let signature = parse_signature_header(
                            headers.get("x-fg-signature").unwrap().to_str().unwrap(),
                        )
                        .unwrap();

                        let signature_headers = [
                            "x-fg-trace-id",
                            "x-fg-timestamp",
                            "x-fg-key-id",
                            "x-fg-signature",
                        ];
                        let covered: Vec<(String, String)> = headers
                            .iter()
                            .filter(|(k, _)| {
                                k.as_str().starts_with("x-fg-")
                                    && !signature_headers.contains(&k.as_str())
                            })
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
                            .collect();

                        let payload = CanonicalPayload::new(
                            &trace_id,
                            Timestamp::from_millis(timestamp),
                            &covered,
                        );
                        verify(&verifying_key, &payload, &signature)
                            .expect("signature must verify against injected headers");
                        "downstream"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn observe_route_forwards_denied_request_and_records_would_deny() {
        let sink = Arc::new(TestSink::default());
        let fg = Arc::new(test_forgeguard_authenticated_deny().with_decision_sink(sink.clone()));
        let app = Router::new()
            .route("/items", get(|| async { "downstream" }))
            .route_layer(axum::middleware::from_fn_with_state(
                fg.clone(),
                forgeguard_layer,
            ))
            .route_layer(fg.observe());

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*sink.0.lock().unwrap(), vec![Effect::WouldDeny]);
    }

    #[tokio::test]
    async fn enforce_route_rejects_denied_request_and_records_denied() {
        let sink = Arc::new(TestSink::default());
        let fg = Arc::new(test_forgeguard_authenticated_deny().with_decision_sink(sink.clone()));
        let app = Router::new()
            .route("/items", get(|| async { "downstream" }))
            .route_layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(*sink.0.lock().unwrap(), vec![Effect::Denied]);
    }

    #[tokio::test]
    async fn default_mode_observe_applies_without_stamp() {
        let sink = Arc::new(TestSink::default());
        let fg = Arc::new(
            test_forgeguard_authenticated_deny()
                .with_default_mode(EnforcementMode::Observe)
                .with_decision_sink(sink.clone()),
        );
        let app = Router::new()
            .route("/items", get(|| async { "downstream" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*sink.0.lock().unwrap(), vec![Effect::WouldDeny]);
    }

    /// Pins the ordering trap documented in [`crate::mode`]: the stamp is
    /// added via `route_layer` UNDER a router-level `forgeguard_layer`
    /// `.layer(...)`, so `forgeguard_layer` runs first and never sees it.
    /// This must fail safe to the guard's default mode (`Enforce`), not
    /// silently apply observe semantics.
    #[tokio::test]
    async fn misordered_observe_stamp_fails_safe_to_enforce() {
        let sink = Arc::new(TestSink::default());
        let fg = Arc::new(test_forgeguard_authenticated_deny().with_decision_sink(sink.clone()));
        let app = Router::new()
            .route("/items", get(|| async { "downstream" }))
            .route_layer(fg.observe())
            .layer(axum::middleware::from_fn_with_state(
                fg.clone(),
                forgeguard_layer,
            ));

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(*sink.0.lock().unwrap(), vec![Effect::Denied]);
    }

    #[tokio::test]
    async fn allowed_enforce_records_allowed() {
        let sink = Arc::new(TestSink::default());
        let fg = Arc::new(test_forgeguard_authenticated().with_decision_sink(sink.clone()));
        let app = Router::new()
            .route("/items", get(|| async { "downstream" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/items")
            .header("x-api-key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*sink.0.lock().unwrap(), vec![Effect::Allowed]);
    }

    #[tokio::test]
    async fn public_route_records_nothing() {
        let sink = Arc::new(TestSink::default());
        let public_routes = vec![PublicRoute::new(
            HttpMethod::Get,
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let fg = Arc::new(
            test_forgeguard(false, DefaultPolicy::Deny, &public_routes)
                .with_decision_sink(sink.clone()),
        );
        let app = Router::new()
            .route("/public", get(|| async { "downstream" }))
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));

        let request = Request::builder()
            .uri("/public")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(sink.0.lock().unwrap().is_empty());
    }
}
