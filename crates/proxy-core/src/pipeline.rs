//! Auth pipeline evaluation — the pure decision function.
//!
//! [`evaluate_pipeline`] encodes every phase of the ForgeGuard request filter
//! as a pure async function with no framework dependencies. Protocol adapters
//! (Pingora, Axum, Lambda) call this and pattern-match on [`PipelineOutcome`].

use forgeguard_authn_core::IdentityChain;
use forgeguard_authz_core::PolicyEngine;
use forgeguard_core::evaluate_flags;
use forgeguard_http::{
    build_query, evaluate_debug, extract_credential, DefaultPolicy, FlagDebugQuery, PublicMatch,
};

use crate::{PipelineConfig, PipelineOutcome, RequestInput};

/// Health check path served before any auth logic.
const HEALTH_PATH: &str = "/.well-known/forgeguard/health";

/// Debug endpoint for flag evaluation (requires debug mode).
const FLAGS_DEBUG_PATH: &str = "/.well-known/forgeguard/flags";

/// Run the full auth pipeline on a single request.
///
/// This is the pure decision function — it performs no I/O itself but awaits
/// the `identity_chain` and `policy_engine` trait methods (which may perform
/// I/O in production but are pure in tests).
///
/// The phases exactly mirror `ForgeGuardProxy::request_filter` in the Pingora
/// adapter, minus CORS handling and metrics (which remain in the adapter).
///
/// # Phases
///
/// 1. **Health check** — `/.well-known/forgeguard/health`
/// 2. **Debug endpoint** — `/.well-known/forgeguard/flags` (debug mode only)
/// 3. **Public route check** — determines auth requirement
/// 4. **Credential extraction** — from headers
/// 5. **Identity resolution** — via the identity chain
/// 6. **Feature flags** — evaluated for authenticated requests
/// 7. **Route matching** — `(method, path)` to action/resource
/// 8. **Feature gate** — reject if gated route's flag is disabled
/// 9. **Policy evaluation** — authz decision for authenticated + matched routes
/// 10. **Default policy** — fallback for unmatched, non-public requests
pub async fn evaluate_pipeline(
    config: &PipelineConfig,
    input: &RequestInput,
    identity_chain: &IdentityChain,
    policy_engine: &dyn PolicyEngine,
) -> PipelineOutcome {
    let method = input.method().to_string();
    let path = input.path();

    // Phase 1: Health check
    if path == HEALTH_PATH {
        return health_response(config, policy_engine);
    }

    // Phase 2: Debug endpoint (requires debug mode)
    if config.debug_mode() && path == FLAGS_DEBUG_PATH {
        return debug_response(config, input);
    }

    // Phase 3: Public route check
    let public_match = config.public_route_matcher().check(&method, path);
    let require_credential = matches!(public_match, PublicMatch::NotPublic);
    let try_credential = matches!(
        public_match,
        PublicMatch::NotPublic | PublicMatch::Opportunistic
    );

    // Phase 4–5: Credential extraction and identity resolution
    let mut identity = None;

    if try_credential {
        let credential = extract_credential(input.headers());

        match credential {
            Some(cred) => match identity_chain.resolve(&cred).await {
                Ok(id) => {
                    identity = Some(id);
                }
                Err(_) if require_credential => {
                    return reject_json(401, "Unauthorized");
                }
                Err(_) => {
                    // Opportunistic: resolution failed, continue without identity
                }
            },
            None if require_credential => {
                return reject_json(401, "Unauthorized");
            }
            None => {
                // Opportunistic or Anonymous: no credential, continue
            }
        }
    }

    // Phase 6: Feature flags (pure, no I/O)
    let flags = identity.as_ref().map(|id| {
        evaluate_flags(
            config.flag_config(),
            id.tenant_id(),
            id.user_id(),
            id.groups(),
        )
    });

    // Phase 7: Route matching
    let matched = config.route_matcher().match_request(&method, path);

    if let Some(matched_route) = matched {
        // Phase 8: Feature gate check
        if let Some(gate) = matched_route.feature_gate() {
            let gate_enabled = flags.as_ref().is_some_and(|f| f.enabled(&gate.to_string()));
            if !gate_enabled {
                return reject_json(404, "Not Found");
            }
        }

        // Phase 9: Policy evaluation — only for authenticated requests.
        // Fail-safe: both explicit deny and evaluation errors result in rejection.
        if let Some(id) = &identity {
            let query = build_query(id, &matched_route, config.project_id(), input.client_ip());
            let allowed = policy_engine
                .evaluate(&query)
                .await
                .is_ok_and(|d| !d.is_denied());

            if !allowed {
                return reject_forbidden_with_action(&matched_route.action().to_string());
            }
        }

        PipelineOutcome::Forward {
            identity,
            flags,
            matched_route: Some(Box::new(matched_route)),
        }
    } else if public_match.is_public() {
        // Public route with no [[routes]] entry — passthrough to upstream
        PipelineOutcome::Forward {
            identity,
            flags,
            matched_route: None,
        }
    } else {
        // Phase 10: No route matched and not a public route
        match config.default_policy() {
            DefaultPolicy::Deny => {
                let body = serde_json::json!({"error": "Forbidden", "reason": "no matching route"});
                PipelineOutcome::Reject {
                    status: 403,
                    body: body.to_string(),
                }
            }
            DefaultPolicy::Passthrough => PipelineOutcome::Forward {
                identity,
                flags,
                matched_route: None,
            },
        }
    }
}

/// Build the health check response body.
fn health_response(config: &PipelineConfig, policy_engine: &dyn PolicyEngine) -> PipelineOutcome {
    let mut body = serde_json::json!({
        "status": "ok",
        "providers": config.auth_providers(),
        "flags": config.flag_config().flags.len(),
    });
    if let Some(stats) = policy_engine.cache_stats() {
        body["cache_hits"] = stats.hits().into();
        body["cache_misses"] = stats.misses().into();
        if let Some(l2_hits) = stats.l2_hits() {
            body["l2_cache_hits"] = l2_hits.into();
        }
        if let Some(l2_misses) = stats.l2_misses() {
            body["l2_cache_misses"] = l2_misses.into();
        }
        if let Some(l2_errors) = stats.l2_errors() {
            body["l2_cache_errors"] = l2_errors.into();
        }
    }
    PipelineOutcome::Health(body.to_string())
}

/// Build the debug endpoint response.
fn debug_response(config: &PipelineConfig, input: &RequestInput) -> PipelineOutcome {
    let query_str = input.query_string().unwrap_or("");

    let query = match FlagDebugQuery::parse(query_str) {
        Ok(q) => q,
        Err(e) => return reject_json(400, &format!("{e}")),
    };

    let result = evaluate_debug(config.flag_config(), &query);

    match serde_json::to_string(&result) {
        Ok(json) => PipelineOutcome::Debug(json),
        Err(_) => reject_json(500, "Internal Server Error"),
    }
}

/// Build a JSON `{"error": <msg>}` reject outcome.
///
/// This intentionally constructs `PipelineOutcome::Reject` directly, bypassing
/// the validated [`PipelineOutcome::reject()`] constructor. All call sites use
/// hardcoded HTTP status codes (400, 401, 403, 404, 500) that are known-valid,
/// so runtime validation is unnecessary. External callers should use
/// [`PipelineOutcome::reject()`] which validates the status range.
fn reject_json(status: u16, error: &str) -> PipelineOutcome {
    let body = serde_json::json!({"error": error});
    PipelineOutcome::Reject {
        status,
        body: body.to_string(),
    }
}

/// Convenience: build a Forbidden reject with action context.
fn reject_forbidden_with_action(action: &str) -> PipelineOutcome {
    let body = serde_json::json!({
        "error": "Forbidden",
        "action": action,
    });
    PipelineOutcome::Reject {
        status: 403,
        body: body.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use forgeguard_authn_core::{
        Credential, Identity, IdentityBuilder, IdentityChain, IdentityResolver,
    };
    use forgeguard_authz_core::{
        CacheStats, DenyReason, PolicyDecision, PolicyEngine, PolicyQuery, StaticPolicyEngine,
    };
    use forgeguard_core::{
        FlagConfig, FlagDefinition, FlagName, FlagType, FlagValue, GroupName, ProjectId,
        QualifiedAction, TenantId, UserId,
    };
    use forgeguard_http::{
        DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMapping, RouteMatcher,
    };

    use super::*;

    // -----------------------------------------------------------------------
    // Mock identity resolver
    // -----------------------------------------------------------------------

    /// A configurable mock identity resolver for tests.
    ///
    /// Can be set to always succeed with a given identity, always fail,
    /// or resolve only specific credential types.
    struct MockIdentityResolver {
        identity: Option<Identity>,
    }

    impl MockIdentityResolver {
        /// Create a resolver that always succeeds with the given identity.
        fn succeeding(identity: Identity) -> Self {
            Self {
                identity: Some(identity),
            }
        }

        /// Create a resolver that always fails.
        fn failing() -> Self {
            Self { identity: None }
        }
    }

    impl IdentityResolver for MockIdentityResolver {
        fn name(&self) -> &'static str {
            "mock-resolver"
        }

        fn can_resolve(&self, _credential: &Credential) -> bool {
            true
        }

        fn resolve(
            &self,
            _credential: &Credential,
        ) -> Pin<Box<dyn Future<Output = forgeguard_authn_core::Result<Identity>> + Send + '_>>
        {
            if let Some(ref identity) = self.identity {
                let identity = identity.clone();
                Box::pin(std::future::ready(Ok(identity)))
            } else {
                Box::pin(std::future::ready(Err(
                    forgeguard_authn_core::Error::InvalidCredential("mock failure".to_string()),
                )))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mock policy engine that returns errors
    // -----------------------------------------------------------------------

    struct ErrorPolicyEngine;

    impl PolicyEngine for ErrorPolicyEngine {
        fn evaluate(
            &self,
            _query: &PolicyQuery,
        ) -> Pin<Box<dyn Future<Output = forgeguard_authz_core::Result<PolicyDecision>> + Send + '_>>
        {
            Box::pin(std::future::ready(Err(
                forgeguard_authz_core::Error::EvaluationFailed("mock error".to_string()),
            )))
        }
    }

    /// A policy engine that reports cache stats for testing the health endpoint.
    struct CachingPolicyEngine {
        inner: StaticPolicyEngine,
        stats: CacheStats,
    }

    impl PolicyEngine for CachingPolicyEngine {
        fn evaluate(
            &self,
            query: &PolicyQuery,
        ) -> Pin<Box<dyn Future<Output = forgeguard_authz_core::Result<PolicyDecision>> + Send + '_>>
        {
            self.inner.evaluate(query)
        }

        fn cache_stats(&self) -> Option<CacheStats> {
            Some(self.stats)
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_identity() -> Identity {
        IdentityBuilder::new(UserId::new("alice").unwrap())
            .tenant(TenantId::new("acme").unwrap())
            .groups(vec![GroupName::new("users").unwrap()])
            .resolver("mock-resolver")
            .build()
    }

    fn make_chain_succeeding() -> IdentityChain {
        IdentityChain::new(vec![Arc::new(MockIdentityResolver::succeeding(
            make_identity(),
        ))])
    }

    fn make_chain_failing() -> IdentityChain {
        IdentityChain::new(vec![Arc::new(MockIdentityResolver::failing())])
    }

    fn make_config(
        routes: &[RouteMapping],
        public_routes: &[PublicRoute],
        default_policy: DefaultPolicy,
        debug_mode: bool,
    ) -> PipelineConfig {
        let route_matcher = RouteMatcher::new(routes).unwrap();
        let public_matcher = PublicRouteMatcher::new(public_routes).unwrap();
        PipelineConfig::new(
            route_matcher,
            public_matcher,
            FlagConfig::default(),
            ProjectId::new("test-project").unwrap(),
            default_policy,
            debug_mode,
            vec!["jwt".to_string()],
        )
    }

    fn make_config_with_flags(
        routes: &[RouteMapping],
        public_routes: &[PublicRoute],
        default_policy: DefaultPolicy,
        flag_config: FlagConfig,
    ) -> PipelineConfig {
        let route_matcher = RouteMatcher::new(routes).unwrap();
        let public_matcher = PublicRouteMatcher::new(public_routes).unwrap();
        PipelineConfig::new(
            route_matcher,
            public_matcher,
            flag_config,
            ProjectId::new("test-project").unwrap(),
            default_policy,
            false,
            vec!["jwt".to_string()],
        )
    }

    fn allow_engine() -> StaticPolicyEngine {
        StaticPolicyEngine::new(PolicyDecision::Allow)
    }

    fn deny_engine() -> StaticPolicyEngine {
        StaticPolicyEngine::new(PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        })
    }

    fn input(method: &str, path: &str) -> RequestInput {
        RequestInput::new(method, path, vec![], None).unwrap()
    }

    fn input_with_bearer(method: &str, path: &str, token: &str) -> RequestInput {
        let headers = vec![("authorization".to_string(), format!("Bearer {token}"))];
        RequestInput::new(method, path, headers, None).unwrap()
    }

    // -----------------------------------------------------------------------
    // Test 1: Health check path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn health_check_returns_health_outcome() {
        let config = make_config(&[], &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input("GET", "/.well-known/forgeguard/health");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Health(body) => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["status"], "ok");
                assert_eq!(v["providers"][0], "jwt");
                assert_eq!(v["flags"], 0);
            }
            other => panic!("expected Health, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: Health check with cache stats
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn health_check_includes_cache_stats() {
        let config = make_config(&[], &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let stats = CacheStats::new(42, 7).with_l2(10, 3, 1);
        let engine = CachingPolicyEngine {
            inner: allow_engine(),
            stats,
        };
        let req = input("GET", "/.well-known/forgeguard/health");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Health(body) => {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["cache_hits"], 42);
                assert_eq!(v["cache_misses"], 7);
                assert_eq!(v["l2_cache_hits"], 10);
                assert_eq!(v["l2_cache_misses"], 3);
                assert_eq!(v["l2_cache_errors"], 1);
            }
            other => panic!("expected Health, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: Debug endpoint enabled
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn debug_endpoint_enabled_returns_debug_outcome() {
        let config = make_config(&[], &[], DefaultPolicy::Deny, true);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = RequestInput::new("GET", "/.well-known/forgeguard/flags", vec![], None)
            .unwrap()
            .with_query_string("user_id=alice");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Debug(body) => {
                // Should be valid JSON
                let _v: serde_json::Value = serde_json::from_str(&body).unwrap();
            }
            other => panic!("expected Debug, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Debug endpoint disabled — falls through
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn debug_endpoint_disabled_falls_through() {
        // debug_mode = false, so the flags path should not be intercepted.
        // With no routes and default deny, it should reject 403.
        let config = make_config(&[], &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/.well-known/forgeguard/flags", "tok_abc");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        // Falls through to the normal pipeline — no route matches, not public, default deny
        match outcome {
            PipelineOutcome::Reject { status, .. } => {
                assert_eq!(status, 403);
            }
            other => panic!("expected Reject(403), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Public anonymous route
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn public_anonymous_route_forwards_without_identity() {
        let public_routes = vec![PublicRoute::new(
            "GET".parse().unwrap(),
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let config = make_config(&[], &public_routes, DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input("GET", "/public");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity,
                flags,
                matched_route,
            } => {
                assert!(identity.is_none());
                assert!(flags.is_none());
                assert!(matched_route.is_none());
            }
            other => panic!("expected Forward(anon), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: Public opportunistic + valid credential
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn public_opportunistic_with_valid_credential_forwards_with_identity() {
        let public_routes = vec![PublicRoute::new(
            "GET".parse().unwrap(),
            "/docs".to_string(),
            PublicAuthMode::Opportunistic,
        )];
        let config = make_config(&[], &public_routes, DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/docs", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity, flags, ..
            } => {
                assert!(identity.is_some());
                assert_eq!(identity.as_ref().unwrap().user_id().as_str(), "alice");
                // Flags should be evaluated since identity was resolved
                assert!(flags.is_some());
            }
            other => panic!("expected Forward(with identity), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Public opportunistic + invalid credential
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn public_opportunistic_with_invalid_credential_forwards_without_identity() {
        let public_routes = vec![PublicRoute::new(
            "GET".parse().unwrap(),
            "/docs".to_string(),
            PublicAuthMode::Opportunistic,
        )];
        let config = make_config(&[], &public_routes, DefaultPolicy::Deny, false);
        let chain = make_chain_failing();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/docs", "bad-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity, flags, ..
            } => {
                assert!(identity.is_none());
                assert!(flags.is_none());
            }
            other => panic!("expected Forward(anon), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 7b: Public opportunistic + no credential at all
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn public_opportunistic_no_credential_forwards_without_identity() {
        let public_routes = vec![PublicRoute::new(
            "GET".parse().unwrap(),
            "/docs".to_string(),
            PublicAuthMode::Opportunistic,
        )];
        let config = make_config(&[], &public_routes, DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        // No Authorization header — opportunistic should forward without identity
        let req = input("GET", "/docs");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity, flags, ..
            } => {
                assert!(identity.is_none());
                assert!(flags.is_none());
            }
            other => panic!("expected Forward(anon), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: Required auth + no credential
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn required_auth_no_credential_rejects_401() {
        let config = make_config(&[], &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        // No Authorization header
        let req = input("GET", "/protected");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 401);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["error"], "Unauthorized");
            }
            other => panic!("expected Reject(401), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: Required auth + invalid credential
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn required_auth_invalid_credential_rejects_401() {
        let config = make_config(&[], &[], DefaultPolicy::Deny, false);
        let chain = make_chain_failing();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/protected", "bad-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 401);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["error"], "Unauthorized");
            }
            other => panic!("expected Reject(401), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Required auth + valid credential + allowed
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn required_auth_valid_credential_allowed_forwards() {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/users".to_string(),
            QualifiedAction::parse("todo:list:user").unwrap(),
            None,
            None,
        )];
        let config = make_config(&routes, &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/users", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity,
                flags,
                matched_route,
            } => {
                assert!(identity.is_some());
                assert_eq!(identity.as_ref().unwrap().user_id().as_str(), "alice");
                assert!(flags.is_some());
                assert!(matched_route.is_some());
                assert_eq!(
                    matched_route.unwrap().action().to_string(),
                    "todo:list:user"
                );
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Feature gate disabled
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn feature_gate_disabled_rejects_404() {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/beta".to_string(),
            QualifiedAction::parse("app:read:beta").unwrap(),
            None,
            Some(FlagName::parse("beta-feature").unwrap()),
        )];
        // No flags configured, so the gate won't be enabled
        let config = make_config(&routes, &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/beta", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 404);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["error"], "Not Found");
            }
            other => panic!("expected Reject(404), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: Feature gate enabled
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn feature_gate_enabled_forwards() {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/beta".to_string(),
            QualifiedAction::parse("app:read:beta").unwrap(),
            None,
            Some(FlagName::parse("beta-feature").unwrap()),
        )];

        let mut flag_config = FlagConfig::default();
        flag_config.flags.insert(
            FlagName::parse("beta-feature").unwrap(),
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(true),
                enabled: true,
                overrides: vec![],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let config = make_config_with_flags(&routes, &[], DefaultPolicy::Deny, flag_config);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/beta", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity,
                matched_route,
                ..
            } => {
                assert!(identity.is_some());
                assert!(matched_route.is_some());
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Policy deny
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn policy_deny_rejects_403() {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/users".to_string(),
            QualifiedAction::parse("todo:list:user").unwrap(),
            None,
            None,
        )];
        let config = make_config(&routes, &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = deny_engine();
        let req = input_with_bearer("GET", "/users", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 403);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["error"], "Forbidden");
                assert_eq!(v["action"], "todo:list:user");
            }
            other => panic!("expected Reject(403), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: Policy error (fail-safe)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn policy_error_fail_safe_rejects_403() {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/users".to_string(),
            QualifiedAction::parse("todo:list:user").unwrap(),
            None,
            None,
        )];
        let config = make_config(&routes, &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = ErrorPolicyEngine;
        let req = input_with_bearer("GET", "/users", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 403);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["error"], "Forbidden");
                assert_eq!(v["action"], "todo:list:user");
            }
            other => panic!("expected Reject(403), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 15: No route + default deny
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_route_default_deny_rejects_403() {
        let config = make_config(&[], &[], DefaultPolicy::Deny, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/unknown", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 403);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["error"], "Forbidden");
                assert_eq!(v["reason"], "no matching route");
            }
            other => panic!("expected Reject(403), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 16: No route + default passthrough
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_route_default_passthrough_forwards() {
        let config = make_config(&[], &[], DefaultPolicy::Passthrough, false);
        let chain = make_chain_succeeding();
        let engine = allow_engine();
        let req = input_with_bearer("GET", "/anything", "valid-token");

        let outcome = evaluate_pipeline(&config, &req, &chain, &engine).await;

        match outcome {
            PipelineOutcome::Forward {
                identity,
                matched_route,
                ..
            } => {
                assert!(identity.is_some());
                assert!(matched_route.is_none());
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }
}
