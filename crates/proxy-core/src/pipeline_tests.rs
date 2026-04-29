//! Tests for the auth pipeline evaluation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

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
    FlagConfig, FlagDefinition, FlagDefinitionParams, FlagName, FlagType, FlagValue, GroupName,
    ProjectId, QualifiedAction, TenantId, UserId,
};

use crate::membership::MembershipResolver;
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
    ) -> Pin<Box<dyn Future<Output = forgeguard_authn_core::Result<Identity>> + Send + '_>> {
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
    PipelineConfig::new(crate::PipelineConfigParams {
        route_matcher,
        public_route_matcher: public_matcher,
        flag_config: FlagConfig::default(),
        project_id: ProjectId::new("test-project").unwrap(),
        default_policy,
        debug_mode,
        auth_providers: vec!["jwt".to_string()],
        membership_resolver: None,
    })
}

fn make_config_with_flags(
    routes: &[RouteMapping],
    public_routes: &[PublicRoute],
    default_policy: DefaultPolicy,
    flag_config: FlagConfig,
) -> PipelineConfig {
    let route_matcher = RouteMatcher::new(routes).unwrap();
    let public_matcher = PublicRouteMatcher::new(public_routes).unwrap();
    PipelineConfig::new(crate::PipelineConfigParams {
        route_matcher,
        public_route_matcher: public_matcher,
        flag_config,
        project_id: ProjectId::new("test-project").unwrap(),
        default_policy,
        debug_mode: false,
        auth_providers: vec!["jwt".to_string()],
        membership_resolver: None,
    })
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

fn make_jwt_identity() -> Identity {
    // JWT-style identity: no tenant_id, no groups (as produced after D1).
    IdentityBuilder::new(UserId::new("alice").unwrap())
        .resolver("mock-resolver")
        .build()
}

fn make_chain_with_jwt_identity() -> IdentityChain {
    IdentityChain::new(vec![Arc::new(MockIdentityResolver::succeeding(
        make_jwt_identity(),
    ))])
}

fn make_config_with_membership(
    routes: &[RouteMapping],
    public_routes: &[PublicRoute],
    default_policy: DefaultPolicy,
    resolver: Arc<dyn MembershipResolver>,
) -> PipelineConfig {
    let route_matcher = RouteMatcher::new(routes).unwrap();
    let public_matcher = PublicRouteMatcher::new(public_routes).unwrap();
    PipelineConfig::new(crate::PipelineConfigParams {
        route_matcher,
        public_route_matcher: public_matcher,
        flag_config: FlagConfig::default(),
        project_id: ProjectId::new("test-project").unwrap(),
        default_policy,
        debug_mode: false,
        auth_providers: vec!["jwt".to_string()],
        membership_resolver: Some(resolver),
    })
}

fn input_with_bearer_and_org(method: &str, path: &str, token: &str, org: &str) -> RequestInput {
    let headers = vec![
        ("authorization".to_string(), format!("Bearer {token}")),
        ("x-forgeguard-org-id".to_string(), org.to_string()),
    ];
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
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(true),
            enabled: true,
            overrides: vec![],
            rollout_percentage: None,
            rollout_variant: None,
        }),
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

// -----------------------------------------------------------------------
// Phase 5b tests: org membership enrichment
// -----------------------------------------------------------------------

#[path = "pipeline_membership_tests.rs"]
mod membership_tests;
