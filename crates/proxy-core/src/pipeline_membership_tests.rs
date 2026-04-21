//! Phase 5b tests: org membership enrichment.
//!
//! Included by `pipeline_tests.rs` as a submodule.

use std::sync::Arc;

use forgeguard_core::{GroupName, OrganizationId, PrincipalKind, TenantId, UserId};
use forgeguard_http::{DefaultPolicy, PublicAuthMode, PublicRoute};

use crate::membership::{Membership, MembershipResolver, ResolveError};
use crate::PipelineOutcome;

use super::{
    allow_engine, input_with_bearer, input_with_bearer_and_org, make_chain_with_jwt_identity,
    make_config, make_config_with_membership, MockIdentityResolver,
};
use std::future::Future;
use std::pin::Pin;

use forgeguard_authn_core::{IdentityBuilder, IdentityChain};

// -----------------------------------------------------------------------
// Mock membership resolvers (Phase 5b)
// -----------------------------------------------------------------------

/// A membership resolver that always returns a fixed membership.
struct SucceedingMembershipResolver {
    membership: Membership,
}

impl MembershipResolver for SucceedingMembershipResolver {
    fn resolve(
        &self,
        _user_id: &UserId,
        _org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Membership>, ResolveError>> + Send + '_>> {
        let membership = self.membership.clone();
        Box::pin(async move { Ok(Some(membership)) })
    }
}

/// A membership resolver that always returns Ok(None) (not a member).
struct FailingMembershipResolver;

impl MembershipResolver for FailingMembershipResolver {
    fn resolve(
        &self,
        _user_id: &UserId,
        _org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Membership>, ResolveError>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }
}

/// A membership resolver that panics if called — used to verify it is NOT invoked.
struct PanicMembershipResolver;

impl MembershipResolver for PanicMembershipResolver {
    fn resolve(
        &self,
        _user_id: &UserId,
        _org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Membership>, ResolveError>> + Send + '_>> {
        panic!("PanicMembershipResolver::resolve must not be called")
    }
}

/// A membership resolver that simulates an I/O error (DynamoDB down, etc.).
struct ErroringMembershipResolver;

impl MembershipResolver for ErroringMembershipResolver {
    fn resolve(
        &self,
        _user_id: &UserId,
        _org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Membership>, ResolveError>> + Send + '_>> {
        Box::pin(async { Err(ResolveError::new("simulated DDB error")) })
    }
}

// -----------------------------------------------------------------------
// Phase 5b test cases
// -----------------------------------------------------------------------

/// Test 1: resolver returns Ok(Some) — identity is enriched with tenant + groups.
#[tokio::test]
async fn membership_enrichment_sets_tenant_and_groups() {
    let membership = Membership::new(vec![GroupName::new("admin").unwrap()]);
    let resolver = Arc::new(SucceedingMembershipResolver { membership });
    let config = make_config_with_membership(&[], &[], DefaultPolicy::Passthrough, resolver);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    let req = input_with_bearer_and_org("GET", "/anything", "valid-token", "acme-corp");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Forward {
            identity: Some(id), ..
        } => {
            assert_eq!(id.tenant_id().unwrap().as_str(), "acme-corp");
            let group_names: Vec<&str> = id.groups().iter().map(GroupName::as_str).collect();
            assert!(group_names.contains(&"admin"));
        }
        other => panic!("expected Forward with identity, got {other:?}"),
    }
}

/// Test 2: resolver returns Ok(None) — 403 with correct body.
#[tokio::test]
async fn membership_not_found_rejects_403() {
    let resolver = Arc::new(FailingMembershipResolver);
    let config = make_config_with_membership(&[], &[], DefaultPolicy::Passthrough, resolver);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    let req = input_with_bearer_and_org("GET", "/anything", "valid-token", "acme-corp");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Reject { status, body } => {
            assert_eq!(status, 403);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"], "Not a member of this organization");
        }
        other => panic!("expected Reject(403), got {other:?}"),
    }
}

/// Test 2b: resolver returns Err — 500 with generic body (I/O error must not leak).
#[tokio::test]
async fn membership_resolver_error_returns_500() {
    let resolver = Arc::new(ErroringMembershipResolver);
    let config = make_config_with_membership(&[], &[], DefaultPolicy::Passthrough, resolver);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    let req = input_with_bearer_and_org("GET", "/anything", "valid-token", "acme-corp");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Reject { status, body } => {
            assert_eq!(status, 500);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"], "Internal Server Error");
        }
        other => panic!("expected Reject(500), got {other:?}"),
    }
}

/// Test 3: no org header on a required (non-public) route — 400.
#[tokio::test]
async fn missing_org_header_on_required_route_rejects_400() {
    let membership = Membership::new(vec![]);
    let resolver = Arc::new(SucceedingMembershipResolver { membership });
    let config = make_config_with_membership(&[], &[], DefaultPolicy::Passthrough, resolver);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    // No X-ForgeGuard-Org-Id header; non-public route (require_credential = true).
    let req = input_with_bearer("GET", "/protected", "valid-token");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Reject { status, body } => {
            assert_eq!(status, 400);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"], "Missing X-ForgeGuard-Org-Id header");
        }
        other => panic!("expected Reject(400), got {other:?}"),
    }
}

/// Test 4: invalid org header value — 400.
#[tokio::test]
async fn invalid_org_header_rejects_400() {
    let membership = Membership::new(vec![]);
    let resolver = Arc::new(SucceedingMembershipResolver { membership });
    let config = make_config_with_membership(&[], &[], DefaultPolicy::Passthrough, resolver);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    // "NOT VALID!" contains spaces and special chars — fails OrganizationId::new.
    let req = input_with_bearer_and_org("GET", "/anything", "valid-token", "NOT VALID!");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Reject { status, body } => {
            assert_eq!(status, 400);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"], "Invalid X-ForgeGuard-Org-Id header");
        }
        other => panic!("expected Reject(400), got {other:?}"),
    }
}

/// Test 5: machine auth (tenant_id already set) — membership resolver is NOT called.
#[tokio::test]
async fn machine_auth_skips_membership_enrichment() {
    // PanicMembershipResolver panics if called — proves it is skipped.
    let resolver = Arc::new(PanicMembershipResolver);
    let config = make_config_with_membership(&[], &[], DefaultPolicy::Passthrough, resolver);

    // Identity with tenant_id already set (as Ed25519 / machine auth would produce).
    let machine_identity = IdentityBuilder::new(UserId::new("alice").unwrap())
        .tenant(TenantId::new("acme-corp").unwrap())
        .principal_kind(PrincipalKind::Machine)
        .resolver("ed25519")
        .build();
    let chain = IdentityChain::new(vec![Arc::new(MockIdentityResolver::succeeding(
        machine_identity,
    ))]);
    let engine = allow_engine();
    let req = input_with_bearer_and_org("GET", "/anything", "valid-token", "acme-corp");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    // Should forward — Phase 5b skipped because tenant_id is already set.
    match outcome {
        PipelineOutcome::Forward {
            identity: Some(id), ..
        } => {
            assert_eq!(id.tenant_id().unwrap().as_str(), "acme-corp");
        }
        other => panic!("expected Forward with identity, got {other:?}"),
    }
}

/// Test 6: no membership resolver configured — existing behavior, no tenant.
#[tokio::test]
async fn no_membership_resolver_skips_phase_5b() {
    // make_config has membership_resolver: None.
    let config = make_config(&[], &[], DefaultPolicy::Passthrough, false);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    let req = input_with_bearer("GET", "/anything", "valid-token");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Forward {
            identity: Some(id), ..
        } => {
            assert!(id.tenant_id().is_none());
        }
        other => panic!("expected Forward with identity (no tenant), got {other:?}"),
    }
}

/// Test 7: opportunistic route + membership resolver configured + no org header.
///
/// Regression test for the silent-drop bug: `identity.take()` was called
/// unconditionally as part of tuple construction, draining `identity` to `None`
/// even when `org_id` was `None`. The fix ensures `take()` is only called when
/// `org_id` is `Some`.
///
/// Invariants:
/// - `PanicMembershipResolver` panics if called — proves the resolver is never
///   invoked when the org header is absent.
/// - The forwarded identity must be the unenriched JWT identity (no tenant_id),
///   not `None`.
#[tokio::test]
async fn no_org_header_on_opportunistic_route_preserves_identity() {
    let public_routes = vec![PublicRoute::new(
        "GET".parse().unwrap(),
        "/opt".to_string(),
        PublicAuthMode::Opportunistic,
    )];
    // PanicMembershipResolver will panic if Phase 5b calls resolve() —
    // proving the resolver is skipped when there is no org header.
    let resolver = Arc::new(PanicMembershipResolver);
    let config = make_config_with_membership(&[], &public_routes, DefaultPolicy::Deny, resolver);
    let chain = make_chain_with_jwt_identity();
    let engine = allow_engine();
    // Valid bearer token, but NO X-ForgeGuard-Org-Id header.
    let req = input_with_bearer("GET", "/opt", "valid-token");

    let outcome = super::evaluate_pipeline(&config, &req, &chain, &engine).await;

    match outcome {
        PipelineOutcome::Forward {
            identity: Some(id), ..
        } => {
            // Identity must be the unenriched JWT identity — not silently dropped.
            assert_eq!(id.user_id().as_str(), "alice");
            assert!(
                id.tenant_id().is_none(),
                "identity must be unenriched (no org header was sent)"
            );
        }
        other => panic!("expected Forward with unenriched identity, got {other:?}"),
    }
}
