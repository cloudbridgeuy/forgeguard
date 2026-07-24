//! Enforce|Observe mode tests (#111 V3).
//!
//! Included by `pipeline_tests.rs` as a submodule.

use forgeguard_core::QualifiedAction;
use forgeguard_http::{DefaultPolicy, RouteMapping};

use super::{
    allow_engine, deny_engine, embedded_engine_granting, input_with_bearer, make_chain_succeeding,
    make_config, ErrorPolicyEngine,
};

use crate::{evaluate_pipeline, EnforcementMode, PipelineOutcome, PolicyEffect};

#[tokio::test]
async fn observe_mode_forwards_on_deny_with_would_deny() {
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

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Observe).await;

    match outcome {
        PipelineOutcome::Forward { effect, .. } => {
            assert_eq!(effect, PolicyEffect::WouldDeny);
        }
        other => panic!("expected Forward(WouldDeny), got {other:?}"),
    }
}

#[tokio::test]
async fn observe_mode_deny_carries_record_from_embedded_engine() {
    let routes = vec![RouteMapping::new(
        "GET".parse().unwrap(),
        "/users".to_string(),
        QualifiedAction::parse("todo:list:user").unwrap(),
        None,
        None,
    )];
    let config = make_config(&routes, &[], DefaultPolicy::Deny, false);
    let chain = make_chain_succeeding();
    // Grant a different verb than the route requires — the embedded engine
    // still produces a record (it always evaluates against the store), but
    // the decision comes back denied.
    let engine = embedded_engine_granting("todo--list--other").await;
    let req = input_with_bearer("GET", "/users", "valid-token");

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Observe).await;

    match outcome {
        PipelineOutcome::Forward { effect, record, .. } => {
            assert_eq!(effect, PolicyEffect::WouldDeny);
            let record = record.expect("embedded engine should produce a record on deny");
            assert!(!record.scope_path().to_string().is_empty());
        }
        other => panic!("expected Forward(WouldDeny) with record, got {other:?}"),
    }
}

#[tokio::test]
async fn observe_mode_allow_reports_would_allow() {
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

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Observe).await;

    match outcome {
        PipelineOutcome::Forward { effect, .. } => {
            assert_eq!(effect, PolicyEffect::WouldAllow);
        }
        other => panic!("expected Forward(WouldAllow), got {other:?}"),
    }
}

#[tokio::test]
async fn enforce_mode_allow_reports_allowed() {
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

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Enforce).await;

    match outcome {
        PipelineOutcome::Forward { effect, .. } => {
            assert_eq!(effect, PolicyEffect::Allowed);
        }
        other => panic!("expected Forward(Allowed), got {other:?}"),
    }
}

#[tokio::test]
async fn enforce_deny_reject_carries_record_from_embedded_engine() {
    let routes = vec![RouteMapping::new(
        "GET".parse().unwrap(),
        "/users".to_string(),
        QualifiedAction::parse("todo:list:user").unwrap(),
        None,
        None,
    )];
    let config = make_config(&routes, &[], DefaultPolicy::Deny, false);
    let chain = make_chain_succeeding();
    // Grant a different verb than the route requires — the embedded engine
    // still produces a record (it always evaluates against the store), but
    // the decision comes back denied.
    let engine = embedded_engine_granting("todo--list--other").await;
    let req = input_with_bearer("GET", "/users", "valid-token");

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Enforce).await;

    match outcome {
        PipelineOutcome::Reject {
            status,
            policy_denied,
            record,
            ..
        } => {
            assert_eq!(status, 403);
            assert!(policy_denied);
            let record = record.expect("embedded engine should produce a record on deny");
            assert!(!record.scope_path().to_string().is_empty());
        }
        other => panic!("expected Reject with record, got {other:?}"),
    }
}

#[tokio::test]
async fn enforce_deny_static_engine_reject_has_no_record() {
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

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Enforce).await;

    match outcome {
        PipelineOutcome::Reject {
            status,
            policy_denied,
            record,
            ..
        } => {
            assert_eq!(status, 403);
            assert!(policy_denied);
            assert!(record.is_none());
        }
        other => panic!("expected Reject with no record, got {other:?}"),
    }
}

#[tokio::test]
async fn policy_error_under_observe_forwards_as_would_deny() {
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

    let outcome = evaluate_pipeline(&config, &req, &chain, &engine, EnforcementMode::Observe).await;

    match outcome {
        PipelineOutcome::Forward { effect, record, .. } => {
            assert_eq!(effect, PolicyEffect::WouldDeny);
            assert!(record.is_none());
        }
        other => panic!("expected Forward(WouldDeny) with no record, got {other:?}"),
    }
}
