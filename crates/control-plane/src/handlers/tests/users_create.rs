//! Integration tests for `POST /api/v1/organizations/{org_id}/users`.
//!
//! Exercises the inline 3-stage saga (S1 → S2 → S3 with C2 compensation) and
//! the seven response paths from plan §9, against the in-memory store + the
//! in-memory `UserPoolClient` (with `arm_*_once` failure injection).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use forgeguard_authn_core::saga::{SagaStage, SagaStatus, SagaTicket, SagaTicketParams, TicketId};
use forgeguard_authn_core::UserPoolError;
use forgeguard_core::{OrgStatus, Organization, OrganizationId, UserId};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::TEST_API_KEY;
use super::users_support::{
    active_org_with_schema, failing_test_app_for_store, metric_lock, payload, test_app_for_store,
    FailingUsersTestApp, UsersTestApp,
};
use crate::metrics::SAGA_COMPENSATION_FAILED_TOTAL;
use crate::store::{InMemoryOrgStore, OrgStore, SagaTicketStore};
use crate::user_pool::UserPoolClient;

const ORG: &str = "org-acme";
const POOL: &str = "us-east-2_TestPool";
const URI: &str = "/api/v1/organizations/org-acme/users";

async fn post(app: &axum::Router, body: Vec<u8>) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(URI)
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Path 1 — 201 Created (happy path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_returns_201() {
    let store = active_org_with_schema(ORG, POOL, &["admin"]).await;
    let UsersTestApp {
        router,
        store: store_handle,
        saga_tickets,
        ..
    } = test_app_for_store(store);

    let resp = post(
        &router,
        payload("alice@example.com", Some("Alice"), &["admin"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;

    let sub_str = json["sub"].as_str().unwrap().to_owned();
    assert!(!sub_str.is_empty());
    assert_eq!(json["attributes"]["name"], "Alice");
    assert_eq!(json["groups"], serde_json::json!(["admin"]));
    let ticket_id = TicketId::try_new(json["ticket_id"].as_str().unwrap()).unwrap();
    let ticket = saga_tickets
        .get_saga_ticket(&ticket_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.current_stage(), SagaStage::Done);
    assert_eq!(ticket.status(), SagaStatus::Succeeded);

    let org_id = OrganizationId::new(ORG).unwrap();
    let sub = UserId::new(&sub_str).unwrap();
    let row = store_handle
        .get_membership_row(&org_id, &sub)
        .await
        .expect("membership row written");
    assert_eq!(row.email(), "alice@example.com");
    assert_eq!(
        row.groups()
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["admin".to_string()],
    );
}

// ---------------------------------------------------------------------------
// Path 6 — 422 validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_required_attr_returns_422() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let resp = post(&router, payload("alice@example.com", None, &[])).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    let errors = json["errors"].as_array().unwrap();
    assert!(errors
        .iter()
        .any(|e| e["field"] == "name" && e["reason"] == "missing_required"));
}

#[tokio::test]
async fn unknown_attr_returns_422() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let body = serde_json::to_vec(&serde_json::json!({
        "email": "alice@example.com",
        "attributes": { "name": "Alice", "bogus": "value" }
    }))
    .unwrap();
    let resp = post(&router, body).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    let errors = json["errors"].as_array().unwrap();
    assert!(errors
        .iter()
        .any(|e| e["field"] == "bogus" && e["reason"] == "unknown_attribute"));
}

#[tokio::test]
async fn undeclared_group_returns_422() {
    let store = active_org_with_schema(ORG, POOL, &["admin"]).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let resp = post(
        &router,
        payload("alice@example.com", Some("Alice"), &["ghosts"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["errors"][0]["field"], "groups.ghosts");
    assert_eq!(json["errors"][0]["reason"], "undeclared_group");
}

#[tokio::test]
async fn empty_groups_is_valid() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ---------------------------------------------------------------------------
// Path 4 — 409 username exists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dup_email_returns_409() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let first = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let dup = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(dup.status(), StatusCode::CONFLICT);
    let json = body_json(dup).await;
    assert_eq!(json["error"], "username_exists");
}

// ---------------------------------------------------------------------------
// Path 5 — 409 in-flight saga
// ---------------------------------------------------------------------------

#[tokio::test]
async fn in_flight_ticket_returns_409() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp {
        router,
        saga_tickets,
        ..
    } = test_app_for_store(store);

    let org_id = OrganizationId::new(ORG).unwrap();
    let existing_ticket = SagaTicket::new(SagaTicketParams {
        ticket_id: TicketId::generate(),
        org_id: org_id.clone(),
        email: "alice@example.com".to_string(),
        groups: Vec::new(),
        attributes: BTreeMap::new(),
        created_at: Utc::now(),
        created_by: UserId::new("seed").unwrap(),
    });
    let existing_id = existing_ticket.ticket_id().clone();
    saga_tickets.put_saga_ticket(existing_ticket).await.unwrap();

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "in_flight_saga");
    assert_eq!(json["existing_ticket_id"], existing_id.as_str());
}

// ---------------------------------------------------------------------------
// State-gate — 409 / 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn draft_org_returns_409() {
    let store = Arc::new(InMemoryOrgStore::new(Default::default()));
    let org_id = OrganizationId::new(ORG).unwrap();
    let org = Organization::new(org_id, format!("{ORG} org"), OrgStatus::Draft, Utc::now());
    store.write_through_org(org, None).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "org_state_conflict");
}

#[tokio::test]
async fn deleted_org_returns_404() {
    let store = Arc::new(InMemoryOrgStore::new(Default::default()));
    let org_id = OrganizationId::new(ORG).unwrap();
    let org = Organization::new(org_id, format!("{ORG} org"), OrgStatus::Deleted, Utc::now());
    store.write_through_org(org, None).await;
    let UsersTestApp { router, .. } = test_app_for_store(store);

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Path 7 — 502 S2 permanent error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s2_permanent_error_returns_502() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp {
        router,
        user_pool,
        saga_tickets,
        ..
    } = test_app_for_store(store);

    user_pool.arm_admin_create_user_once(UserPoolError::Permanent {
        source: "cognito boom".into(),
    });

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "upstream_error");
    let ticket_id = TicketId::try_new(json["ticket_id"].as_str().unwrap()).unwrap();
    let ticket = saga_tickets
        .get_saga_ticket(&ticket_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.current_stage(), SagaStage::Failed);
    assert_eq!(ticket.status(), SagaStatus::Failed);
}

#[tokio::test]
async fn s2_transient_error_returns_502_with_transient_message() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp {
        router,
        user_pool,
        saga_tickets,
        ..
    } = test_app_for_store(store);

    user_pool.arm_admin_create_user_once(UserPoolError::Transient {
        source: "cognito throttled".into(),
    });

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "upstream_error");
    assert!(
        json["message"].as_str().unwrap().contains("transient"),
        "transient S2 must surface a transient-flavoured message, got: {}",
        json["message"]
    );
    let ticket_id = TicketId::try_new(json["ticket_id"].as_str().unwrap()).unwrap();
    let ticket = saga_tickets
        .get_saga_ticket(&ticket_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.current_stage(), SagaStage::Failed);
    assert_eq!(ticket.status(), SagaStatus::Failed);
}

// ---------------------------------------------------------------------------
// Path 2 — 202 parked saga (S3 transient, C2 succeeds)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s3_transient_c2_succeeds_returns_202() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let FailingUsersTestApp {
        router,
        failing_store,
        user_pool,
        saga_tickets,
    } = failing_test_app_for_store(store);

    // Force S3 to fail on the next call so the saga drops into compensation.
    failing_store.fail_next_put_membership_row();

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "in_progress");
    let ticket_id = TicketId::try_new(json["ticket_id"].as_str().unwrap()).unwrap();
    let ticket = saga_tickets
        .get_saga_ticket(&ticket_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.current_stage(), SagaStage::Failed);
    assert_eq!(ticket.status(), SagaStatus::Failed);

    // C2 must have removed the saga-minted Cognito user.
    use forgeguard_authn_core::user_pool::PoolId;
    let pool = PoolId::try_new(POOL).unwrap();
    let err = user_pool
        .admin_get_user(&pool, "alice@example.com")
        .await
        .err();
    assert!(matches!(err, Some(UserPoolError::UserNotFound)));
}

// ---------------------------------------------------------------------------
// Path 3 — 500 compensation failed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s3_transient_c2_fails_returns_500() {
    let _guard = metric_lock().await;
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let FailingUsersTestApp {
        router,
        failing_store,
        user_pool,
        saga_tickets,
    } = failing_test_app_for_store(store);

    failing_store.fail_next_put_membership_row();
    user_pool.arm_admin_delete_user_once(UserPoolError::Transient {
        source: "deadline".into(),
    });

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "failed");
    let ticket_id = TicketId::try_new(json["ticket_id"].as_str().unwrap()).unwrap();
    let ticket = saga_tickets
        .get_saga_ticket(&ticket_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.current_stage(), SagaStage::CompensationFailed);
    assert_eq!(ticket.status(), SagaStatus::CompensationFailed);
}

#[tokio::test]
async fn metric_incremented_on_compensation_failure() {
    let _guard = metric_lock().await;
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let FailingUsersTestApp {
        router,
        failing_store,
        user_pool,
        ..
    } = failing_test_app_for_store(store);

    let before = SAGA_COMPENSATION_FAILED_TOTAL.get();
    failing_store.fail_next_put_membership_row();
    user_pool.arm_admin_delete_user_once(UserPoolError::Transient {
        source: "boom".into(),
    });
    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(SAGA_COMPENSATION_FAILED_TOTAL.get(), before + 1);
}

// ---------------------------------------------------------------------------
// Persistence invariants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ticket_persisted_with_correct_schema() {
    let store = active_org_with_schema(ORG, POOL, &["admin"]).await;
    let UsersTestApp {
        router,
        saga_tickets,
        ..
    } = test_app_for_store(store);

    let resp = post(
        &router,
        payload("alice@example.com", Some("Alice"), &["admin"]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    let ticket_id = TicketId::try_new(json["ticket_id"].as_str().unwrap()).unwrap();
    let ticket = saga_tickets
        .get_saga_ticket(&ticket_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.org_id().as_str(), ORG);
    assert_eq!(ticket.email(), "alice@example.com");
    assert_eq!(
        ticket.attributes().get("name").map(String::as_str),
        Some("Alice")
    );
    assert_eq!(
        ticket
            .groups()
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["admin".to_string()],
    );
    assert!(ticket.sub().is_some());
}

#[tokio::test]
async fn gsi_entry_removed_after_termination() {
    let store = active_org_with_schema(ORG, POOL, &[]).await;
    let UsersTestApp {
        router,
        saga_tickets,
        ..
    } = test_app_for_store(store);

    let resp = post(&router, payload("alice@example.com", Some("Alice"), &[])).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let org_id = OrganizationId::new(ORG).unwrap();
    let in_flight = saga_tickets
        .find_in_flight_saga_by_email(&org_id, "alice@example.com")
        .await
        .unwrap();
    assert!(
        in_flight.is_none(),
        "terminal sagas must not be returned by in-flight lookup",
    );
}
