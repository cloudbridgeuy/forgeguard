//! Integration tests for the V4 Active branch of
//! `PUT /api/v1/organizations/{org_id}/user-schema`.
//!
//! Covers the 10 cases (T1–T10) of the V4 plan §9: the Cognito-first happy
//! path, the `AttributeAlreadyExists` tolerance + retry seam (A4.7), the `502`
//! upstream-failure branches, the append-only `422` violations, the
//! `pool_not_provisioned` `409`, and the optimistic-lock `412`.

use std::sync::Arc;

use axum::http::StatusCode;
use forgeguard_authn_core::user_pool::UserPoolError;
use serde_json::json;

use super::user_schema_active_support::{
    active_org, active_org_no_pool, body_json, get_schema, put_schema, schema_test_app,
    seed_schema, FailingStore,
};
use crate::store::OrgStore;

fn custom_attr(min_length: Option<u32>) -> serde_json::Value {
    match min_length {
        Some(min) => json!({ "type": "string", "min_length": min, "required": false }),
        None => json!({ "type": "string", "required": false }),
    }
}

fn transient_error() -> UserPoolError {
    UserPoolError::Transient {
        source: Box::new(std::io::Error::other("cognito throttled")),
    }
}

// --- T1 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_appends_new_custom_attr() {
    let store = active_org("us-east-2_acme");
    let app = schema_test_app(store as Arc<dyn OrgStore>);

    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(axum::http::header::ETAG).is_some(),
        "successful Active PUT must emit ETag"
    );
    let json = body_json(resp).await;
    assert_eq!(json["custom"]["dept"]["type"], "string");
}

// --- T2 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_cognito_already_exists_treated_as_success() {
    let store = active_org("us-east-2_acme");
    let app = schema_test_app(store as Arc<dyn OrgStore>);
    app.user_pool
        .arm_update_user_pool_once(UserPoolError::AttributeAlreadyExists {
            name: "custom:dept".to_owned(),
        });

    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);

    // Tolerating `AttributeAlreadyExists` must not abort the DDB write — the
    // new attribute is persisted and observable via GET.
    let get_resp = get_schema(&app.router).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(get_resp).await["custom"]["dept"]["type"],
        "string"
    );
}

// --- T3 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_cognito_error_returns_502() {
    let store = active_org("us-east-2_acme");
    let app = schema_test_app(store as Arc<dyn OrgStore>);
    app.user_pool.arm_update_user_pool_once(transient_error());

    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "upstream_error");
    assert_eq!(json["reason"], "cognito_update_failed");

    // DDB row must be untouched — a Cognito failure aborts before persisting.
    let get_resp = get_schema(&app.router).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(get_resp).await,
        json!({ "standard": {}, "custom": {} })
    );
}

// --- T4 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_ddb_write_fails_after_cognito_success() {
    let failing = Arc::new(FailingStore::new(active_org("us-east-2_acme")));
    failing.fail_next_put_user_schema();
    let app = schema_test_app(Arc::clone(&failing) as Arc<dyn OrgStore>);

    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "upstream_error");
    assert_eq!(json["reason"], "schema_persist_failed");
}

// --- T5 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_retry_after_partial_failure_succeeds() {
    let failing = Arc::new(FailingStore::new(active_org("us-east-2_acme")));
    failing.fail_next_put_user_schema();
    let app = schema_test_app(Arc::clone(&failing) as Arc<dyn OrgStore>);
    let body = json!({ "standard": {}, "custom": { "dept": custom_attr(None) } });

    // First attempt: Cognito succeeds, the DDB write fails → 502.
    let first = put_schema(&app.router, body.clone(), None).await;
    assert_eq!(first.status(), StatusCode::BAD_GATEWAY);

    // Retry: Cognito now reports the attribute already exists (A4.7); the
    // handler tolerates it and the now-drained store persists the row.
    app.user_pool
        .arm_update_user_pool_once(UserPoolError::AttributeAlreadyExists {
            name: "custom:dept".to_owned(),
        });
    let second = put_schema(&app.router, body, None).await;
    assert_eq!(second.status(), StatusCode::OK);
    let json = body_json(second).await;
    assert_eq!(json["custom"]["dept"]["type"], "string");
}

// --- T6 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_removal_rejected() {
    let store = active_org("us-east-2_acme");
    seed_schema(
        store.as_ref(),
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
    )
    .await;
    let app = schema_test_app(store as Arc<dyn OrgStore>);

    let resp = put_schema(&app.router, json!({ "standard": {}, "custom": {} }), None).await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "append_only_violation");
    assert_eq!(json["violations"][0]["field"], "custom.dept");
    assert_eq!(json["violations"][0]["reason"], "removed");
}

// --- T7 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_rename_rejected() {
    let store = active_org("us-east-2_acme");
    seed_schema(
        store.as_ref(),
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
    )
    .await;
    let app = schema_test_app(store as Arc<dyn OrgStore>);

    // A rename reads as "remove `dept`, add `department`" — the removal trips
    // the append-only guard.
    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "department": custom_attr(None) } }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "append_only_violation");
    assert_eq!(json["violations"][0]["reason"], "removed");
}

// --- T8 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_type_change_rejected() {
    let store = active_org("us-east-2_acme");
    seed_schema(
        store.as_ref(),
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
    )
    .await;
    let app = schema_test_app(store as Arc<dyn OrgStore>);

    // Adding a `min_length` bound to an existing attribute is a shape change.
    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "dept": custom_attr(Some(5)) } }),
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "append_only_violation");
    assert_eq!(json["violations"][0]["reason"], "length_bounds_changed");
}

// --- T9 --------------------------------------------------------------------

#[tokio::test]
async fn active_org_no_pool_id_returns_409() {
    let store = active_org_no_pool();
    let app = schema_test_app(store as Arc<dyn OrgStore>);

    let resp = put_schema(&app.router, json!({ "standard": {}, "custom": {} }), None).await;

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "pool_not_provisioned");
}

// --- T10 -------------------------------------------------------------------

#[tokio::test]
async fn etag_mismatch_returns_412() {
    let store = active_org("us-east-2_acme");
    let stored_etag = seed_schema(
        store.as_ref(),
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
    )
    .await;
    let app = schema_test_app(store as Arc<dyn OrgStore>);

    let resp = put_schema(
        &app.router,
        json!({ "standard": {}, "custom": { "dept": custom_attr(None) } }),
        Some("\"definitely-stale\""),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let json = body_json(resp).await;
    assert_eq!(json["reason"], "stale_etag");
    assert_eq!(json["current_etag"], stored_etag);
}
