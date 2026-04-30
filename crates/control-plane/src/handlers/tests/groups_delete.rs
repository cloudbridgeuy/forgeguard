use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app, TEST_API_KEY};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an org, create a group, and return the group's etag.
async fn setup_org_with_group(
    store: Arc<crate::store::InMemoryOrgStore>,
    org_id: &str,
    group_name: &str,
) -> String {
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, org_id, "Delete Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{org_id}/groups"))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": group_name,
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    resp.headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_with_inheritor_returns_409_blocking_inheritors() {
    let store = empty_store();
    // Create "member" first, then "admin" which inherits from it.
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-del-inh", "Inheritor Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create "member"
    let app = test_app(Arc::clone(&store));
    let member_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-del-inh/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "member",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(member_resp.status(), StatusCode::CREATED);
    let member_etag = member_resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // Create "admin" inheriting "member"
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-del-inh/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "admin",
                        "allow": ["cp:org:write"],
                        "inherits": ["member"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Attempt to delete "member" — blocked by "admin" inheriting it
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-del-inh/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &member_etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "delete_conflict");
    let inheritors = json["blocking_inheritors"].as_array().unwrap();
    assert!(
        !inheritors.is_empty(),
        "blocking_inheritors must list the inheriting group"
    );
    assert!(
        inheritors.iter().any(|v| v == "admin"),
        "blocking_inheritors must contain 'admin'"
    );
}

#[tokio::test]
async fn delete_group_with_membership_returns_409_memberships_count() {
    let store = empty_store();
    let etag = setup_org_with_group(Arc::clone(&store), "org-del-mem", "admin").await;

    // Seed a membership so count_memberships_for_group returns a non-empty map.
    use forgeguard_core::OrganizationId;
    let org_id = OrganizationId::new("org-del-mem").unwrap();
    store
        .seed_membership(&org_id, "user-alice", vec!["admin".to_owned()])
        .await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-del-mem/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "delete_conflict");
    let counts = json["memberships_count"].as_object().unwrap();
    assert!(!counts.is_empty(), "memberships_count must be non-empty");
    assert!(
        counts.contains_key("user-alice"),
        "must list the seeded user"
    );
}

#[tokio::test]
async fn delete_group_with_both_returns_409_both_arrays_populated() {
    let store = empty_store();
    // Setup org with "member" and "admin" inheriting "member"
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-del-both", "Both Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create "member"
    let app = test_app(Arc::clone(&store));
    let member_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-del-both/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "member",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(member_resp.status(), StatusCode::CREATED);
    let member_etag = member_resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // Create "admin" inheriting "member"
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-del-both/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "admin",
                        "allow": ["cp:org:write"],
                        "inherits": ["member"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Seed a direct membership on "member" as well
    use forgeguard_core::OrganizationId;
    let org_id = OrganizationId::new("org-del-both").unwrap();
    store
        .seed_membership(&org_id, "user-bob", vec!["member".to_owned()])
        .await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-del-both/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &member_etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "delete_conflict");
    let inheritors = json["blocking_inheritors"].as_array().unwrap();
    let counts = json["memberships_count"].as_object().unwrap();
    assert!(
        !inheritors.is_empty(),
        "blocking_inheritors must be non-empty"
    );
    assert!(!counts.is_empty(), "memberships_count must be non-empty");
}

#[tokio::test]
async fn delete_group_clean_returns_204_then_get_returns_404() {
    let store = empty_store();
    let etag = setup_org_with_group(Arc::clone(&store), "org-del-clean", "admin").await;

    // Delete the group (no inheritors, no members)
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-del-clean/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify subsequent GET returns 404
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-del-clean/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
