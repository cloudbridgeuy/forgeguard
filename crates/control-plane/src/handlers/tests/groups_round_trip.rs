//! Round-trip parity test: RBAC entries survive a JSON POST + GET round-trip
//! through the control-plane groups API.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use forgeguard_authz_core::RbacEntry;
use http_body_util::BodyExt;
use serde::Deserialize;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app, TEST_API_KEY};

// ---------------------------------------------------------------------------
// Local TOML parsing types
//
// `forgeguard.toml` RBAC entries omit the `type` field entirely (defaulting
// to "rbac").  Cedar entries carry `type = "cedar"`.  We parse via
// `toml::Value` first, then classify by whether the `type` key is present.
// ---------------------------------------------------------------------------

/// Thin wrapper so we can deserialise the `[[policies]]` section directly.
#[derive(Deserialize)]
struct RawForgeGuardToml {
    policies: Vec<toml::Value>,
}

/// Extract RBAC entries from the raw `[[policies]]` values.
///
/// An entry is treated as RBAC when it has no `type` key, or `type = "rbac"`.
/// Entries with `type = "cedar"` (or any other explicit type) are silently
/// skipped.
fn extract_rbac_entries(policies: Vec<toml::Value>) -> Vec<RbacEntry> {
    policies
        .into_iter()
        .filter_map(|val| {
            let table = val.as_table()?;
            // Classify by the `type` field.
            // Entries without a `type` key default to "rbac" (same logic as
            // xtask's `PolicyEntry` custom deserialiser).
            let ty = table.get("type").and_then(|v| v.as_str());
            match ty {
                // Explicitly Cedar or any other non-rbac type — discard.
                Some(t) if t != "rbac" => None,
                // No `type` field (implicit rbac) or explicit `type = "rbac"`.
                _ => {
                    let name = table.get("name")?.as_str()?.to_owned();
                    let description = table
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    let inherits = table
                        .get("inherits")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    let allow = table
                        .get("allow")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    let tenant_scoped = table
                        .get("tenant_scoped")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(true);
                    Some(RbacEntry {
                        name,
                        description,
                        inherits,
                        allow,
                        tenant_scoped,
                    })
                }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Pure helper
// ---------------------------------------------------------------------------

/// Convert a slice of [`RbacEntry`] values to a canonical `toml::Value::Array`
/// suitable for byte-stable equality comparisons.
///
/// Entries are sorted alphabetically by name. Each entry becomes a
/// `toml::Value::Table`. Keys are stored alphabetically (BTreeMap backing —
/// the `preserve_order` feature of the `toml` crate is not enabled); equality
/// is value-based and key-order independent.  When `description` is `None`,
/// the key is omitted entirely.
fn rbac_entries_to_toml_value(entries: &[RbacEntry]) -> toml::Value {
    let mut sorted: Vec<&RbacEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let strings_to_array = |v: &[String]| {
        toml::Value::Array(v.iter().map(|s| toml::Value::String(s.clone())).collect())
    };

    let array: Vec<toml::Value> = sorted
        .into_iter()
        .map(|e| {
            let mut table = toml::map::Map::new();
            table.insert("name".to_owned(), toml::Value::String(e.name.clone()));
            if let Some(desc) = &e.description {
                table.insert("description".to_owned(), toml::Value::String(desc.clone()));
            }
            table.insert("inherits".to_owned(), strings_to_array(&e.inherits));
            table.insert("allow".to_owned(), strings_to_array(&e.allow));
            table.insert(
                "tenant_scoped".to_owned(),
                toml::Value::Boolean(e.tenant_scoped),
            );
            toml::Value::Table(table)
        })
        .collect();

    toml::Value::Array(array)
}

// ---------------------------------------------------------------------------
// Unit tests for the pure helper
// ---------------------------------------------------------------------------

#[test]
fn rbac_entries_to_toml_value_sorts_by_name() {
    let entries = vec![
        RbacEntry {
            name: "owner".to_owned(),
            description: None,
            inherits: vec![],
            allow: vec!["cp-org-delete".to_owned()],
            tenant_scoped: true,
        },
        RbacEntry {
            name: "admin".to_owned(),
            description: None,
            inherits: vec![],
            allow: vec!["cp-org-write".to_owned()],
            tenant_scoped: true,
        },
        RbacEntry {
            name: "member".to_owned(),
            description: None,
            inherits: vec![],
            allow: vec!["cp-org-read".to_owned()],
            tenant_scoped: true,
        },
    ];

    let val = rbac_entries_to_toml_value(&entries);
    let arr = val.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(
        arr[0].as_table().unwrap()["name"].as_str().unwrap(),
        "admin"
    );
    assert_eq!(
        arr[1].as_table().unwrap()["name"].as_str().unwrap(),
        "member"
    );
    assert_eq!(
        arr[2].as_table().unwrap()["name"].as_str().unwrap(),
        "owner"
    );
}

#[test]
fn rbac_entries_to_toml_value_omits_none_description() {
    let entries = vec![RbacEntry {
        name: "viewer".to_owned(),
        description: None,
        inherits: vec![],
        allow: vec!["cp-org-read".to_owned()],
        tenant_scoped: true,
    }];

    let val = rbac_entries_to_toml_value(&entries);
    let arr = val.as_array().unwrap();
    let table = arr[0].as_table().unwrap();
    assert!(
        !table.contains_key("description"),
        "description key must be absent when None"
    );
}

#[test]
fn rbac_entries_to_toml_value_preserves_array_order() {
    let entries = vec![RbacEntry {
        name: "admin".to_owned(),
        description: None,
        inherits: vec!["member".to_owned(), "viewer".to_owned()],
        allow: vec!["cp-org-write".to_owned(), "cp-org-read".to_owned()],
        tenant_scoped: true,
    }];

    let val = rbac_entries_to_toml_value(&entries);
    let arr = val.as_array().unwrap();
    let table = arr[0].as_table().unwrap();

    let inherits: Vec<&str> = table["inherits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(inherits, vec!["member", "viewer"]);

    let allow: Vec<&str> = table["allow"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(allow, vec!["cp-org-write", "cp-org-read"]);
}

// ---------------------------------------------------------------------------
// Integration test — round-trip through the Axum app
// ---------------------------------------------------------------------------

/// Synthetic RBAC fixture with action IDs in qualified (colon) form.
///
/// # Why synthetic?
///
/// The production `forgeguard.toml` stores action IDs in VP/dash form
/// (e.g. `cp-organization-read`) because Cedar policy ARN segments use
/// dashes.  The groups API, however, validates action IDs in qualified
/// colon form (e.g. `cp:organization:read`).  The dash→colon mapping is
/// lossy for multi-token actions (e.g. `cp-member-change-role` could be
/// `cp:member:change-role` or `cp:member-change:role`), so round-tripping
/// the real `forgeguard.toml` through the API is impossible without
/// format conversion.
///
/// This fixture uses colon-form action IDs that pass API validation while
/// still exercising all the important code paths: multi-level `inherits`,
/// optional `description`, Cedar filtering, and the `toml::Value` equality
/// assertion.
const SOURCE_TOML: &str = r#"
[[policies]]
name = "member"
description = "Read-only"
allow = ["cp:org:read", "cp:key:read"]

[[policies]]
name = "admin"
inherits = ["member"]
allow = ["cp:org:write", "cp:key:write", "cp:group:create"]

[[policies]]
name = "owner"
description = "Full access"
inherits = ["admin"]
allow = ["cp:org:delete"]

[[policies]]
type = "cedar"
name = "raw-policy"
body = "permit(principal, action, resource);"
"#;

/// Owned mirror of the `GroupResource` response DTO, used to deserialise
/// the JSON response from `GET /api/v1/organizations/{org_id}/groups`.
///
/// The `etag` field returned by the API is intentionally omitted here —
/// it is not part of the round-trip parity check (serde ignores unknown
/// fields by default).
#[derive(Deserialize)]
struct GroupResourceOwned {
    name: String,
    description: Option<String>,
    #[serde(default)]
    inherits: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    tenant_scoped: bool,
}

/// Verifies that RBAC entries survive a JSON POST + GET round-trip through
/// the control-plane groups API without information loss.
///
/// The test uses a synthetic inline TOML fixture (see [`SOURCE_TOML`]) with
/// action IDs in qualified colon form (`cp:org:read`), which is the format
/// the groups API validates.  One Cedar entry in the fixture is filtered out
/// before the round-trip to confirm that `extract_rbac_entries` skips it.
#[tokio::test]
async fn rbac_entries_round_trip_through_groups_api() {
    // ------------------------------------------------------------------
    // 1. Parse the inline fixture and extract RBAC entries.
    // ------------------------------------------------------------------
    let raw: RawForgeGuardToml = toml::from_str(SOURCE_TOML)
        .unwrap_or_else(|e| panic!("failed to parse SOURCE_TOML fixture: {e}"));

    let original_entries: Vec<RbacEntry> = extract_rbac_entries(raw.policies);

    assert!(
        !original_entries.is_empty(),
        "SOURCE_TOML fixture must contain at least one RBAC policy entry"
    );

    // ------------------------------------------------------------------
    // 2. Spin up the in-memory app and create a Draft org.
    // ------------------------------------------------------------------
    let store = empty_store();
    let app = test_app(Arc::clone(&store));

    let resp = create_draft_org(&app, "org-roundtrip", "Round-trip Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED, "create org failed");

    // ------------------------------------------------------------------
    // 3. POST each RBAC entry as a group.
    // ------------------------------------------------------------------
    for entry in &original_entries {
        let body_json = serde_json::json!({
            "name": entry.name,
            "description": entry.description,
            "inherits": entry.inherits,
            "allow": entry.allow,
            "tenant_scoped": entry.tenant_scoped,
        });
        let body_bytes = serde_json::to_vec(&body_json).unwrap();

        let app = test_app(Arc::clone(&store));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/organizations/org-roundtrip/groups")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(body_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST group '{}' failed with status {}",
            entry.name,
            resp.status()
        );
        assert!(
            resp.headers().get("etag").is_some(),
            "POST group '{}' must return ETag",
            entry.name
        );
    }

    // ------------------------------------------------------------------
    // 4. GET the full group list.
    // ------------------------------------------------------------------
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-roundtrip/groups")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "GET groups failed");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let resources: Vec<GroupResourceOwned> = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to deserialise GET /groups response: {e}"));

    // ------------------------------------------------------------------
    // 5. Convert response DTOs back to RbacEntry (drop etag).
    // ------------------------------------------------------------------
    let round_tripped: Vec<RbacEntry> = resources
        .into_iter()
        .map(|r| RbacEntry {
            name: r.name,
            description: r.description,
            inherits: r.inherits,
            allow: r.allow,
            tenant_scoped: r.tenant_scoped,
        })
        .collect();

    assert!(
        !round_tripped.is_empty(),
        "round-tripped group list must not be empty"
    );

    // ------------------------------------------------------------------
    // 6. Compare canonical toml::Value representations.
    // ------------------------------------------------------------------
    let expected = rbac_entries_to_toml_value(&original_entries);
    let actual = rbac_entries_to_toml_value(&round_tripped);

    assert_eq!(
        actual, expected,
        "round-tripped groups do not match original RBAC entries"
    );
}
