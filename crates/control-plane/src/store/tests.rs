#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use super::*;
use crate::model_event_store::ModelEventStore;
use crate::signing_key::SigningKeyStatus;

fn sample_json() -> &'static str {
    r#"{
            "organizations": {
                "org-acme": {
                    "name": "Acme Corp",
                    "status": "active",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "todo-app",
                        "upstream_url": "https://api.acme.com",
                        "default_policy": "deny",
                        "routes": [],
                        "public_routes": [],
                        "features": {}
                    }
                }
            }
        }"#
}

#[tokio::test]
async fn build_org_store_valid_json() {
    let store = build_org_store(sample_json()).unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();
    let config = record.config().unwrap();
    assert_eq!(config.upstream_url(), "https://api.acme.com");
    assert_eq!(
        config.default_policy(),
        forgeguard_core::DefaultPolicy::Deny
    );
    assert_eq!(record.org().name(), "Acme Corp");
    assert_eq!(record.org().status(), OrgStatus::Active);
}

#[test]
fn build_org_store_invalid_json() {
    let result = build_org_store("not json at all {{{");
    assert!(result.is_err());
}

#[test]
fn build_org_store_invalid_org_id() {
    let json = r#"{
            "organizations": {
                "UPPER-CASE": {
                    "name": "Bad Org",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "proj",
                        "upstream_url": "https://example.com",
                        "default_policy": "deny"
                    }
                }
            }
        }"#;
    let result = build_org_store(json);
    assert!(result.is_err());
}

#[tokio::test]
async fn build_org_store_empty_organizations() {
    let json = r#"{ "organizations": {} }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    assert!(store.get(&org_id).await.unwrap().is_none());
}

#[tokio::test]
async fn build_org_store_multiple_orgs() {
    let json = r#"{
            "organizations": {
                "org-alpha": {
                    "name": "Alpha Inc",
                    "status": "active",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "proj-a",
                        "upstream_url": "https://alpha.com",
                        "default_policy": "deny"
                    }
                },
                "org-beta": {
                    "name": "Beta LLC",
                    "status": "active",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "proj-b",
                        "upstream_url": "https://beta.com",
                        "default_policy": "passthrough"
                    }
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let alpha = OrganizationId::new("org-alpha").unwrap();
    let beta = OrganizationId::new("org-beta").unwrap();
    assert!(store.get(&alpha).await.unwrap().is_some());
    assert!(store.get(&beta).await.unwrap().is_some());
    let alpha_record = store.get(&alpha).await.unwrap().unwrap();
    let beta_record = store.get(&beta).await.unwrap().unwrap();
    assert_eq!(
        alpha_record.config().unwrap().upstream_url(),
        "https://alpha.com"
    );
    assert_eq!(
        beta_record.config().unwrap().default_policy(),
        forgeguard_core::DefaultPolicy::Passthrough
    );
    assert_eq!(alpha_record.org().status(), OrgStatus::Active);
    assert_eq!(beta_record.org().status(), OrgStatus::Active);
}

#[test]
fn compute_etag_deterministic() {
    let store = build_org_store(sample_json()).unwrap();
    // Access the inner map synchronously for this test
    let guard = store.orgs.try_read().unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = guard.get(&org_id).unwrap();
    let config = record.config().unwrap();

    let etag1 = compute_etag(config);
    let etag2 = compute_etag(config);
    assert_eq!(etag1, etag2);
}

#[tokio::test]
async fn build_org_store_ignores_unknown_fields() {
    let json = r#"{
            "organizations": {
                "org-acme": {
                    "name": "Acme Corp",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "todo-app",
                        "upstream_url": "https://api.acme.com",
                        "default_policy": "deny",
                        "extra_field": "ignored"
                    }
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(record.org().status(), OrgStatus::Draft);
}

#[test]
fn compute_etag_quoted_hex_format() {
    let store = build_org_store(sample_json()).unwrap();
    let guard = store.orgs.try_read().unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = guard.get(&org_id).unwrap();
    let config = record.config().unwrap();

    let etag = compute_etag(config);
    let etag_str = etag.as_str();
    // 16 hex chars + 2 quote chars = 18
    assert_eq!(
        etag_str.len(),
        18,
        "ETag should be 18 chars, got: {etag_str}"
    );
    assert!(
        etag_str.starts_with('"'),
        "ETag should start with quote: {etag_str}"
    );
    assert!(
        etag_str.ends_with('"'),
        "ETag should end with quote: {etag_str}"
    );
    // Inner part is hex
    let inner = &etag_str[1..17];
    assert!(
        inner.chars().all(|c| c.is_ascii_hexdigit()),
        "ETag inner should be hex: {inner}"
    );
}

#[tokio::test]
async fn write_through_org_creates_new_row() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org_id = OrganizationId::new("org-new").unwrap();
    let org = Organization::new(org_id.clone(), "New Org".to_string(), OrgStatus::Draft, now);
    let config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj",
        "upstream_url": "https://example.com",
        "default_policy": "deny"
    }))
    .unwrap();

    store.write_through_org(org, Some(config)).await;

    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(fetched.org().name(), "New Org");
    assert_eq!(fetched.org().status(), OrgStatus::Draft);
}

#[tokio::test]
async fn write_through_org_without_config_round_trips_as_draft() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org_id = OrganizationId::new("org-draft").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Draft Org".to_string(),
        OrgStatus::Draft,
        now,
    );

    store.write_through_org(org, None).await;

    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert!(fetched.configured().is_none());
    assert_eq!(fetched.org().status(), OrgStatus::Draft);
}

#[tokio::test]
async fn write_through_org_upsert_promotes_draft_to_configured() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org_id = OrganizationId::new("org-promote").unwrap();
    let org = Organization::new(org_id.clone(), "Promote".to_string(), OrgStatus::Draft, now);
    store.write_through_org(org, None).await;

    let later = now + chrono::Duration::seconds(1);
    let updated_org = Organization::new(
        org_id.clone(),
        "Promote".to_string(),
        OrgStatus::Draft,
        later,
    );
    let config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "p",
        "upstream_url": "https://example.com",
        "default_policy": "deny"
    }))
    .unwrap();

    store.write_through_org(updated_org, Some(config)).await;

    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert!(fetched.configured().is_some());
}

#[tokio::test]
async fn build_org_store_draft_entry_without_config() {
    let json = r#"{
            "organizations": {
                "org-seeded-draft": {
                    "name": "Seeded Draft"
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-seeded-draft").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();
    assert!(record.config().is_none());
    assert_eq!(record.org().status(), OrgStatus::Draft);
}

#[tokio::test]
async fn build_org_store_status_omitted_with_config_defaults_to_draft() {
    // Loader heuristic dropped in V5: config presence no longer implies Active.
    let json = r#"{
            "organizations": {
                "org-no-status": {
                    "name": "No Status",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "p",
                        "upstream_url": "https://example.com",
                        "default_policy": "deny"
                    }
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-no-status").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();
    assert!(record.config().is_some(), "config is populated");
    assert_eq!(
        record.org().status(),
        OrgStatus::Draft,
        "status defaults to Draft when omitted, even with config"
    );
}

#[tokio::test]
async fn build_org_store_status_active_explicit() {
    let json = r#"{
            "organizations": {
                "org-active": {
                    "name": "Active",
                    "status": "active",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "p",
                        "upstream_url": "https://example.com",
                        "default_policy": "deny"
                    }
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-active").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(record.org().status(), OrgStatus::Active);
}

#[tokio::test]
async fn build_org_store_status_draft_explicit_with_config() {
    // The heuristic is gone — declared status is the only source of truth.
    let json = r#"{
            "organizations": {
                "org-draft-with-cfg": {
                    "name": "Draft With Config",
                    "status": "draft",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "p",
                        "upstream_url": "https://example.com",
                        "default_policy": "deny"
                    }
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-draft-with-cfg").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();
    assert!(record.config().is_some());
    assert_eq!(record.org().status(), OrgStatus::Draft);
}

#[tokio::test]
async fn list_orgs_empty() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let result = store.list(0, 10).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn write_through_org_upsert_replaces_existing_row() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org_id = OrganizationId::new("org-upd").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Original".to_string(),
        OrgStatus::Draft,
        now,
    );
    let config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj",
        "upstream_url": "https://example.com",
        "default_policy": "deny"
    }))
    .unwrap();
    store.write_through_org(org, Some(config)).await;

    let later = now + chrono::Duration::seconds(1);
    let updated_org = Organization::new(
        org_id.clone(),
        "Updated".to_string(),
        OrgStatus::Draft,
        later,
    );
    let new_config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj-new",
        "upstream_url": "https://updated.com",
        "default_policy": "passthrough"
    }))
    .unwrap();

    store.write_through_org(updated_org, Some(new_config)).await;

    let record = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(record.org().name(), "Updated");
    assert_eq!(
        record.config().unwrap().upstream_url(),
        "https://updated.com"
    );
}

#[tokio::test]
async fn list_orgs_with_pagination() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    // Seed 3 orgs
    for i in 0..3 {
        let org = Organization::new(
            OrganizationId::new(format!("org-{i}")).unwrap(),
            format!("Org {i}"),
            OrgStatus::Draft,
            now,
        );
        let config: OrgConfig = serde_json::from_value(serde_json::json!({
            "version": "2026-04-07",
            "project_id": format!("proj-{i}"),
            "upstream_url": "https://example.com",
            "default_policy": "deny"
        }))
        .unwrap();
        store.write_through_org(org, Some(config)).await;
    }

    // List all
    let all = store.list(0, 10).await.unwrap();
    assert_eq!(all.len(), 3);

    // List with limit
    let page = store.list(0, 2).await.unwrap();
    assert_eq!(page.len(), 2);

    // List with offset past end
    let empty = store.list(10, 10).await.unwrap();
    assert!(empty.is_empty());
}

// -- Signing key tests --

fn make_store_with_org(org_id_str: &str) -> InMemoryOrgStore {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org = Organization::new(
        OrganizationId::new(org_id_str).unwrap(),
        "Test Org".to_string(),
        OrgStatus::Draft,
        now,
    );
    let config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj",
        "upstream_url": "https://example.com",
        "default_policy": "deny"
    }))
    .unwrap();
    let configured = ConfiguredConfig::compute(config);
    let record = OrgRecord::new(org, Some(configured));
    store
        .orgs
        .try_write()
        .unwrap()
        .insert(OrganizationId::new(org_id_str).unwrap(), record);
    store
}

/// Seed `org_id_str`'s keys by writing through
/// [`crate::model_event_store::ModelEventStore`], mirroring how production
/// wires `DynamoOrgStore`/`DynamoModelEventStore` onto one shared table: key
/// mutations are `ModelEventStore`-only now (see
/// `model_event_store::in_memory_tests` for the write-path coverage), so
/// `OrgStore::list_keys` here is exercised only as the read side of that
/// write-through.
async fn model_events_for(
    store: &Arc<InMemoryOrgStore>,
    org_id: &OrganizationId,
) -> crate::model_event_store::InMemoryModelEventStore {
    let record = store.get(org_id).await.unwrap().unwrap();
    let model_events = crate::model_event_store::InMemoryModelEventStore::new_with_org_store(
        Arc::clone(store) as Arc<dyn OrgStore>,
    );
    model_events
        .create_org(record, forgeguard_authz_core::Actor::System)
        .await
        .unwrap();
    model_events
}

#[tokio::test]
async fn list_keys_returns_generated_keys() {
    let store = Arc::new(make_store_with_org("org-list"));
    let org_id = OrganizationId::new("org-list").unwrap();
    let model_events = model_events_for(&store, &org_id).await;

    model_events
        .generate_org_key(org_id.as_str(), forgeguard_authz_core::Actor::System)
        .await
        .unwrap();
    model_events
        .generate_org_key(org_id.as_str(), forgeguard_authz_core::Actor::System)
        .await
        .unwrap();

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 2);
}

#[tokio::test]
async fn list_keys_no_keys_returns_empty() {
    let store = make_store_with_org("org-empty");
    let org_id = OrganizationId::new("org-empty").unwrap();

    let keys = store.list_keys(&org_id).await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn revoke_key_write_through_updates_list_keys() {
    let store = Arc::new(make_store_with_org("org-revoke"));
    let org_id = OrganizationId::new("org-revoke").unwrap();
    let model_events = model_events_for(&store, &org_id).await;

    let (generated, _revision) = model_events
        .generate_org_key(org_id.as_str(), forgeguard_authz_core::Actor::System)
        .await
        .unwrap();
    model_events
        .revoke_org_key(
            org_id.as_str(),
            generated.key_id(),
            forgeguard_authz_core::Actor::System,
        )
        .await
        .unwrap();

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(*keys[0].status(), SigningKeyStatus::Revoked);
}

// =============================================================================
// Group CRUD tests (V2) — see tests/groups.rs
// =============================================================================

mod groups;

// =============================================================================
// User schema CRUD tests (issue #100 V2) — see tests/user_schema.rs
// =============================================================================

mod user_schema;
