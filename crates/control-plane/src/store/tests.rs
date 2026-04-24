#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::signing_key::SigningKeyStatus;

fn sample_json() -> &'static str {
    r#"{
            "organizations": {
                "org-acme": {
                    "name": "Acme Corp",
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
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "proj-a",
                        "upstream_url": "https://alpha.com",
                        "default_policy": "deny"
                    }
                },
                "org-beta": {
                    "name": "Beta LLC",
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
}

#[test]
fn compute_etag_deterministic() {
    let store = build_org_store(sample_json()).unwrap();
    // Access the inner map synchronously for this test
    let guard = store.orgs.try_read().unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = guard.get(&org_id).unwrap();
    let config = record.config().unwrap();

    let etag1 = compute_etag(config).unwrap();
    let etag2 = compute_etag(config).unwrap();
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
    assert!(store.get(&org_id).await.unwrap().is_some());
}

#[test]
fn compute_etag_quoted_hex_format() {
    let store = build_org_store(sample_json()).unwrap();
    let guard = store.orgs.try_read().unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = guard.get(&org_id).unwrap();
    let config = record.config().unwrap();

    let etag = compute_etag(config).unwrap();
    // 16 hex chars + 2 quote chars = 18
    assert_eq!(etag.len(), 18, "ETag should be 18 chars, got: {etag}");
    assert!(
        etag.starts_with('"'),
        "ETag should start with quote: {etag}"
    );
    assert!(etag.ends_with('"'), "ETag should end with quote: {etag}");
    // Inner part is hex
    let inner = &etag[1..17];
    assert!(
        inner.chars().all(|c| c.is_ascii_hexdigit()),
        "ETag inner should be hex: {inner}"
    );
}

#[tokio::test]
async fn create_org_success() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org = Organization::new(
        OrganizationId::new("org-new").unwrap(),
        "New Org".to_string(),
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

    let record = store.create(org, Some(config)).await.unwrap();
    assert_eq!(record.org().name(), "New Org");
    assert_eq!(record.org().status(), OrgStatus::Draft);

    // Verify it's retrievable
    let fetched = store
        .get(&OrganizationId::new("org-new").unwrap())
        .await
        .unwrap();
    assert!(fetched.is_some());
}

#[tokio::test]
async fn create_org_without_config_round_trips_as_draft() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org = Organization::new(
        OrganizationId::new("org-draft").unwrap(),
        "Draft Org".to_string(),
        OrgStatus::Draft,
        now,
    );

    let record = store.create(org, None).await.unwrap();
    assert!(record.configured().is_none(), "configured should be None");

    // Re-fetch
    let fetched = store
        .get(&OrganizationId::new("org-draft").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(fetched.configured().is_none());
    assert_eq!(fetched.org().status(), OrgStatus::Draft);
}

#[tokio::test]
async fn update_promotes_draft_to_configured() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org_id = OrganizationId::new("org-promote").unwrap();
    let org = Organization::new(org_id.clone(), "Promote".to_string(), OrgStatus::Draft, now);
    store.create(org, None).await.unwrap();

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

    let record = store
        .update(&org_id, updated_org, Some(config), None)
        .await
        .unwrap();
    assert!(record.configured().is_some());
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
async fn create_org_duplicate_fails() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj",
        "upstream_url": "https://example.com",
        "default_policy": "deny"
    }))
    .unwrap();

    let org1 = Organization::new(
        OrganizationId::new("org-dup").unwrap(),
        "First".to_string(),
        OrgStatus::Draft,
        now,
    );
    store.create(org1, Some(config.clone())).await.unwrap();

    let org2 = Organization::new(
        OrganizationId::new("org-dup").unwrap(),
        "Second".to_string(),
        OrgStatus::Draft,
        now,
    );
    let result = store.create(org2, Some(config)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn list_orgs_empty() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let result = store.list(0, 10).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn update_org_success() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org = Organization::new(
        OrganizationId::new("org-upd").unwrap(),
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
    store.create(org, Some(config)).await.unwrap();

    let org_id = OrganizationId::new("org-upd").unwrap();
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

    let record = store
        .update(&org_id, updated_org, Some(new_config), None)
        .await
        .unwrap();
    assert_eq!(record.org().name(), "Updated");
    assert_eq!(
        record.config().unwrap().upstream_url(),
        "https://updated.com"
    );
}

#[tokio::test]
async fn update_org_not_found() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let org_id = OrganizationId::new("org-missing").unwrap();
    let now = Utc::now();
    let org = Organization::new(org_id.clone(), "Ghost".to_string(), OrgStatus::Draft, now);
    let config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj",
        "upstream_url": "https://example.com",
        "default_policy": "deny"
    }))
    .unwrap();

    let result = store.update(&org_id, org, Some(config), None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn delete_org_success() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    let org = Organization::new(
        OrganizationId::new("org-del").unwrap(),
        "To Delete".to_string(),
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
    store.create(org, Some(config)).await.unwrap();

    let org_id = OrganizationId::new("org-del").unwrap();
    store.delete(&org_id).await.unwrap();
    assert!(store.get(&org_id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_org_not_found() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let org_id = OrganizationId::new("org-nope").unwrap();
    let result = store.delete(&org_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn list_orgs_with_pagination() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let now = Utc::now();
    // Create 3 orgs
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
        store.create(org, Some(config)).await.unwrap();
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
    let configured = ConfiguredConfig::compute(config).unwrap();
    let record = OrgRecord::new(org, Some(configured));
    store
        .orgs
        .try_write()
        .unwrap()
        .insert(OrganizationId::new(org_id_str).unwrap(), record);
    store
}

#[tokio::test]
async fn generate_key_happy_path() {
    let store = make_store_with_org("org-keys");
    let org_id = OrganizationId::new("org-keys").unwrap();

    let result = store.generate_key(&org_id).await.unwrap();
    assert!(!result.key_id().is_empty());
    assert!(result.private_key_pem().contains("PRIVATE KEY"));
    assert!(result.public_key_pem().contains("PUBLIC KEY"));
    assert!(result.created_at() <= Utc::now());
}

#[tokio::test]
async fn generate_key_nonexistent_org_returns_error() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let org_id = OrganizationId::new("org-ghost").unwrap();

    let result = store.generate_key(&org_id).await;
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn list_keys_returns_generated_keys() {
    let store = make_store_with_org("org-list");
    let org_id = OrganizationId::new("org-list").unwrap();

    store.generate_key(&org_id).await.unwrap();
    store.generate_key(&org_id).await.unwrap();

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
async fn revoke_key_happy_path() {
    let store = make_store_with_org("org-revoke");
    let org_id = OrganizationId::new("org-revoke").unwrap();

    let generated = store.generate_key(&org_id).await.unwrap();
    store.revoke_key(&org_id, generated.key_id()).await.unwrap();

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(*keys[0].status(), SigningKeyStatus::Revoked);
}

#[tokio::test]
async fn revoke_key_nonexistent_org_returns_error() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let org_id = OrganizationId::new("org-ghost").unwrap();

    let result = store.revoke_key(&org_id, "key-abc").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn revoke_key_nonexistent_key_returns_error() {
    let store = make_store_with_org("org-badkey");
    let org_id = OrganizationId::new("org-badkey").unwrap();

    // Generate one key, then try to revoke a different key_id
    store.generate_key(&org_id).await.unwrap();

    let result = store.revoke_key(&org_id, "key-nonexistent").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

// ---------------------------------------------------------------------
// Optimistic-locking tests (issue #56, V1)
// ---------------------------------------------------------------------

#[tokio::test]
async fn update_with_matching_expected_etag_succeeds() {
    let store = build_org_store(sample_json()).unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();

    let record = store.get(&org_id).await.unwrap().unwrap();
    let current_etag = record
        .configured()
        .expect("sample has config")
        .etag()
        .to_string();

    let new_config = record.config().cloned();
    let new_org = record.org().clone();
    let updated = store
        .update(&org_id, new_org, new_config, Some(&current_etag))
        .await
        .unwrap();

    // Same content → same etag.
    assert_eq!(updated.configured().unwrap().etag(), current_etag);
}

#[tokio::test]
async fn update_with_stale_expected_etag_returns_precondition_failed() {
    let store = build_org_store(sample_json()).unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();

    let result = store
        .update(
            &org_id,
            record.org().clone(),
            record.config().cloned(),
            Some("\"definitely-not-the-etag\""),
        )
        .await;

    match result {
        Err(Error::PreconditionFailed { current_etag }) => {
            assert_eq!(current_etag, record.configured().unwrap().etag());
        }
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn update_without_expected_etag_writes_unconditionally() {
    let store = build_org_store(sample_json()).unwrap();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();

    let updated = store
        .update(
            &org_id,
            record.org().clone(),
            record.config().cloned(),
            None,
        )
        .await
        .unwrap();
    assert!(updated.configured().is_some());
}

#[tokio::test]
async fn update_draft_with_expected_etag_fails_with_empty_current() {
    let json = r#"{
            "organizations": {
                "org-draft": {
                    "name": "Draft Org"
                }
            }
        }"#;
    let store = build_org_store(json).unwrap();
    let org_id = OrganizationId::new("org-draft").unwrap();
    let record = store.get(&org_id).await.unwrap().unwrap();

    let result = store
        .update(&org_id, record.org().clone(), None, Some("\"anything\""))
        .await;

    match result {
        Err(Error::PreconditionFailed { current_etag }) => {
            assert!(current_etag.is_empty(), "Draft has no etag");
        }
        other => panic!("expected PreconditionFailed with empty current, got {other:?}"),
    }
}

#[tokio::test]
async fn rotate_signing_key_happy_path() {
    let store = make_store_with_org("org-rotate");
    let org_id = OrganizationId::new("org-rotate").unwrap();

    let original = store.generate_key(&org_id).await.unwrap();
    let rotated = store
        .rotate_signing_key(&org_id, original.key_id())
        .await
        .unwrap();

    assert_ne!(rotated.key_id(), original.key_id());
    assert!(rotated.private_key_pem().contains("PRIVATE KEY"));

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 2);

    let old = keys
        .iter()
        .find(|k| k.key_id() == original.key_id())
        .unwrap();
    assert!(matches!(old.status(), SigningKeyStatus::Rotating { .. }));

    let new = keys
        .iter()
        .find(|k| k.key_id() == rotated.key_id())
        .unwrap();
    assert!(matches!(new.status(), SigningKeyStatus::Active));
}

#[tokio::test]
async fn rotate_signing_key_nonexistent_org_returns_not_found() {
    let store = InMemoryOrgStore::new(BTreeMap::new());
    let org_id = OrganizationId::new("org-ghost").unwrap();
    let err = store
        .rotate_signing_key(&org_id, "key-abc")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got: {err:?}");
}

#[tokio::test]
async fn rotate_signing_key_nonexistent_key_returns_not_found() {
    let store = make_store_with_org("org-rot-miss");
    let org_id = OrganizationId::new("org-rot-miss").unwrap();
    let err = store
        .rotate_signing_key(&org_id, "key-missing")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got: {err:?}");
}

#[tokio::test]
async fn rotate_signing_key_revoked_target_returns_conflict() {
    let store = make_store_with_org("org-rot-revoked");
    let org_id = OrganizationId::new("org-rot-revoked").unwrap();

    let generated = store.generate_key(&org_id).await.unwrap();
    store.revoke_key(&org_id, generated.key_id()).await.unwrap();

    let err = store
        .rotate_signing_key(&org_id, generated.key_id())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Conflict(_)), "got: {err:?}");
}

#[tokio::test]
async fn rotate_signing_key_rotating_target_returns_conflict() {
    let store = make_store_with_org("org-rot-double");
    let org_id = OrganizationId::new("org-rot-double").unwrap();

    let generated = store.generate_key(&org_id).await.unwrap();
    store
        .rotate_signing_key(&org_id, generated.key_id())
        .await
        .unwrap();

    // Second rotation of the now-Rotating key → 409
    let err = store
        .rotate_signing_key(&org_id, generated.key_id())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Conflict(_)), "got: {err:?}");
}
