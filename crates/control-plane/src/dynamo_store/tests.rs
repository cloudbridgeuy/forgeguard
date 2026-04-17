use super::*;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a DynamoDB client pointing at a local DynamoDB-compatible endpoint.
///
/// Uses `DYNAMODB_ENDPOINT` env var, falling back to `http://localhost:8000`.
async fn test_client() -> aws_sdk_dynamodb::Client {
    let endpoint =
        std::env::var("DYNAMODB_ENDPOINT").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(aws_config::Region::new("us-east-1"))
        .test_credentials()
        .load()
        .await;
    aws_sdk_dynamodb::Client::new(&config)
}

/// Generate a unique table name per test run.
/// Uses an atomic counter to avoid collisions when tests run in parallel.
fn unique_table_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test-{ts}-{n}")
}

/// Create a test table using key names from the shared schema file.
/// This ensures test tables match the production CDK-provisioned table.
async fn create_test_table(client: &aws_sdk_dynamodb::Client, table_name: &str) {
    client
        .create_table()
        .table_name(table_name)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(pk())
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(sk())
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(pk())
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(sk())
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(5)
                .write_capacity_units(5)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

fn sample_config() -> OrgConfig {
    serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "todo-app",
        "upstream_url": "https://api.acme.com",
        "default_policy": "deny",
        "routes": [],
        "public_routes": [],
        "features": {}
    }))
    .unwrap()
}

#[tokio::test]
async fn create_then_get_round_trip() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Acme Corp".to_string(),
        OrgStatus::Draft,
        now,
    );
    let config = sample_config();

    // Create
    let created = store.create(org, Some(config)).await.unwrap();
    assert_eq!(created.org().name(), "Acme Corp");
    assert_eq!(created.org().status(), OrgStatus::Draft);
    assert_eq!(created.org().org_id().as_str(), "org-acme");

    // Get
    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(fetched.org().org_id().as_str(), "org-acme");
    assert_eq!(fetched.org().name(), "Acme Corp");
    assert_eq!(fetched.org().status(), OrgStatus::Draft);
    assert_eq!(
        fetched.configured().map(ConfiguredConfig::etag),
        created.configured().map(ConfiguredConfig::etag)
    );

    // Verify timestamps survive round-trip (RFC 3339 may lose sub-nanosecond)
    let diff = (fetched.org().created_at() - created.org().created_at())
        .num_milliseconds()
        .abs();
    assert!(diff < 1, "created_at should round-trip within 1ms");
}

#[tokio::test]
async fn create_without_config_round_trips_as_draft() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("org-dyn-draft").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Dyn Draft".to_string(),
        OrgStatus::Draft,
        now,
    );

    let created = store.create(org, None).await.unwrap();
    assert!(created.configured().is_none());

    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert!(fetched.configured().is_none());
    assert_eq!(fetched.org().name(), "Dyn Draft");
    assert_eq!(fetched.org().status(), OrgStatus::Draft);
}

#[tokio::test]
async fn update_promotes_draft_to_configured_dynamo() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("org-dyn-promote").unwrap();
    let org = Organization::new(org_id.clone(), "Promote".to_string(), OrgStatus::Draft, now);
    store.create(org, None).await.unwrap();

    let later = now + chrono::Duration::seconds(1);
    let updated = Organization::new(
        org_id.clone(),
        "Promote".to_string(),
        OrgStatus::Draft,
        later,
    );
    let record = store
        .update(&org_id, updated, Some(sample_config()), None)
        .await
        .unwrap();
    assert!(record.configured().is_some());

    // Re-fetch and verify
    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert!(fetched.configured().is_some());
    assert_eq!(
        fetched.configured().map(ConfiguredConfig::etag),
        record.configured().map(ConfiguredConfig::etag)
    );
}

#[tokio::test]
async fn create_duplicate_returns_conflict() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("org-dup").unwrap();
    let org1 = Organization::new(org_id.clone(), "First".to_string(), OrgStatus::Draft, now);
    let config = sample_config();

    store.create(org1, Some(config.clone())).await.unwrap();

    let org2 = Organization::new(org_id, "Second".to_string(), OrgStatus::Draft, now);
    let result = store.create(org2, Some(config)).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::Conflict(_)),
        "expected Conflict, got: {err:?}"
    );
}

#[tokio::test]
async fn get_nonexistent_returns_none() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let org_id = OrganizationId::new("org-ghost").unwrap();
    let result = store.get(&org_id).await.unwrap();
    assert!(result.is_none());
}

// -----------------------------------------------------------------------
// list() tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn list_empty_table() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let result = store.list(0, 10).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn list_returns_created_orgs() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();

    for i in 0..3 {
        let org = Organization::new(
            OrganizationId::new(format!("org-{i}")).unwrap(),
            format!("Org {i}"),
            OrgStatus::Draft,
            now,
        );
        store.create(org, Some(sample_config())).await.unwrap();
    }

    let all = store.list(0, 10).await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn list_offset_and_limit() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();

    for i in 0..3 {
        let org = Organization::new(
            OrganizationId::new(format!("org-{i}")).unwrap(),
            format!("Org {i}"),
            OrgStatus::Draft,
            now,
        );
        store.create(org, Some(sample_config())).await.unwrap();
    }

    let page = store.list(1, 1).await.unwrap();
    assert_eq!(page.len(), 1);
}

// -----------------------------------------------------------------------
// update() tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn update_existing_org() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();

    let org_id = OrganizationId::new("org-upd").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Original".to_string(),
        OrgStatus::Draft,
        now,
    );
    store.create(org, Some(sample_config())).await.unwrap();

    // Update name and config
    let later = now + chrono::Duration::seconds(1);
    let updated_org = Organization::new(
        org_id.clone(),
        "Updated".to_string(),
        OrgStatus::Active,
        later,
    );
    let new_config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj-new",
        "upstream_url": "https://updated.com",
        "default_policy": "passthrough",
        "routes": [],
        "public_routes": [],
        "features": {}
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

    // Verify via get
    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(fetched.org().name(), "Updated");
    assert_eq!(fetched.org().status(), OrgStatus::Active);
    assert_eq!(
        fetched.config().unwrap().upstream_url(),
        "https://updated.com"
    );
}

#[tokio::test]
async fn update_org_id_mismatch_returns_store_error() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();

    let org_id = OrganizationId::new("org-a").unwrap();
    let org = Organization::new(
        OrganizationId::new("org-b").unwrap(),
        "Mismatch".to_string(),
        OrgStatus::Draft,
        now,
    );

    let result = store
        .update(&org_id, org, Some(sample_config()), None)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::Store(ref msg) if msg.contains("mismatch")),
        "expected Store error with 'mismatch', got: {err:?}"
    );
}

#[tokio::test]
async fn update_nonexistent_returns_not_found() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();

    let org_id = OrganizationId::new("org-ghost").unwrap();
    let org = Organization::new(org_id.clone(), "Ghost".to_string(), OrgStatus::Draft, now);

    let result = store
        .update(&org_id, org, Some(sample_config()), None)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

// -----------------------------------------------------------------------
// delete() tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn delete_existing_org() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();

    let org_id = OrganizationId::new("org-del").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "To Delete".to_string(),
        OrgStatus::Draft,
        now,
    );
    store.create(org, Some(sample_config())).await.unwrap();

    store.delete(&org_id).await.unwrap();
    assert!(store.get(&org_id).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_nonexistent_is_ok() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);

    let org_id = OrganizationId::new("org-nope").unwrap();
    let result = store.delete(&org_id).await;
    assert!(result.is_ok());
}

// -----------------------------------------------------------------------
// Signing key tests
// -----------------------------------------------------------------------

/// Helper: create a store with a single org already inserted.
async fn store_with_org(org_id_str: &str) -> (DynamoOrgStore, OrganizationId) {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let now = chrono::Utc::now();
    let org_id = OrganizationId::new(org_id_str).unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Test Org".to_string(),
        OrgStatus::Draft,
        now,
    );
    store.create(org, Some(sample_config())).await.unwrap();
    (store, org_id)
}

#[tokio::test]
async fn generate_key_round_trip() {
    use crate::signing_key::SigningKeyStatus;

    let (store, org_id) = store_with_org("org-keygen").await;

    let result = store.generate_key(&org_id).await.unwrap();
    assert!(!result.key_id().is_empty());
    assert!(result.private_key_pem().contains("PRIVATE KEY"));
    assert!(result.public_key_pem().contains("PUBLIC KEY"));

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id(), result.key_id());
    assert_eq!(keys[0].public_key_pem(), result.public_key_pem());
    assert_eq!(*keys[0].status(), SigningKeyStatus::Active);
}

#[tokio::test]
async fn revoke_key_sets_status() {
    use crate::signing_key::SigningKeyStatus;

    let (store, org_id) = store_with_org("org-revoke").await;

    let generated = store.generate_key(&org_id).await.unwrap();
    store.revoke_key(&org_id, generated.key_id()).await.unwrap();

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(*keys[0].status(), SigningKeyStatus::Revoked);
}

#[tokio::test]
async fn revoke_nonexistent_key_returns_error() {
    let (store, org_id) = store_with_org("org-rev-bad").await;

    // Generate one key, then try to revoke a different key_id.
    store.generate_key(&org_id).await.unwrap();

    let result = store.revoke_key(&org_id, "key-nonexistent").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn generate_key_on_nonexistent_org_fails() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client, table);
    let org_id = OrganizationId::new("org-ghost").unwrap();

    let result = store.generate_key(&org_id).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn list_keys_on_empty_org_returns_empty() {
    let (store, org_id) = store_with_org("org-nokeys").await;

    let keys = store.list_keys(&org_id).await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn update_org_preserves_signing_keys() {
    use crate::signing_key::SigningKeyStatus;

    let (store, org_id) = store_with_org("org-preserve").await;

    // Generate a signing key
    let generated = store.generate_key(&org_id).await.unwrap();

    // Update the org config (full item replacement via PutItem)
    let now = chrono::Utc::now();
    let updated_org = Organization::new(
        org_id.clone(),
        "Renamed Org".to_string(),
        OrgStatus::Active,
        now,
    );
    let new_config: OrgConfig = serde_json::from_value(serde_json::json!({
        "version": "2026-04-07",
        "project_id": "proj-updated",
        "upstream_url": "https://updated.example.com",
        "default_policy": "deny",
        "routes": [],
        "public_routes": [],
        "features": {}
    }))
    .unwrap();

    store
        .update(&org_id, updated_org, Some(new_config), None)
        .await
        .unwrap();

    // Verify signing keys survived the update
    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 1, "signing key must survive org update");
    assert_eq!(keys[0].key_id(), generated.key_id());
    assert_eq!(keys[0].public_key_pem(), generated.public_key_pem());
    assert_eq!(*keys[0].status(), SigningKeyStatus::Active);

    // Also verify the org fields were actually updated
    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert_eq!(fetched.org().name(), "Renamed Org");
    assert_eq!(fetched.org().status(), OrgStatus::Active);
}
