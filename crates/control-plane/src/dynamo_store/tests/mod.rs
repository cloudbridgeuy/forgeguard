use super::*;
use crate::model_event_store::DynamoModelEventStore;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;

/// DynamoDB Local accepts TCP connections before its SQLite engine is fully
/// warm, so the first burst of parallel requests can fail with
/// `Connection reset by peer`. This probe runs once per process and retries an
/// idempotent `ListTables` until it succeeds.
async fn warm_engine_once(client: &aws_sdk_dynamodb::Client) {
    static WARMED: OnceCell<()> = OnceCell::const_new();
    WARMED
        .get_or_init(|| async {
            const MAX_ATTEMPTS: u32 = 25;
            const BACKOFF: Duration = Duration::from_millis(200);
            let mut last_err = None;
            for _ in 0..MAX_ATTEMPTS {
                match client.list_tables().send().await {
                    Ok(_) => return,
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(BACKOFF).await;
                    }
                }
            }
            panic!(
                "DynamoDB Local did not become ready after {MAX_ATTEMPTS} attempts: {:?}",
                last_err
            );
        })
        .await;
}

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
    let client = aws_sdk_dynamodb::Client::new(&config);
    warm_engine_once(&client).await;
    client
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

/// Write an org item directly via `PutItem` (bypassing the retired
/// `OrgStore::create`/`update`/`delete` — org writes now flow through
/// `ModelEventStore`; these `DynamoOrgStore` read-path tests only need a row
/// present in the shared table).
async fn put_test_org(
    client: &aws_sdk_dynamodb::Client,
    table: &str,
    org: &Organization,
    config: Option<OrgConfig>,
) {
    let configured = config.map(crate::store::ConfiguredConfig::compute);
    let item = crate::dynamo_store::to_item(org, configured.as_ref(), &[]).unwrap();
    client
        .put_item()
        .table_name(table)
        .set_item(Some(item))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn create_then_get_round_trip() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client.clone(), table.clone());

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("org-acme").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Acme Corp".to_string(),
        OrgStatus::Draft,
        now,
    );
    let config = sample_config();

    // Seed
    put_test_org(&client, &table, &org, Some(config)).await;
    let created = store.get(&org_id).await.unwrap().unwrap();
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

    let store = DynamoOrgStore::new(client.clone(), table.clone());

    let now = chrono::Utc::now();
    let org_id = OrganizationId::new("org-dyn-draft").unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Dyn Draft".to_string(),
        OrgStatus::Draft,
        now,
    );

    put_test_org(&client, &table, &org, None).await;
    let created = store.get(&org_id).await.unwrap().unwrap();
    assert!(created.configured().is_none());

    let fetched = store.get(&org_id).await.unwrap().unwrap();
    assert!(fetched.configured().is_none());
    assert_eq!(fetched.org().name(), "Dyn Draft");
    assert_eq!(fetched.org().status(), OrgStatus::Draft);
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

    let store = DynamoOrgStore::new(client.clone(), table.clone());
    let now = chrono::Utc::now();

    for i in 0..3 {
        let org = Organization::new(
            OrganizationId::new(format!("org-{i}")).unwrap(),
            format!("Org {i}"),
            OrgStatus::Draft,
            now,
        );
        put_test_org(&client, &table, &org, Some(sample_config())).await;
    }

    let all = store.list(0, 10).await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn list_offset_and_limit() {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client.clone(), table.clone());
    let now = chrono::Utc::now();

    for i in 0..3 {
        let org = Organization::new(
            OrganizationId::new(format!("org-{i}")).unwrap(),
            format!("Org {i}"),
            OrgStatus::Draft,
            now,
        );
        put_test_org(&client, &table, &org, Some(sample_config())).await;
    }

    let page = store.list(1, 1).await.unwrap();
    assert_eq!(page.len(), 1);
}

// -----------------------------------------------------------------------
// Signing key tests
// -----------------------------------------------------------------------

/// Helper: create a store with a single org already inserted.
async fn store_with_org(org_id_str: &str) -> (DynamoOrgStore, OrganizationId) {
    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let store = DynamoOrgStore::new(client.clone(), table.clone());
    let now = chrono::Utc::now();
    let org_id = OrganizationId::new(org_id_str).unwrap();
    let org = Organization::new(
        org_id.clone(),
        "Test Org".to_string(),
        OrgStatus::Draft,
        now,
    );
    put_test_org(&client, &table, &org, Some(sample_config())).await;
    (store, org_id)
}

/// Seed `org_id`'s keys by writing through
/// [`crate::model_event_store::DynamoModelEventStore`], mirroring how
/// production wires `DynamoOrgStore`/`DynamoModelEventStore` onto one shared
/// table: key mutations are `ModelEventStore`-only now, so `OrgStore::list_keys`
/// here is exercised only as the read side of that write-through.
fn model_events_for(client: &aws_sdk_dynamodb::Client, table: &str) -> DynamoModelEventStore {
    DynamoModelEventStore::new(client.clone(), table.to_string())
}

#[tokio::test]
async fn generate_key_round_trip() {
    use crate::model_event_store::ModelEventStore;
    use crate::signing_key::SigningKeyStatus;

    let (store, org_id) = store_with_org("org-keygen").await;
    let model_events = model_events_for(&store.client, &store.table_name);

    let (result, _revision) = model_events
        .generate_org_key(org_id.as_str(), forgeguard_authz_core::Actor::System)
        .await
        .unwrap();
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
    use crate::model_event_store::ModelEventStore;
    use crate::signing_key::SigningKeyStatus;

    let (store, org_id) = store_with_org("org-revoke").await;
    let model_events = model_events_for(&store.client, &store.table_name);

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

#[tokio::test]
async fn revoke_nonexistent_key_is_noop() {
    use crate::model_event_store::ModelEventStore;

    let (store, org_id) = store_with_org("org-rev-bad").await;
    let model_events = model_events_for(&store.client, &store.table_name);

    // Generate one key, then try to revoke a different key_id — D6 no-op.
    model_events
        .generate_org_key(org_id.as_str(), forgeguard_authz_core::Actor::System)
        .await
        .unwrap();

    let result = model_events
        .revoke_org_key(
            org_id.as_str(),
            "key-nonexistent",
            forgeguard_authz_core::Actor::System,
        )
        .await
        .unwrap();
    assert!(result.is_none());

    let keys = store.list_keys(&org_id).await.unwrap();
    assert_eq!(keys.len(), 1);
}

#[tokio::test]
async fn generate_key_on_nonexistent_org_fails() {
    use crate::model_event_store::ModelEventStore;

    let client = test_client().await;
    let table = unique_table_name();
    create_test_table(&client, &table).await;

    let model_events = model_events_for(&client, &table);
    let org_id = OrganizationId::new("org-ghost").unwrap();

    let result = model_events
        .generate_org_key(org_id.as_str(), forgeguard_authz_core::Actor::System)
        .await;
    match result {
        Err(Error::NotFound(_)) => {}
        Err(other) => panic!("expected NotFound, got: {other:?}"),
        // `GenerateKeyResult` intentionally has no `Debug` impl to keep the
        // private key out of test output, so handle `Ok` without printing it.
        Ok(_) => panic!("expected NotFound, got Ok(_)"),
    }
}

#[tokio::test]
async fn list_keys_on_empty_org_returns_empty() {
    let (store, org_id) = store_with_org("org-nokeys").await;

    let keys = store.list_keys(&org_id).await.unwrap();
    assert!(keys.is_empty());
}

mod groups;
mod user_schema;
