//! DynamoDB-backed organization store.
//!
//! Activated via `--store=dynamodb --dynamodb-table <TABLE>` on the
//! control-plane binary.
//!
//! Key attribute names (`PK`, `SK`) are read from the shared schema file
//! at `infra/control-plane/schema/dynamodb.json` — the single source of
//! truth consumed by both CDK (TypeScript) and Rust.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use forgeguard_core::{OrgStatus, Organization, OrganizationId};

use crate::config::OrgConfig;
use crate::error::{Error, Result};
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};
use crate::store::{compute_etag, OrgRecord, OrgStore};

// ---------------------------------------------------------------------------
// Key schema — single source of truth from shared JSON
// ---------------------------------------------------------------------------

/// Parsed DynamoDB key schema from the shared JSON file.
#[derive(serde::Deserialize)]
struct KeySchema {
    #[serde(rename = "partitionKey")]
    partition_key: String,
    #[serde(rename = "sortKey")]
    sort_key: String,
}

/// Schema JSON baked in at compile time. Build fails if the file is missing.
const SCHEMA_JSON: &str = include_str!("../../../infra/control-plane/schema/dynamodb.json");

fn key_schema() -> &'static KeySchema {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<KeySchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        // Safety: the JSON is baked in at compile time via include_str!.
        // A parse failure here means the checked-in file is malformed —
        // a programmer error, not a runtime condition.
        match serde_json::from_str(SCHEMA_JSON) {
            Ok(s) => s,
            Err(e) => {
                // OnceLock requires a value, not a Result.
                // This is a compile-time-embedded constant; log and abort.
                tracing::error!("BUG: dynamodb.json schema is invalid: {e}");
                std::process::abort();
            }
        }
    })
}

/// Partition key attribute name (e.g. `"PK"`).
fn pk() -> &'static str {
    &key_schema().partition_key
}

/// Sort key attribute name (e.g. `"SK"`).
fn sk() -> &'static str {
    &key_schema().sort_key
}

const SK_META: &str = "META";
const ORG_PREFIX: &str = "ORG#";

// ---------------------------------------------------------------------------
// DynamoOrgStore
// ---------------------------------------------------------------------------

/// DynamoDB-backed organization store.
pub(crate) struct DynamoOrgStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoOrgStore {
    pub(crate) fn new(client: aws_sdk_dynamodb::Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers (pure transforms)
// ---------------------------------------------------------------------------

/// Insert a string attribute into a DynamoDB item map.
fn put_s(item: &mut HashMap<String, AttributeValue>, key: &str, value: impl Into<String>) {
    item.insert(key.to_string(), AttributeValue::S(value.into()));
}

/// Serialize an `Organization` + `OrgConfig` + etag into a DynamoDB item.
fn to_item(
    org: &Organization,
    config: &OrgConfig,
    etag: &str,
) -> Result<HashMap<String, AttributeValue>> {
    let mut item = HashMap::new();

    put_s(&mut item, pk(), format!("{ORG_PREFIX}{}", org.org_id()));
    put_s(&mut item, sk(), SK_META);
    put_s(&mut item, "name", org.name());
    put_s(&mut item, "status", org.status().to_string());
    put_s(&mut item, "created_at", org.created_at().to_rfc3339());
    put_s(&mut item, "updated_at", org.updated_at().to_rfc3339());

    if let Some(v) = org.cognito_pool_id() {
        put_s(&mut item, "cognito_pool_id", v);
    }
    if let Some(v) = org.cognito_jwks_url() {
        put_s(&mut item, "cognito_jwks_url", v);
    }
    if let Some(v) = org.policy_store_id() {
        put_s(&mut item, "policy_store_id", v);
    }

    let config_json = serde_json::to_string(config)
        .map_err(|e| Error::Store(format!("serialize config: {e}")))?;
    put_s(&mut item, "config", config_json);
    put_s(&mut item, "etag", etag);

    Ok(item)
}

/// Parse a DynamoDB item back into an `OrgRecord`.
///
/// Validation failures produce `Error::Store`. Raw `AttributeValue` maps
/// never leak past this function (Parse Don't Validate).
fn from_item(item: &HashMap<String, AttributeValue>) -> Result<OrgRecord> {
    let pk = get_s(item, pk())?;
    let org_id_str = pk
        .strip_prefix(ORG_PREFIX)
        .ok_or_else(|| Error::Store(format!("pk missing {ORG_PREFIX} prefix: {pk}")))?;
    let org_id = OrganizationId::new(org_id_str)
        .map_err(|e| Error::Store(format!("invalid org_id in pk: {e}")))?;

    let name = get_s(item, "name")?;
    let status: OrgStatus = get_s(item, "status")?
        .parse()
        .map_err(|e: forgeguard_core::Error| Error::Store(format!("invalid status: {e}")))?;

    let created_at = parse_datetime(item, "created_at")?;
    let updated_at = parse_datetime(item, "updated_at")?;

    let cognito_pool_id = get_s_opt(item, "cognito_pool_id");
    let cognito_jwks_url = get_s_opt(item, "cognito_jwks_url");
    let policy_store_id = get_s_opt(item, "policy_store_id");

    let config: OrgConfig = serde_json::from_str(&get_s(item, "config")?)
        .map_err(|e| Error::Store(format!("deserialize config: {e}")))?;

    let etag = get_s(item, "etag")?;

    let org = Organization::new(org_id, name, status, created_at)
        .with_updated_at(updated_at)
        .with_aws_resources(cognito_pool_id, cognito_jwks_url, policy_store_id);

    Ok(OrgRecord::new(org, config, etag))
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

fn get_s(item: &HashMap<String, AttributeValue>, key: &str) -> Result<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .ok_or_else(|| Error::Store(format!("missing or non-string attribute: {key}")))
}

fn get_s_opt(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok()).cloned()
}

fn parse_datetime(item: &HashMap<String, AttributeValue>, key: &str) -> Result<DateTime<Utc>> {
    let s = get_s(item, key)?;
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Store(format!("invalid datetime for {key}: {e}")))
}

// ---------------------------------------------------------------------------
// SDK error mapping
// ---------------------------------------------------------------------------

fn map_sdk_error<E: std::fmt::Display>(err: E) -> Error {
    Error::Store(err.to_string())
}

/// Map a `PutItem` SDK error, converting `ConditionalCheckFailedException`
/// into the provided domain error.
fn map_put_item_error(
    sdk_err: aws_sdk_dynamodb::error::SdkError<aws_sdk_dynamodb::operation::put_item::PutItemError>,
    on_condition_failed: Error,
) -> Error {
    if let aws_sdk_dynamodb::error::SdkError::ServiceError(ref service_err) = sdk_err {
        if service_err.err().is_conditional_check_failed_exception() {
            return on_condition_failed;
        }
    }
    map_sdk_error(sdk_err)
}

// ---------------------------------------------------------------------------
// OrgStore implementation
// ---------------------------------------------------------------------------

impl OrgStore for DynamoOrgStore {
    async fn create(&self, org: Organization, config: OrgConfig) -> Result<OrgRecord> {
        let etag = compute_etag(&config)?;
        let item = to_item(&org, &config, &etag)?;

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", pk())
            .send()
            .await;

        match result {
            Ok(_) => Ok(OrgRecord::new(org, config, etag)),
            Err(sdk_err) => Err(map_put_item_error(
                sdk_err,
                Error::Conflict(format!("organization '{}' already exists", org.org_id())),
            )),
        }
    }

    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>> {
        let pk_value = format!("{ORG_PREFIX}{org_id}");

        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(pk_value))
            .key(sk(), AttributeValue::S(SK_META.to_string()))
            .send()
            .await
            .map_err(map_sdk_error)?;

        match result.item {
            Some(ref item) => from_item(item).map(Some),
            None => Ok(None),
        }
    }

    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>> {
        // Known anti-pattern: Scan reads all table items. #45 will add an
        // entity_type GSI so list() becomes a single Query.
        let mut all_items = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut request = self
                .client
                .scan()
                .table_name(&self.table_name)
                .filter_expression("begins_with(#pk, :org_prefix) AND #sk = :meta")
                .expression_attribute_names("#pk", pk())
                .expression_attribute_names("#sk", sk())
                .expression_attribute_values(
                    ":org_prefix",
                    AttributeValue::S(ORG_PREFIX.to_string()),
                )
                .expression_attribute_values(":meta", AttributeValue::S(SK_META.to_string()));

            if let Some(key) = exclusive_start_key {
                request = request.set_exclusive_start_key(Some(key));
            }

            let result = request.send().await.map_err(map_sdk_error)?;

            if let Some(items) = result.items {
                all_items.extend(items);
            }

            match result.last_evaluated_key {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
                _ => break,
            }
        }

        // Apply offset/limit in-memory (see #45 for future GSI-based pagination).
        all_items
            .iter()
            .skip(offset)
            .take(limit)
            .map(from_item)
            .collect()
    }

    async fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: OrgConfig,
    ) -> Result<OrgRecord> {
        if org_id != org.org_id() {
            return Err(Error::Store(format!(
                "org_id mismatch: path '{}' vs body '{}'",
                org_id,
                org.org_id()
            )));
        }
        let etag = compute_etag(&config)?;
        let item = to_item(&org, &config, &etag)?;

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", pk())
            .send()
            .await;

        match result {
            Ok(_) => Ok(OrgRecord::new(org, config, etag)),
            Err(sdk_err) => Err(map_put_item_error(
                sdk_err,
                Error::NotFound(format!("organization '{}' not found", org.org_id())),
            )),
        }
    }

    async fn delete(&self, org_id: &OrganizationId) -> Result<()> {
        let pk_value = format!("{ORG_PREFIX}{org_id}");

        self.client
            .delete_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(pk_value))
            .key(sk(), AttributeValue::S(SK_META.to_string()))
            .send()
            .await
            .map_err(map_sdk_error)?;

        // Idempotent: always Ok(()) regardless of whether the item existed.
        Ok(())
    }

    async fn generate_key(&self, _org_id: &OrganizationId) -> Result<GenerateKeyResult> {
        Err(Error::Store(
            "not yet implemented: DynamoDB generate_key".into(),
        ))
    }

    async fn list_keys(&self, _org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        Err(Error::Store(
            "not yet implemented: DynamoDB list_keys".into(),
        ))
    }

    async fn revoke_key(&self, _org_id: &OrganizationId, _key_id: &str) -> Result<()> {
        Err(Error::Store(
            "not yet implemented: DynamoDB revoke_key".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Integration tests — feature-gated behind `dynamodb-tests`
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a DynamoDB client pointing at a local DynamoDB-compatible endpoint.
    ///
    /// Uses `DYNAMODB_ENDPOINT` env var, falling back to `http://localhost:8000`.
    async fn test_client() -> aws_sdk_dynamodb::Client {
        let endpoint = std::env::var("DYNAMODB_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());
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
        let created = store.create(org, config).await.unwrap();
        assert_eq!(created.org().name(), "Acme Corp");
        assert_eq!(created.org().status(), OrgStatus::Draft);
        assert_eq!(created.org().org_id().as_str(), "org-acme");

        // Get
        let fetched = store.get(&org_id).await.unwrap().unwrap();
        assert_eq!(fetched.org().org_id().as_str(), "org-acme");
        assert_eq!(fetched.org().name(), "Acme Corp");
        assert_eq!(fetched.org().status(), OrgStatus::Draft);
        assert_eq!(fetched.etag(), created.etag());

        // Verify timestamps survive round-trip (RFC 3339 may lose sub-nanosecond)
        let diff = (fetched.org().created_at() - created.org().created_at())
            .num_milliseconds()
            .abs();
        assert!(diff < 1, "created_at should round-trip within 1ms");
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

        store.create(org1, config.clone()).await.unwrap();

        let org2 = Organization::new(org_id, "Second".to_string(), OrgStatus::Draft, now);
        let result = store.create(org2, config).await;

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
            store.create(org, sample_config()).await.unwrap();
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
            store.create(org, sample_config()).await.unwrap();
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
        store.create(org, sample_config()).await.unwrap();

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
            .update(&org_id, updated_org, new_config)
            .await
            .unwrap();
        assert_eq!(record.org().name(), "Updated");
        assert_eq!(record.config().upstream_url(), "https://updated.com");

        // Verify via get
        let fetched = store.get(&org_id).await.unwrap().unwrap();
        assert_eq!(fetched.org().name(), "Updated");
        assert_eq!(fetched.org().status(), OrgStatus::Active);
        assert_eq!(fetched.config().upstream_url(), "https://updated.com");
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

        let result = store.update(&org_id, org, sample_config()).await;
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

        let result = store.update(&org_id, org, sample_config()).await;
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
        store.create(org, sample_config()).await.unwrap();

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
}
