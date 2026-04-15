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
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry, SigningKeyStatus};
use crate::store::{compute_etag, generate_key_material, OrgRecord, OrgStore};

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
const SCHEMA_JSON: &str = include_str!("../../../../infra/control-plane/schema/dynamodb.json");

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

    /// Fetch the raw DynamoDB item for an org, returning `None` if absent.
    async fn get_raw_item(
        &self,
        org_id: &OrganizationId,
    ) -> Result<Option<HashMap<String, AttributeValue>>> {
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
        Ok(result.item)
    }

    /// Write an updated `signing_keys` JSON list back to the org item.
    ///
    /// Uses `attribute_exists(#pk)` to ensure the org still exists.
    #[allow(dead_code)]
    async fn write_signing_keys(
        &self,
        org_id: &OrganizationId,
        keys: &[SigningKeyEntry],
    ) -> Result<()> {
        let keys_json = serde_json::to_string(keys)
            .map_err(|e| Error::Store(format!("serialize signing_keys: {e}")))?;

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(format!("{ORG_PREFIX}{org_id}")))
            .key(sk(), AttributeValue::S(SK_META.to_string()))
            .update_expression("SET #sk_attr = :sk_val")
            .expression_attribute_names("#sk_attr", "signing_keys")
            .expression_attribute_values(":sk_val", AttributeValue::S(keys_json))
            .condition_expression("attribute_exists(#pk)")
            .expression_attribute_names("#pk", pk())
            .send()
            .await
            .map_err(|sdk_err| {
                map_update_item_error(
                    sdk_err,
                    Error::NotFound(format!("organization '{org_id}' not found")),
                )
            })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers (pure transforms)
// ---------------------------------------------------------------------------

/// Insert a string attribute into a DynamoDB item map.
fn put_s(item: &mut HashMap<String, AttributeValue>, key: &str, value: impl Into<String>) {
    item.insert(key.to_string(), AttributeValue::S(value.into()));
}

/// Serialize an `Organization` + `OrgConfig` + etag + signing keys into a DynamoDB item.
fn to_item(
    org: &Organization,
    config: &OrgConfig,
    etag: &str,
    signing_keys: &[SigningKeyEntry],
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

    if !signing_keys.is_empty() {
        let keys_json = serde_json::to_string(signing_keys)
            .map_err(|e| Error::Store(format!("serialize signing_keys: {e}")))?;
        put_s(&mut item, "signing_keys", keys_json);
    }

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

/// Map an `UpdateItem` SDK error, converting `ConditionalCheckFailedException`
/// into the provided domain error.
#[allow(dead_code)]
fn map_update_item_error(
    sdk_err: aws_sdk_dynamodb::error::SdkError<
        aws_sdk_dynamodb::operation::update_item::UpdateItemError,
    >,
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
// Signing-key helpers
// ---------------------------------------------------------------------------

/// Deserialize the `signing_keys` JSON string attribute from a DynamoDB item.
///
/// Returns an empty `Vec` when the attribute is absent (new org, no keys yet).
fn signing_keys_from_item(item: &HashMap<String, AttributeValue>) -> Result<Vec<SigningKeyEntry>> {
    match get_s_opt(item, "signing_keys") {
        Some(json) => serde_json::from_str(&json)
            .map_err(|e| Error::Store(format!("deserialize signing_keys: {e}"))),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// OrgStore implementation
// ---------------------------------------------------------------------------

impl OrgStore for DynamoOrgStore {
    async fn create(&self, org: Organization, config: OrgConfig) -> Result<OrgRecord> {
        let etag = compute_etag(&config)?;
        let item = to_item(&org, &config, &etag, &[])?;

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
        match self.get_raw_item(org_id).await? {
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

        // Read existing item to preserve signing_keys across the PutItem replacement.
        let existing = self
            .get_raw_item(org_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("organization '{org_id}' not found")))?;
        let existing_keys = signing_keys_from_item(&existing)?;

        let etag = compute_etag(&config)?;
        let item = to_item(&org, &config, &etag, &existing_keys)?;

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

    async fn generate_key(&self, org_id: &OrganizationId) -> Result<GenerateKeyResult> {
        // Synchronous — `ThreadRng` is not `Send`, must complete before `.await`.
        let result = generate_key_material()?;
        let entry = SigningKeyEntry::new(
            result.key_id().to_string(),
            result.public_key_pem().to_string(),
            SigningKeyStatus::Active,
            result.created_at(),
            None,
        )?;

        let item = self
            .get_raw_item(org_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("organization '{org_id}' not found")))?;

        let mut keys = signing_keys_from_item(&item)?;
        keys.push(entry);
        self.write_signing_keys(org_id, &keys).await?;

        Ok(result)
    }

    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        match self.get_raw_item(org_id).await? {
            Some(ref item) => signing_keys_from_item(item),
            None => Ok(Vec::new()),
        }
    }

    async fn revoke_key(&self, org_id: &OrganizationId, key_id: &str) -> Result<()> {
        let item = self
            .get_raw_item(org_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("organization '{org_id}' not found")))?;

        let mut keys = signing_keys_from_item(&item)?;
        let entry = keys
            .iter_mut()
            .find(|k| k.key_id() == key_id)
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "signing key '{key_id}' not found for organization '{org_id}'"
                ))
            })?;
        entry.revoke();

        self.write_signing_keys(org_id, &keys).await
    }
}

// ---------------------------------------------------------------------------
// Integration tests — feature-gated behind `dynamodb-tests`
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
