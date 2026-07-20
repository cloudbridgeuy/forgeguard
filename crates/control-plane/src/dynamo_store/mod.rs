//! DynamoDB-backed organization store.
//!
//! Activated via `--store=dynamodb --dynamodb-table <TABLE>` on the
//! control-plane binary.
//!
//! Key attribute names (`PK`, `SK`) are read from the shared schema file
//! at `infra/control-plane/schema/forgeguard-orgs.json` — the single source
//! of truth consumed by both CDK (TypeScript) and Rust.

pub(crate) mod groups;

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use forgeguard_core::{OrgStatus, Organization, OrganizationId};

use crate::config::OrgConfig;
use crate::error::{Error, Result};
use crate::etag::Etag;
use crate::handlers::groups::codec::{group_pk, group_sk, SK_GROUP_PREFIX};
use crate::signing_key::SigningKeyEntry;
use crate::store::{ConfiguredConfig, EtagedGroup, OrgRecord, OrgStore};

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
const SCHEMA_JSON: &str =
    include_str!("../../../../infra/control-plane/schema/forgeguard-orgs.json");

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
                tracing::error!("BUG: forgeguard-orgs.json schema is invalid: {e}");
                std::process::abort();
            }
        }
    })
}

/// Partition key attribute name (e.g. `"PK"`).
pub(crate) fn pk() -> &'static str {
    &key_schema().partition_key
}

/// Sort key attribute name (e.g. `"SK"`).
pub(crate) fn sk() -> &'static str {
    &key_schema().sort_key
}

pub(crate) const SK_META: &str = "META";
pub(crate) const ORG_PREFIX: &str = "ORG#";
pub(crate) const USER_PREFIX: &str = "USER#";

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
}

// ---------------------------------------------------------------------------
// Serialization helpers (pure transforms)
// ---------------------------------------------------------------------------

/// Insert a string attribute into a DynamoDB item map.
fn put_s(item: &mut HashMap<String, AttributeValue>, key: &str, value: impl Into<String>) {
    item.insert(key.to_string(), AttributeValue::S(value.into()));
}

/// Serialize an `Organization` + optional `ConfiguredConfig` + signing keys into a DynamoDB item.
///
/// When `configured` is `None` (Draft org), the `config` and `etag` attributes
/// are omitted entirely — no sentinel values.
pub(crate) fn to_item(
    org: &Organization,
    configured: Option<&ConfiguredConfig>,
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

    if let Some(c) = configured {
        let config_json = serde_json::to_string(c.config())
            .map_err(|e| Error::Store(format!("serialize config: {e}")))?;
        put_s(&mut item, "config", config_json);
        put_s(&mut item, "etag", c.etag().as_str());
    }

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
///
/// `config` and `etag` are read as a pair: both present (Configured) or both
/// absent (Draft). Asymmetric presence is an integrity error.
pub(crate) fn from_item(item: &HashMap<String, AttributeValue>) -> Result<OrgRecord> {
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

    let configured = match (get_s_opt(item, "config"), get_s_opt(item, "etag")) {
        (Some(config_json), Some(etag_raw)) => {
            let config: OrgConfig = serde_json::from_str(&config_json)
                .map_err(|e| Error::Store(format!("deserialize config: {e}")))?;
            let etag = Etag::try_new(etag_raw).map_err(|e| {
                Error::Store(format!("invalid stored etag for org '{org_id}': {e}"))
            })?;
            Some(ConfiguredConfig::from_stored(config, etag))
        }
        (None, None) => None,
        (Some(_), None) => {
            return Err(Error::Store(format!(
                "org '{org_id}' has 'config' attribute but no matching 'etag'"
            )))
        }
        (None, Some(_)) => {
            return Err(Error::Store(format!(
                "org '{org_id}' has 'etag' attribute but no matching 'config'"
            )))
        }
    };

    let org = Organization::new(org_id, name, status, created_at)
        .with_updated_at(updated_at)
        .with_aws_resources(cognito_pool_id, cognito_jwks_url, policy_store_id);

    Ok(OrgRecord::new(org, configured))
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

pub(crate) fn get_s(item: &HashMap<String, AttributeValue>, key: &str) -> Result<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .ok_or_else(|| Error::Store(format!("missing or non-string attribute: {key}")))
}

pub(crate) fn get_s_opt(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok()).cloned()
}

pub(crate) fn parse_datetime(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<DateTime<Utc>> {
    let s = get_s(item, key)?;
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Store(format!("invalid datetime for {key}: {e}")))
}

// ---------------------------------------------------------------------------
// SDK error mapping
// ---------------------------------------------------------------------------

pub(crate) fn map_sdk_error<E: std::fmt::Display>(err: E) -> Error {
    Error::Store(err.to_string())
}

// ---------------------------------------------------------------------------
// Signing-key helpers
// ---------------------------------------------------------------------------

/// Deserialize the `signing_keys` JSON string attribute from a DynamoDB item.
///
/// Returns an empty `Vec` when the attribute is absent (new org, no keys yet).
pub(crate) fn signing_keys_from_item(
    item: &HashMap<String, AttributeValue>,
) -> Result<Vec<SigningKeyEntry>> {
    match get_s_opt(item, "signing_keys") {
        Some(json) => serde_json::from_str(&json)
            .map_err(|e| Error::Store(format!("deserialize signing_keys: {e}"))),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// OrgStore implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl OrgStore for DynamoOrgStore {
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

    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        match self.get_raw_item(org_id).await? {
            Some(ref item) => signing_keys_from_item(item),
            None => Ok(Vec::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Group CRUD (V2) — DynamoDB-backed implementations
    // -----------------------------------------------------------------------

    async fn get_group(&self, org_id: &OrganizationId, name: &str) -> Result<Option<EtagedGroup>> {
        let pk_value = group_pk(org_id);
        let sk_value = group_sk(name);
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(pk_value))
            .key(sk(), AttributeValue::S(sk_value))
            .send()
            .await
            .map_err(map_sdk_error)?;
        result
            .item
            .as_ref()
            .map(groups::etaged_group_from_item)
            .transpose()
    }

    async fn list_groups(&self, org_id: &OrganizationId) -> Result<Vec<EtagedGroup>> {
        let pk_value = group_pk(org_id);

        let mut all_items = Vec::new();
        let mut exclusive_start_key = None;

        loop {
            let mut request = self
                .client
                .query()
                .table_name(&self.table_name)
                .key_condition_expression("#pk = :pk AND begins_with(#sk, :prefix)")
                .expression_attribute_names("#pk", pk())
                .expression_attribute_names("#sk", sk())
                .expression_attribute_values(":pk", AttributeValue::S(pk_value.clone()))
                .expression_attribute_values(
                    ":prefix",
                    AttributeValue::S(SK_GROUP_PREFIX.to_string()),
                );

            if let Some(key) = exclusive_start_key {
                request = request.set_exclusive_start_key(Some(key));
            }

            let result = request.send().await.map_err(map_sdk_error)?;

            all_items.extend(result.items.unwrap_or_default());

            match result.last_evaluated_key {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
                _ => break,
            }
        }

        // DynamoDB Query with a begins_with SK condition returns items sorted
        // ascending by SK, which equals ascending by group name (after stripping
        // the GROUP# prefix). No client-side sort needed.
        all_items
            .iter()
            .map(groups::etaged_group_from_item)
            .collect()
    }

    async fn list_inheritors(&self, org_id: &OrganizationId, name: &str) -> Result<Vec<String>> {
        // V2: dev-volume only; future work uses GSI1 for O(rows-in-org)
        let groups_list = self.list_groups(org_id).await?;
        Ok(groups_list
            .into_iter()
            .filter(|g| g.entry().inherits.iter().any(|s| s == name))
            .map(|g| g.entry().name.clone())
            .collect())
    }

    async fn count_memberships_for_group(
        &self,
        org_id: &OrganizationId,
        name: &str,
    ) -> Result<BTreeMap<String, u32>> {
        // V2: full-table scan; future: GSI1 (PK=ORG#{org_id}, SK=USER#{sub})
        // for O(rows-in-org) instead of O(table-size).
        //
        // Membership rows are keyed `PK=USER#{sub}, SK=ORG#{org_id}` and store
        // the user's group memberships as `groups: List<String>`.
        // If the write side for membership rows is not yet deployed, this scan
        // returns an empty BTreeMap safely.
        let sk_value = format!("{ORG_PREFIX}{org_id}");

        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        let mut exclusive_start_key = None;

        loop {
            let mut request = self
                .client
                .scan()
                .table_name(&self.table_name)
                // Filter: SK equals ORG#{org_id} AND the groups list contains the target name.
                .filter_expression(
                    "begins_with(#pk, :user_prefix) AND #sk = :sk_val AND contains(#groups, :group_name)",
                )
                .expression_attribute_names("#pk", pk())
                .expression_attribute_names("#sk", sk())
                .expression_attribute_names("#groups", "groups")
                .expression_attribute_values(
                    ":user_prefix",
                    AttributeValue::S(USER_PREFIX.to_string()),
                )
                .expression_attribute_values(":sk_val", AttributeValue::S(sk_value.clone()))
                .expression_attribute_values(
                    ":group_name",
                    AttributeValue::S(name.to_string()),
                );

            if let Some(key) = exclusive_start_key {
                request = request.set_exclusive_start_key(Some(key));
            }

            let result = request.send().await.map_err(map_sdk_error)?;

            for item in result.items.unwrap_or_default() {
                // Extract the user sub from PK: "USER#{sub}" → sub.
                if let Some(user_sub) = item
                    .get(pk())
                    .and_then(|v| v.as_s().ok())
                    .and_then(|pk_val| pk_val.strip_prefix(USER_PREFIX))
                {
                    // Each user has at most one ORG row per org, so count is always 1 per user.
                    *counts.entry(user_sub.to_string()).or_insert(0) += 1;
                }
            }

            match result.last_evaluated_key {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
                _ => break,
            }
        }

        Ok(counts)
    }
}

// ---------------------------------------------------------------------------
// Integration tests — feature-gated behind `dynamodb-tests`
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "dynamodb-tests")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
