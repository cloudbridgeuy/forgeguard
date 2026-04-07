use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use chrono::Utc;
use forgeguard_core::{OrgStatus, Organization, OrganizationId};
use serde::Deserialize;

use crate::config::OrgConfig;
use crate::error::{Error, Result};

/// Abstraction over organization config storage.
///
/// Implementations: `InMemoryOrgStore` (in-memory, loaded from file or built programmatically).
/// Future: DynamoDB-backed store for production.
pub(crate) trait OrgStore: Send + Sync {
    fn get(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<Option<OrgRecord>>> + Send;

    fn create(
        &self,
        org: Organization,
        config: OrgConfig,
    ) -> impl std::future::Future<Output = Result<OrgRecord>> + Send;

    fn list(
        &self,
        offset: usize,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<OrgRecord>>> + Send;

    fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: OrgConfig,
    ) -> impl std::future::Future<Output = Result<OrgRecord>> + Send;

    fn delete(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Debug, Clone)]
pub(crate) struct OrgRecord {
    org: Organization,
    config: OrgConfig,
    etag: String,
}

impl OrgRecord {
    pub(crate) fn new(org: Organization, config: OrgConfig, etag: String) -> Self {
        Self { org, config, etag }
    }

    pub(crate) fn org(&self) -> &Organization {
        &self.org
    }

    pub(crate) fn config(&self) -> &OrgConfig {
        &self.config
    }

    pub(crate) fn etag(&self) -> &str {
        &self.etag
    }
}

#[derive(Debug)]
pub(crate) struct InMemoryOrgStore {
    orgs: tokio::sync::RwLock<BTreeMap<OrganizationId, OrgRecord>>,
}

impl InMemoryOrgStore {
    pub(crate) fn new(orgs: BTreeMap<OrganizationId, OrgRecord>) -> Self {
        Self {
            orgs: tokio::sync::RwLock::new(orgs),
        }
    }
}

impl OrgStore for InMemoryOrgStore {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>> {
        let guard = self.orgs.read().await;
        Ok(guard.get(org_id).cloned())
    }

    async fn create(&self, org: Organization, config: OrgConfig) -> Result<OrgRecord> {
        let mut guard = self.orgs.write().await;
        let org_id = org.org_id().clone();
        if guard.contains_key(&org_id) {
            return Err(Error::Conflict(format!(
                "organization '{org_id}' already exists"
            )));
        }
        let etag = compute_etag(&config)?;
        let record = OrgRecord::new(org, config, etag);
        guard.insert(org_id, record.clone());
        Ok(record)
    }

    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>> {
        let guard = self.orgs.read().await;
        let records: Vec<OrgRecord> = guard.values().skip(offset).take(limit).cloned().collect();
        Ok(records)
    }

    async fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: OrgConfig,
    ) -> Result<OrgRecord> {
        let mut guard = self.orgs.write().await;
        if !guard.contains_key(org_id) {
            return Err(Error::NotFound(format!(
                "organization '{org_id}' not found"
            )));
        }
        let etag = compute_etag(&config)?;
        let record = OrgRecord::new(org, config, etag);
        guard.insert(org_id.clone(), record.clone());
        Ok(record)
    }

    async fn delete(&self, org_id: &OrganizationId) -> Result<()> {
        let mut guard = self.orgs.write().await;
        guard.remove(org_id);
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct RawOrgFile {
    organizations: HashMap<String, RawOrgEntry>,
}

#[derive(Debug, Deserialize)]
struct RawOrgEntry {
    name: String,
    config: OrgConfig,
}

pub(crate) fn compute_etag(config: &OrgConfig) -> Result<String> {
    let json = serde_json::to_string(config).map_err(|e| Error::Config(e.to_string()))?;
    let hash = xxhash_rust::xxh64::xxh64(json.as_bytes(), 0);
    Ok(format!("\"{hash:016x}\""))
}

pub(crate) fn build_org_store(json_str: &str) -> Result<InMemoryOrgStore> {
    let raw: RawOrgFile =
        serde_json::from_str(json_str).map_err(|e| Error::Config(e.to_string()))?;

    let now = Utc::now();
    let mut orgs = BTreeMap::new();

    for (raw_id, raw_entry) in raw.organizations {
        let org_id = OrganizationId::new(&raw_id)
            .map_err(|e| Error::Config(format!("invalid organization id {raw_id:?}: {e}")))?;

        let etag = compute_etag(&raw_entry.config)?;

        let org = Organization::new(org_id.clone(), raw_entry.name, OrgStatus::Active, now);
        let record = OrgRecord::new(org, raw_entry.config, etag);

        orgs.insert(org_id, record);
    }

    Ok(InMemoryOrgStore::new(orgs))
}

pub(crate) fn load_config_file(path: &Path) -> color_eyre::Result<InMemoryOrgStore> {
    let json_str = std::fs::read_to_string(path)?;
    let store = build_org_store(&json_str)?;
    Ok(store)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
        assert_eq!(record.config().upstream_url(), "https://api.acme.com");
        assert_eq!(
            record.config().default_policy(),
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
        assert_eq!(
            store
                .get(&alpha)
                .await
                .unwrap()
                .unwrap()
                .config()
                .upstream_url(),
            "https://alpha.com"
        );
        assert_eq!(
            store
                .get(&beta)
                .await
                .unwrap()
                .unwrap()
                .config()
                .default_policy(),
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

        let etag1 = compute_etag(record.config()).unwrap();
        let etag2 = compute_etag(record.config()).unwrap();
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

        let etag = compute_etag(record.config()).unwrap();
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

        let record = store.create(org, config).await.unwrap();
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
        store.create(org1, config.clone()).await.unwrap();

        let org2 = Organization::new(
            OrganizationId::new("org-dup").unwrap(),
            "Second".to_string(),
            OrgStatus::Draft,
            now,
        );
        let result = store.create(org2, config).await;
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
        store.create(org, config).await.unwrap();

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
            .update(&org_id, updated_org, new_config)
            .await
            .unwrap();
        assert_eq!(record.org().name(), "Updated");
        assert_eq!(record.config().upstream_url(), "https://updated.com");
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

        let result = store.update(&org_id, org, config).await;
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
        store.create(org, config).await.unwrap();

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
            store.create(org, config).await.unwrap();
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
}
