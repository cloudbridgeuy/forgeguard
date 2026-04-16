use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use chrono::Utc;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use forgeguard_core::{OrgStatus, Organization, OrganizationId};
use serde::Deserialize;

use crate::config::OrgConfig;
use crate::dynamo_store::DynamoOrgStore;
use crate::error::{Error, Result};
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};

/// Abstraction over organization config storage.
///
/// Implementations: `InMemoryOrgStore` (file-backed), `DynamoOrgStore` (DynamoDB).
/// Runtime dispatch via `AnyOrgStore`.
pub(crate) trait OrgStore: Send + Sync {
    fn get(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<Option<OrgRecord>>> + Send;

    fn create(
        &self,
        org: Organization,
        config: Option<OrgConfig>,
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
        config: Option<OrgConfig>,
    ) -> impl std::future::Future<Output = Result<OrgRecord>> + Send;

    fn delete(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    fn generate_key(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<GenerateKeyResult>> + Send;

    fn list_keys(
        &self,
        org_id: &OrganizationId,
    ) -> impl std::future::Future<Output = Result<Vec<SigningKeyEntry>>> + Send;

    fn revoke_key(
        &self,
        org_id: &OrganizationId,
        key_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// A configured (`OrgConfig` + matching etag) pair.
///
/// Couples config with its content-addressed etag so the two cannot drift.
/// Construct via [`ConfiguredConfig::compute`] (computes the etag) or
/// [`ConfiguredConfig::from_stored`] (reuses an etag that was persisted
/// alongside the config — e.g. read from DynamoDB).
#[derive(Debug, Clone)]
pub(crate) struct ConfiguredConfig {
    config: OrgConfig,
    etag: String,
}

impl ConfiguredConfig {
    /// Build from a config alone, computing the etag from its contents.
    pub(crate) fn compute(config: OrgConfig) -> Result<Self> {
        let etag = compute_etag(&config)?;
        Ok(Self { config, etag })
    }

    /// Build from an already-paired (config, etag) — e.g. when
    /// reconstituting an `OrgRecord` from a DynamoDB item.
    pub(crate) fn from_stored(config: OrgConfig, etag: String) -> Self {
        Self { config, etag }
    }

    pub(crate) fn config(&self) -> &OrgConfig {
        &self.config
    }

    pub(crate) fn etag(&self) -> &str {
        &self.etag
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OrgRecord {
    org: Organization,
    configured: Option<ConfiguredConfig>,
}

impl OrgRecord {
    /// Construct from an org and its (optional) configured pair.
    ///
    /// `configured = None` represents a Draft org with no proxy config yet.
    pub(crate) fn new(org: Organization, configured: Option<ConfiguredConfig>) -> Self {
        Self { org, configured }
    }

    pub(crate) fn org(&self) -> &Organization {
        &self.org
    }

    /// The proxy config, if the org has been configured.
    pub(crate) fn config(&self) -> Option<&OrgConfig> {
        self.configured.as_ref().map(ConfiguredConfig::config)
    }

    /// The (config, etag) pair, if the org has been configured.
    ///
    /// Use this when both the config and its etag are needed together
    /// (e.g. the proxy-config handler — single null-check, no chance of
    /// reading one and forgetting the other).
    pub(crate) fn configured(&self) -> Option<&ConfiguredConfig> {
        self.configured.as_ref()
    }
}

#[derive(Debug)]
pub(crate) struct InMemoryOrgStore {
    orgs: tokio::sync::RwLock<BTreeMap<OrganizationId, OrgRecord>>,
    signing_keys: tokio::sync::RwLock<BTreeMap<OrganizationId, Vec<SigningKeyEntry>>>,
}

impl InMemoryOrgStore {
    pub(crate) fn new(orgs: BTreeMap<OrganizationId, OrgRecord>) -> Self {
        Self {
            orgs: tokio::sync::RwLock::new(orgs),
            signing_keys: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }
}

impl OrgStore for InMemoryOrgStore {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>> {
        let guard = self.orgs.read().await;
        Ok(guard.get(org_id).cloned())
    }

    async fn create(&self, org: Organization, config: Option<OrgConfig>) -> Result<OrgRecord> {
        let mut guard = self.orgs.write().await;
        let org_id = org.org_id().clone();
        if guard.contains_key(&org_id) {
            return Err(Error::Conflict(format!(
                "organization '{org_id}' already exists"
            )));
        }
        let configured = config.map(ConfiguredConfig::compute).transpose()?;
        let record = OrgRecord::new(org, configured);
        guard.insert(org_id, record.clone());
        Ok(record)
    }

    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>> {
        let guard = self.orgs.read().await;
        Ok(guard.values().skip(offset).take(limit).cloned().collect())
    }

    async fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: Option<OrgConfig>,
    ) -> Result<OrgRecord> {
        if org_id != org.org_id() {
            return Err(Error::Store(format!(
                "org_id mismatch: path '{}' vs body '{}'",
                org_id,
                org.org_id()
            )));
        }
        let mut guard = self.orgs.write().await;
        if !guard.contains_key(org_id) {
            return Err(Error::NotFound(format!(
                "organization '{org_id}' not found"
            )));
        }
        let configured = config.map(ConfiguredConfig::compute).transpose()?;
        let record = OrgRecord::new(org, configured);
        guard.insert(org_id.clone(), record.clone());
        Ok(record)
    }

    async fn delete(&self, org_id: &OrganizationId) -> Result<()> {
        let mut guard = self.orgs.write().await;
        guard.remove(org_id);
        Ok(())
    }

    async fn generate_key(&self, org_id: &OrganizationId) -> Result<GenerateKeyResult> {
        // Verify the organization exists before generating key material.
        {
            let orgs = self.orgs.read().await;
            if !orgs.contains_key(org_id) {
                return Err(Error::NotFound(format!(
                    "organization '{org_id}' not found"
                )));
            }
        }

        // Synchronous — `ThreadRng` is not `Send`, must complete before `.await`.
        let result = generate_key_material()?;
        let entry = result.to_entry()?;

        let mut guard = self.signing_keys.write().await;
        guard.entry(org_id.clone()).or_default().push(entry);

        Ok(result)
    }

    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        let guard = self.signing_keys.read().await;
        Ok(guard.get(org_id).cloned().unwrap_or_default())
    }

    async fn revoke_key(&self, org_id: &OrganizationId, key_id: &str) -> Result<()> {
        let mut guard = self.signing_keys.write().await;
        let keys = guard.get_mut(org_id).ok_or_else(|| {
            Error::NotFound(format!("no signing keys found for organization '{org_id}'"))
        })?;
        let entry = keys
            .iter_mut()
            .find(|k| k.key_id() == key_id)
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "signing key '{key_id}' not found for organization '{org_id}'"
                ))
            })?;
        entry.revoke();
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
    #[serde(default)]
    config: Option<OrgConfig>,
}

fn generate_key_id() -> String {
    let bytes: [u8; 16] = rand::random();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("key-{hex}")
}

/// Generate an Ed25519 keypair and return the constituent parts.
///
/// `ThreadRng` is not `Send`, so this function is intentionally synchronous.
/// Callers must invoke it *before* any `.await` point.
pub(crate) fn generate_key_material() -> Result<GenerateKeyResult> {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);

    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::Store(format!("failed to encode private key: {e}")))?
        .to_string();
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::Store(format!("failed to encode public key: {e}")))?;

    let now = Utc::now();
    let key_id = generate_key_id();

    Ok(GenerateKeyResult::new(key_id, private_pem, public_pem, now))
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

        // Seeded orgs are Active when configured, Draft when not — matches
        // the semantic of "this org needs onboarding to receive traffic".
        let configured = raw_entry
            .config
            .map(ConfiguredConfig::compute)
            .transpose()?;
        let status = if configured.is_some() {
            OrgStatus::Active
        } else {
            OrgStatus::Draft
        };

        let org = Organization::new(org_id.clone(), raw_entry.name, status, now);
        let record = OrgRecord::new(org, configured);

        orgs.insert(org_id, record);
    }

    Ok(InMemoryOrgStore::new(orgs))
}

pub(crate) fn load_config_file(path: &Path) -> color_eyre::Result<InMemoryOrgStore> {
    let json_str = std::fs::read_to_string(path)?;
    let store = build_org_store(&json_str)?;
    Ok(store)
}

// ---------------------------------------------------------------------------
// AnyOrgStore — dispatch enum for runtime store selection
// ---------------------------------------------------------------------------

/// Enum wrapper that delegates to the active store backend.
///
/// The `OrgStore` trait uses RPITIT (`impl Future` in return position), making
/// it not object-safe. This enum provides static dispatch instead of `dyn`.
pub(crate) enum AnyOrgStore {
    Memory(InMemoryOrgStore),
    DynamoDb(DynamoOrgStore),
}

impl OrgStore for AnyOrgStore {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>> {
        match self {
            Self::Memory(s) => s.get(org_id).await,
            Self::DynamoDb(s) => s.get(org_id).await,
        }
    }

    async fn create(&self, org: Organization, config: Option<OrgConfig>) -> Result<OrgRecord> {
        match self {
            Self::Memory(s) => s.create(org, config).await,
            Self::DynamoDb(s) => s.create(org, config).await,
        }
    }

    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>> {
        match self {
            Self::Memory(s) => s.list(offset, limit).await,
            Self::DynamoDb(s) => s.list(offset, limit).await,
        }
    }

    async fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: Option<OrgConfig>,
    ) -> Result<OrgRecord> {
        match self {
            Self::Memory(s) => s.update(org_id, org, config).await,
            Self::DynamoDb(s) => s.update(org_id, org, config).await,
        }
    }

    async fn delete(&self, org_id: &OrganizationId) -> Result<()> {
        match self {
            Self::Memory(s) => s.delete(org_id).await,
            Self::DynamoDb(s) => s.delete(org_id).await,
        }
    }

    async fn generate_key(&self, org_id: &OrganizationId) -> Result<GenerateKeyResult> {
        match self {
            Self::Memory(s) => s.generate_key(org_id).await,
            Self::DynamoDb(s) => s.generate_key(org_id).await,
        }
    }

    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        match self {
            Self::Memory(s) => s.list_keys(org_id).await,
            Self::DynamoDb(s) => s.list_keys(org_id).await,
        }
    }

    async fn revoke_key(&self, org_id: &OrganizationId, key_id: &str) -> Result<()> {
        match self {
            Self::Memory(s) => s.revoke_key(org_id, key_id).await,
            Self::DynamoDb(s) => s.revoke_key(org_id, key_id).await,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
            .update(&org_id, updated_org, Some(config))
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
            .update(&org_id, updated_org, Some(new_config))
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

        let result = store.update(&org_id, org, Some(config)).await;
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
}
