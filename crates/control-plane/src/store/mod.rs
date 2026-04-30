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
use crate::etag::Etag;
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

    /// Persist a mutation to an existing organization.
    ///
    /// When `expected_etag` is `Some(e)`, the implementation MUST return
    /// `Error::PreconditionFailed { current_etag }` if the currently stored
    /// config etag does not equal `e`. When `expected_etag` is `None`, the
    /// implementation writes unconditionally (last-write-wins — preserved
    /// for callers that do not opt in).
    fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: Option<OrgConfig>,
        expected_etag: Option<&Etag>,
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

    fn rotate_signing_key(
        &self,
        org_id: &OrganizationId,
        key_id: &str,
    ) -> impl std::future::Future<Output = Result<GenerateKeyResult>> + Send;
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
    etag: Etag,
}

impl ConfiguredConfig {
    /// Build from a config alone, computing the etag from its contents.
    pub(crate) fn compute(config: OrgConfig) -> Result<Self> {
        let etag = compute_etag(&config)?;
        Ok(Self { config, etag })
    }

    /// Build from an already-paired (config, etag) — e.g. when
    /// reconstituting an `OrgRecord` from a DynamoDB item.
    pub(crate) fn from_stored(config: OrgConfig, etag: Etag) -> Result<Self> {
        Ok(Self { config, etag })
    }

    pub(crate) fn config(&self) -> &OrgConfig {
        &self.config
    }

    pub(crate) fn etag(&self) -> &Etag {
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
        expected_etag: Option<&Etag>,
    ) -> Result<OrgRecord> {
        if org_id != org.org_id() {
            return Err(Error::Store(format!(
                "org_id mismatch: path '{}' vs body '{}'",
                org_id,
                org.org_id()
            )));
        }
        let mut guard = self.orgs.write().await;
        let Some(current) = guard.get(org_id) else {
            return Err(Error::NotFound(format!(
                "organization '{org_id}' not found"
            )));
        };

        let stored_etag = current.configured().map(ConfiguredConfig::etag);
        if let crate::etag::EtagCheck::Mismatch {
            current: current_etag,
        } = crate::etag::check_etag(stored_etag, expected_etag)
        {
            return Err(Error::PreconditionFailed { current_etag });
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

    async fn rotate_signing_key(
        &self,
        org_id: &OrganizationId,
        key_id: &str,
    ) -> Result<GenerateKeyResult> {
        {
            let orgs = self.orgs.read().await;
            if !orgs.contains_key(org_id) {
                return Err(Error::NotFound(format!(
                    "organization '{org_id}' not found"
                )));
            }
        }

        // Generate material BEFORE any .await that touches !Send RNG state.
        let result = generate_key_material()?;
        let new_entry = result.to_entry()?;

        let mut guard = self.signing_keys.write().await;
        let existing = guard.get(org_id).cloned().unwrap_or_default();
        let updated = crate::signing_key::rotate_entries(
            existing,
            key_id,
            new_entry,
            Utc::now(),
            chrono::Duration::hours(crate::signing_key::ROTATION_GRACE_HOURS),
        )?;
        guard.insert(org_id.clone(), updated);
        Ok(result)
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

pub(crate) fn compute_etag(config: &OrgConfig) -> Result<Etag> {
    let json = serde_json::to_string(config).map_err(|e| Error::Config(e.to_string()))?;
    let hash = xxhash_rust::xxh64::xxh64(json.as_bytes(), 0);
    let raw = format!("\"{hash:016x}\"");
    Etag::try_new(raw).map_err(|e| Error::Config(e.to_string()))
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
        expected_etag: Option<&Etag>,
    ) -> Result<OrgRecord> {
        match self {
            Self::Memory(s) => s.update(org_id, org, config, expected_etag).await,
            Self::DynamoDb(s) => s.update(org_id, org, config, expected_etag).await,
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

    async fn rotate_signing_key(
        &self,
        org_id: &OrganizationId,
        key_id: &str,
    ) -> Result<GenerateKeyResult> {
        match self {
            Self::Memory(s) => s.rotate_signing_key(org_id, key_id).await,
            Self::DynamoDb(s) => s.rotate_signing_key(org_id, key_id).await,
        }
    }
}

#[cfg(test)]
mod tests;
