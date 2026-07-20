pub(crate) mod groups;

pub(crate) use groups::EtagedGroup;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use forgeguard_core::{OrgStatus, Organization, OrganizationId};
use serde::Deserialize;

use crate::config::OrgConfig;
use crate::error::{Error, Result};
use crate::etag::Etag;
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};

/// Abstraction over organization config storage.
///
/// Implementations: `InMemoryOrgStore` (file-backed), `DynamoOrgStore` (DynamoDB).
/// Construction picks one adapter; the runtime sees `Arc<dyn OrgStore>`.
#[async_trait]
pub(crate) trait OrgStore: Send + Sync {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>>;

    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>>;

    /// Write-through hook for `InMemoryModelEventStore::{create_org,update_org}`.
    ///
    /// In production, `DynamoOrgStore` and `DynamoModelEventStore` share one DynamoDB
    /// table, so an org appended to the log is already visible via `get`/`list` — no
    /// write-through needed, hence the default no-op body. `InMemoryOrgStore` overrides
    /// this to keep its separate in-memory read-model mirrored with the event log
    /// (dev-mode `--store=memory` and handler tests).
    ///
    /// Unconditionally upserts: unlike the retired `OrgStore::create`/`update`, there is
    /// no conflict/precondition semantics here — the log's own revision check already
    /// gates the mutation before this hook runs.
    async fn write_through_org(&self, _org: Organization, _config: Option<OrgConfig>) {}

    /// Write-through hook for `InMemoryModelEventStore`'s
    /// `generate_org_key`/`revoke_org_key`/`rotate_org_key` (#113 V3).
    ///
    /// In production, `DynamoOrgStore` and `DynamoModelEventStore` share one
    /// DynamoDB table item's `signing_keys` attribute, so a key mutation
    /// appended to the log is already visible via `list_keys` — no
    /// write-through needed, hence the default no-op body. `InMemoryOrgStore`
    /// overrides this to keep its separate in-memory `list_keys` read-model
    /// mirrored with the event log (dev-mode `--store=memory` and handler
    /// tests). `keys` is the full post-mutation list — an unconditional
    /// replace, matching `write_through_org`'s semantics.
    async fn write_through_signing_keys(
        &self,
        _org_id: &OrganizationId,
        _keys: Vec<SigningKeyEntry>,
    ) {
    }

    /// Write-through hook for `InMemoryModelEventStore::{put_group, delete_group}`
    /// (#113 V4, Task 4).
    ///
    /// In production, `DynamoOrgStore` and `DynamoModelEventStore` share one
    /// DynamoDB table, so a group appended to the log is already visible via
    /// `get_group`/`list_groups` — no write-through needed, hence the default
    /// no-op body. `InMemoryOrgStore` overrides this to keep its separate
    /// in-memory group read-model mirrored with the event log (dev-mode
    /// `--store=memory` and handler tests). Unconditionally upserts: the
    /// log's own revision check already gated the mutation before this hook
    /// runs, same rationale as `write_through_org`.
    async fn write_through_group(&self, _org_id: &OrganizationId, _entry: EtagedGroup) {}

    /// Write-through hook for `InMemoryModelEventStore::delete_group`
    /// (#113 V4, Task 4) — see `write_through_group` for rationale.
    async fn write_through_group_delete(&self, _org_id: &OrganizationId, _name: &str) {}

    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>>;

    // -----------------------------------------------------------------------
    // Group CRUD (V2) — consumed by Group D handler bodies
    // -----------------------------------------------------------------------

    /// Retrieve a single group by name, or `None` if it does not exist.
    async fn get_group(&self, org_id: &OrganizationId, name: &str) -> Result<Option<EtagedGroup>>;

    /// List all groups for an org, sorted ascending by name.
    async fn list_groups(&self, org_id: &OrganizationId) -> Result<Vec<EtagedGroup>>;

    /// Return the names of groups that list `name` in their `inherits` field.
    async fn list_inheritors(&self, org_id: &OrganizationId, name: &str) -> Result<Vec<String>>;

    /// Return the count of users in the given group, keyed by user id.
    async fn count_memberships_for_group(
        &self,
        org_id: &OrganizationId,
        name: &str,
    ) -> Result<BTreeMap<String, u32>>;
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
    pub(crate) fn compute(config: OrgConfig) -> Self {
        let etag = compute_etag(&config);
        Self { config, etag }
    }

    /// Build from an already-paired (config, etag) — e.g. when
    /// reconstituting an `OrgRecord` from a DynamoDB item.
    pub(crate) fn from_stored(config: OrgConfig, etag: Etag) -> Self {
        Self { config, etag }
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
    /// `(org_id, group_name)` → stored group + etag.
    groups: tokio::sync::RwLock<BTreeMap<(OrganizationId, String), EtagedGroup>>,
    /// `(org_id, user_id)` → group names the user belongs to.
    ///
    /// Added in V2 to allow delete-conflict pre-checks to be exercised in
    /// InMemory tests. Production memberships live in DynamoDB only (Group E).
    memberships_to_groups: tokio::sync::RwLock<BTreeMap<(OrganizationId, String), Vec<String>>>,
}

impl InMemoryOrgStore {
    pub(crate) fn new(orgs: BTreeMap<OrganizationId, OrgRecord>) -> Self {
        Self {
            orgs: tokio::sync::RwLock::new(orgs),
            signing_keys: tokio::sync::RwLock::new(BTreeMap::new()),
            groups: tokio::sync::RwLock::new(BTreeMap::new()),
            memberships_to_groups: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    /// Test fixture: write a membership row into the in-memory store.
    ///
    /// This is intentionally only available under `#[cfg(test)]` — it is a
    /// seeding helper for integration tests that exercise delete-conflict
    /// pre-checks (F.4 / `groups_delete.rs`). Production paths write
    /// memberships only via Group E (DynamoDB).
    ///
    /// Calls for the same `(org_id, user_id)` key overwrite (not append).
    /// Tests that need multiple group memberships for one user must pass them
    /// all in a single `groups` vector.
    #[cfg(test)]
    pub(crate) async fn seed_membership(
        &self,
        org_id: &OrganizationId,
        user_id: &str,
        groups: Vec<String>,
    ) {
        let mut m = self.memberships_to_groups.write().await;
        m.insert((org_id.clone(), user_id.to_owned()), groups);
    }
}

#[async_trait]
impl OrgStore for InMemoryOrgStore {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>> {
        let guard = self.orgs.read().await;
        Ok(guard.get(org_id).cloned())
    }

    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>> {
        let guard = self.orgs.read().await;
        Ok(guard.values().skip(offset).take(limit).cloned().collect())
    }

    async fn write_through_org(&self, org: Organization, config: Option<OrgConfig>) {
        let org_id = org.org_id().clone();
        let configured = config.map(ConfiguredConfig::compute);
        let record = OrgRecord::new(org, configured);
        let mut guard = self.orgs.write().await;
        guard.insert(org_id, record);
    }

    async fn write_through_signing_keys(
        &self,
        org_id: &OrganizationId,
        keys: Vec<SigningKeyEntry>,
    ) {
        let mut guard = self.signing_keys.write().await;
        guard.insert(org_id.clone(), keys);
    }

    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        let guard = self.signing_keys.read().await;
        Ok(guard.get(org_id).cloned().unwrap_or_default())
    }

    async fn write_through_group(&self, org_id: &OrganizationId, entry: EtagedGroup) {
        let mut g = self.groups.write().await;
        g.insert((org_id.clone(), entry.entry().name.clone()), entry);
    }

    async fn write_through_group_delete(&self, org_id: &OrganizationId, name: &str) {
        let mut g = self.groups.write().await;
        g.remove(&(org_id.clone(), name.to_string()));
    }

    // -----------------------------------------------------------------------
    // Group CRUD (V2)
    // -----------------------------------------------------------------------

    async fn get_group(&self, org_id: &OrganizationId, name: &str) -> Result<Option<EtagedGroup>> {
        let g = self.groups.read().await;
        Ok(g.get(&(org_id.clone(), name.to_string())).cloned())
    }

    async fn list_groups(&self, org_id: &OrganizationId) -> Result<Vec<EtagedGroup>> {
        let g = self.groups.read().await;
        // BTreeMap is already sorted by key; the key is `(org_id, name)` so
        // filtering on `org_id` yields entries in ascending `name` order.
        let result = g
            .range((org_id.clone(), String::new())..)
            .take_while(|((oid, _), _)| oid == org_id)
            .map(|(_, v)| v.clone())
            .collect();
        Ok(result)
    }

    async fn list_inheritors(&self, org_id: &OrganizationId, name: &str) -> Result<Vec<String>> {
        let g = self.groups.read().await;
        let inheritors = g
            .range((org_id.clone(), String::new())..)
            .take_while(|((oid, _), _)| oid == org_id)
            .filter(|(_, eg)| eg.entry().inherits.iter().any(|i| i == name))
            .map(|((_, group_name), _)| group_name.clone())
            .collect();
        Ok(inheritors)
    }

    async fn count_memberships_for_group(
        &self,
        org_id: &OrganizationId,
        name: &str,
    ) -> Result<BTreeMap<String, u32>> {
        let m = self.memberships_to_groups.read().await;
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        for ((oid, user_id), groups) in m.iter() {
            if oid == org_id && groups.iter().any(|g| g == name) {
                *counts.entry(user_id.clone()).or_insert(0) += 1;
            }
        }
        Ok(counts)
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
    #[serde(default = "default_raw_status")]
    status: OrgStatus,
}

fn default_raw_status() -> OrgStatus {
    OrgStatus::Draft
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

pub(crate) fn compute_etag(config: &OrgConfig) -> Etag {
    compute_etag_json(config)
}

/// Compute a deterministic ETag from any serializable value.
///
/// Serialises `value` to JSON, takes the xxHash-64 of the UTF-8 bytes, and
/// wraps the 16-hex-digit hash in RFC 7232 strong-etag quotes (e.g.
/// `"a1b2c3d4e5f60708"`). Used by both proxy-config and user-schema rows so
/// that the on-wire etag format is identical across sub-resources.
pub(crate) fn compute_etag_json<T: serde::Serialize>(value: &T) -> Etag {
    // serde_json::to_string is infallible for a well-typed struct with no
    // non-string map keys; fall back to an empty slice so the hash is still
    // deterministic on the (unreachable) error branch.
    let json = serde_json::to_string(value).unwrap_or_default();
    let hash = xxhash_rust::xxh64::xxh64(json.as_bytes(), 0);
    // The formatted string is always 18 bytes ("hex16" + two quote chars),
    // so from_validated's non-empty invariant is always satisfied.
    Etag::from_validated(format!("\"{hash:016x}\""))
}

pub(crate) fn build_org_store(json_str: &str) -> Result<InMemoryOrgStore> {
    let raw: RawOrgFile =
        serde_json::from_str(json_str).map_err(|e| Error::Config(e.to_string()))?;

    let now = Utc::now();
    let mut orgs = BTreeMap::new();

    for (raw_id, raw_entry) in raw.organizations {
        let org_id = OrganizationId::new(&raw_id)
            .map_err(|e| Error::Config(format!("invalid organization id {raw_id:?}: {e}")))?;

        let configured = raw_entry.config.map(ConfiguredConfig::compute);
        let status = raw_entry.status;

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

#[cfg(test)]
mod tests;
