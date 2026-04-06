use std::collections::HashMap;
use std::path::Path;

use forgeguard_core::OrganizationId;
use serde::Deserialize;

use crate::config::OrgProxyConfig;
use crate::error::{Error, Result};

/// Abstraction over organization config storage.
///
/// Implementations: `OrgConfigStore` (in-memory, loaded from file or built programmatically).
/// Future: S3-backed store for production.
pub(crate) trait OrgStore: Send + Sync {
    fn get(&self, org_id: &OrganizationId) -> Option<&OrgEntry>;
}

#[derive(Debug, Clone)]
pub(crate) struct OrgEntry {
    config: OrgProxyConfig,
    etag: String,
}

impl OrgEntry {
    pub(crate) fn config(&self) -> &OrgProxyConfig {
        &self.config
    }

    pub(crate) fn etag(&self) -> &str {
        &self.etag
    }
}

#[cfg(test)]
impl OrgEntry {
    /// Create a new `OrgEntry`. Computes ETag from the config.
    pub(crate) fn new(config: OrgProxyConfig) -> Result<Self> {
        let etag = compute_etag(&config)?;
        Ok(Self { config, etag })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OrgConfigStore {
    orgs: HashMap<OrganizationId, OrgEntry>,
}

#[cfg(test)]
impl OrgConfigStore {
    /// Create a store from pre-built entries. Used by tests and future in-memory backends.
    pub(crate) fn from_entries(entries: Vec<(OrganizationId, OrgEntry)>) -> Self {
        Self {
            orgs: entries.into_iter().collect(),
        }
    }
}

impl OrgStore for OrgConfigStore {
    fn get(&self, org_id: &OrganizationId) -> Option<&OrgEntry> {
        self.orgs.get(org_id)
    }
}

#[derive(Debug, Deserialize)]
struct RawOrgFile {
    organizations: HashMap<String, RawOrgEntry>,
}

#[derive(Debug, Deserialize)]
struct RawOrgEntry {
    config: OrgProxyConfig,
}

pub(crate) fn compute_etag(config: &OrgProxyConfig) -> Result<String> {
    let json = serde_json::to_string(config).map_err(|e| Error::Config(e.to_string()))?;
    let hash = xxhash_rust::xxh64::xxh64(json.as_bytes(), 0);
    Ok(format!("\"{hash:016x}\""))
}

pub(crate) fn build_org_store(json_str: &str) -> Result<OrgConfigStore> {
    let raw: RawOrgFile =
        serde_json::from_str(json_str).map_err(|e| Error::Config(e.to_string()))?;

    let mut orgs = HashMap::new();

    for (raw_id, raw_entry) in raw.organizations {
        let org_id = OrganizationId::new(&raw_id)
            .map_err(|e| Error::Config(format!("invalid organization id {raw_id:?}: {e}")))?;

        if org_id != raw_entry.config.organization_id {
            return Err(Error::Config(format!(
                "organization key '{raw_id}' does not match config organization_id '{}'",
                raw_entry.config.organization_id
            )));
        }

        let etag = compute_etag(&raw_entry.config)?;

        orgs.insert(
            org_id,
            OrgEntry {
                config: raw_entry.config,
                etag,
            },
        );
    }

    Ok(OrgConfigStore { orgs })
}

pub(crate) fn load_config_file(path: &Path) -> color_eyre::Result<OrgConfigStore> {
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
                    "config": {
                        "organization_id": "org-acme",
                        "cognito_pool_id": "us-east-1_ABC",
                        "cognito_jwks_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC/.well-known/jwks.json",
                        "policy_store_id": "ps-123",
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

    #[test]
    fn build_org_store_valid_json() {
        let store = build_org_store(sample_json()).unwrap();
        let org_id = OrganizationId::new("org-acme").unwrap();
        let entry = store.get(&org_id).unwrap();
        assert_eq!(
            entry.config().organization_id,
            OrganizationId::new("org-acme").unwrap()
        );
        assert_eq!(
            entry.config().default_policy,
            forgeguard_http::DefaultPolicy::Deny
        );
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
                    "config": {
                        "organization_id": "UPPER-CASE",
                        "cognito_pool_id": "pool",
                        "cognito_jwks_url": "https://example.com",
                        "policy_store_id": "ps",
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

    #[test]
    fn build_org_store_empty_organizations() {
        let json = r#"{ "organizations": {} }"#;
        let store = build_org_store(json).unwrap();
        let org_id = OrganizationId::new("org-acme").unwrap();
        assert!(store.get(&org_id).is_none());
    }

    #[test]
    fn build_org_store_multiple_orgs() {
        let json = r#"{
            "organizations": {
                "org-alpha": {
                    "config": {
                        "organization_id": "org-alpha",
                        "cognito_pool_id": "pool-a",
                        "cognito_jwks_url": "https://example.com/a",
                        "policy_store_id": "ps-a",
                        "project_id": "proj-a",
                        "upstream_url": "https://alpha.com",
                        "default_policy": "deny"
                    }
                },
                "org-beta": {
                    "config": {
                        "organization_id": "org-beta",
                        "cognito_pool_id": "pool-b",
                        "cognito_jwks_url": "https://example.com/b",
                        "policy_store_id": "ps-b",
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
        assert!(store.get(&alpha).is_some());
        assert!(store.get(&beta).is_some());
        assert_eq!(
            store.get(&alpha).unwrap().config().upstream_url,
            "https://alpha.com"
        );
        assert_eq!(
            store.get(&beta).unwrap().config().default_policy,
            forgeguard_http::DefaultPolicy::Passthrough
        );
    }

    #[test]
    fn compute_etag_deterministic() {
        let store = build_org_store(sample_json()).unwrap();
        let org_id = OrganizationId::new("org-acme").unwrap();
        let entry = store.get(&org_id).unwrap();

        let etag1 = compute_etag(entry.config()).unwrap();
        let etag2 = compute_etag(entry.config()).unwrap();
        assert_eq!(etag1, etag2);
    }

    #[test]
    fn build_org_store_mismatched_org_id() {
        let json = r#"{
            "organizations": {
                "org-acme": {
                    "config": {
                        "organization_id": "org-other",
                        "cognito_pool_id": "us-east-1_ABC",
                        "cognito_jwks_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC/.well-known/jwks.json",
                        "policy_store_id": "ps-123",
                        "project_id": "todo-app",
                        "upstream_url": "https://api.acme.com",
                        "default_policy": "deny"
                    }
                }
            }
        }"#;
        let result = build_org_store(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not match"),
            "expected mismatch error, got: {err}"
        );
    }

    #[test]
    fn compute_etag_quoted_hex_format() {
        let store = build_org_store(sample_json()).unwrap();
        let org_id = OrganizationId::new("org-acme").unwrap();
        let entry = store.get(&org_id).unwrap();

        let etag = compute_etag(entry.config()).unwrap();
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
}
