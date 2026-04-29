//! Organization proxy configuration types.

use std::collections::BTreeMap;

use forgeguard_core::{ConfigVersion, DefaultPolicy, ProjectId};
use forgeguard_http::{HttpMethod, PublicAuthMode};
use serde::{Deserialize, Serialize};

pub(crate) use forgeguard_authz_core::TenantConfig;

fn default_namespace() -> String {
    "app".to_string()
}

/// Versioned organization proxy configuration.
///
/// This is the org-configurable subset of `forgeguard.toml`.
/// Stored as JSON in the control plane, served via the proxy-config endpoint.
/// Version follows AWS-style date format (e.g. "2026-04-07").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OrgConfig {
    version: ConfigVersion,
    project_id: ProjectId,
    upstream_url: String,
    default_policy: DefaultPolicy,
    #[serde(default = "default_namespace")]
    namespace: String,
    #[serde(default)]
    tenant: TenantConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vp_store_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cognito_user_pool_id: Option<String>,
    #[serde(default)]
    routes: Vec<RouteEntry>,
    #[serde(default)]
    public_routes: Vec<PublicRouteEntry>,
    #[serde(default)]
    features: BTreeMap<String, serde_json::Value>,
}

impl OrgConfig {
    #[cfg(test)]
    pub(crate) fn version(&self) -> &ConfigVersion {
        &self.version
    }

    #[cfg(test)]
    pub(crate) fn upstream_url(&self) -> &str {
        &self.upstream_url
    }

    #[cfg(test)]
    pub(crate) fn default_policy(&self) -> DefaultPolicy {
        self.default_policy
    }

    #[cfg(test)]
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    #[cfg(test)]
    pub(crate) fn tenant(&self) -> &TenantConfig {
        &self.tenant
    }

    #[cfg(test)]
    pub(crate) fn vp_store_id(&self) -> Option<&str> {
        self.vp_store_id.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn cognito_user_pool_id(&self) -> Option<&str> {
        self.cognito_user_pool_id.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RouteEntry {
    method: HttpMethod,
    path: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    feature_gate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicRouteEntry {
    method: HttpMethod,
    path: String,
    auth_mode: PublicAuthMode,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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

    #[test]
    fn deserialize_minimal() {
        let config = sample_config();
        assert_eq!(config.version().as_str(), "2026-04-07");
        assert_eq!(config.upstream_url(), "https://api.acme.com");
        assert_eq!(config.default_policy(), DefaultPolicy::Deny);
    }

    #[test]
    fn serde_round_trip() {
        let config = sample_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: OrgConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version(), config.version());
        assert_eq!(back.upstream_url(), config.upstream_url());
    }

    #[test]
    fn defaults_for_optional_fields() {
        let config: OrgConfig = serde_json::from_value(serde_json::json!({
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "passthrough"
        }))
        .unwrap();
        assert!(config.routes.is_empty());
        assert!(config.public_routes.is_empty());
        assert!(config.features.is_empty());
    }

    #[test]
    fn deserialize_defaults_for_new_fields() {
        let config: OrgConfig = serde_json::from_value(serde_json::json!({
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny"
        }))
        .unwrap();
        assert_eq!(config.namespace(), "app");
        assert!(config.tenant().enabled);
        assert_eq!(config.tenant().principal_attribute, "tenant_id");
        assert_eq!(config.tenant().resource_attribute, "tenant_id");
        assert!(config.vp_store_id().is_none());
        assert!(config.cognito_user_pool_id().is_none());
    }

    #[test]
    fn round_trip_with_all_new_fields_set() {
        let config: OrgConfig = serde_json::from_value(serde_json::json!({
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny",
            "namespace": "customer-app",
            "tenant": {"enabled": false, "principal_attribute": "org", "resource_attribute": "org"},
            "vp_store_id": "ps-abc",
            "cognito_user_pool_id": "us-east-2_xyz"
        }))
        .unwrap();
        let json = serde_json::to_string(&config).unwrap();
        let back: OrgConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.namespace(), "customer-app");
        assert!(!back.tenant().enabled);
        assert_eq!(back.tenant().principal_attribute, "org");
        assert_eq!(back.vp_store_id(), Some("ps-abc"));
        assert_eq!(back.cognito_user_pool_id(), Some("us-east-2_xyz"));
    }

    #[test]
    fn pre_existing_payload_compat() {
        let config = sample_config();
        assert_eq!(config.namespace(), "app");
        assert!(config.tenant().enabled);
        assert!(config.vp_store_id().is_none());
        assert!(config.cognito_user_pool_id().is_none());
    }

    #[test]
    fn namespace_explicit_value_overrides_default() {
        let config: OrgConfig = serde_json::from_value(serde_json::json!({
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny",
            "namespace": "customer-app"
        }))
        .unwrap();
        assert_eq!(config.namespace(), "customer-app");
    }
}
