//! Raw serde structs for TOML deserialization.
//!
//! These mirror the TOML shape with `String` fields. The validated domain types
//! are produced via `TryFrom<RawProxyConfig> for ProxyConfig` (Parse Don't Validate).

use std::collections::HashMap;

use std::fmt;

use serde::Deserialize;

/// Top-level raw config as it appears in `forgeguard.toml`.
#[derive(Debug, Deserialize)]
pub(crate) struct RawProxyConfig {
    pub(crate) project_id: String,
    pub(crate) listen_addr: String,
    pub(crate) upstream_url: String,
    #[serde(default = "default_policy")]
    pub(crate) default_policy: String,
    #[serde(default = "default_client_ip_source")]
    pub(crate) client_ip_source: String,
    #[serde(default)]
    pub(crate) auth: Option<RawAuthConfig>,
    #[serde(default)]
    pub(crate) authz: Option<RawAuthzConfig>,
    #[serde(default)]
    pub(crate) metrics: Option<RawMetricsConfig>,
    #[serde(default)]
    pub(crate) routes: Vec<RawRouteMapping>,
    #[serde(default)]
    pub(crate) public_routes: Vec<RawPublicRoute>,
    #[serde(default)]
    pub(crate) policies: Vec<forgeguard_core::Policy>,
    #[serde(default)]
    pub(crate) groups: Vec<forgeguard_core::GroupDefinition>,
    #[serde(default)]
    pub(crate) features: Option<RawFlagConfig>,
    #[serde(default)]
    pub(crate) aws: Option<RawAwsConfig>,
    #[serde(default)]
    pub(crate) schema: Option<RawSchemaConfig>,
    #[serde(default)]
    pub(crate) cors: Option<crate::cors::RawCorsConfig>,
    #[serde(default)]
    pub(crate) cluster: Option<RawClusterConfig>,
    #[serde(default)]
    pub(crate) authn: Option<RawAuthnConfig>,
    #[serde(default)]
    pub(crate) api_keys: Vec<RawApiKeyEntry>,
    #[serde(default)]
    pub(crate) policy_tests: Vec<RawPolicyTest>,
}

/// Raw feature flag configuration.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawFlagConfig {
    #[serde(default)]
    pub(crate) flags:
        std::collections::HashMap<forgeguard_core::FlagName, forgeguard_core::FlagDefinition>,
}

fn default_policy() -> String {
    "deny".to_string()
}

fn default_client_ip_source() -> String {
    "peer".to_string()
}

/// Raw authentication config.
#[derive(Debug, Deserialize)]
pub(crate) struct RawAuthConfig {
    #[serde(default)]
    pub(crate) chain_order: Vec<String>,
}

/// Raw authentication provider configuration.
/// Maps the `[authn]` TOML section.
#[derive(Debug, Deserialize)]
pub(crate) struct RawAuthnConfig {
    #[serde(default)]
    pub(crate) jwt: Option<RawJwtConfig>,
}

/// Raw JWT resolver configuration.
/// Maps the `[authn.jwt]` TOML section.
#[derive(Debug, Deserialize)]
pub(crate) struct RawJwtConfig {
    pub(crate) jwks_url: String,
    pub(crate) issuer: String,
    #[serde(default)]
    pub(crate) audience: Option<String>,
    #[serde(default)]
    pub(crate) user_id_claim: Option<String>,
    #[serde(default)]
    pub(crate) tenant_claim: Option<String>,
    #[serde(default)]
    pub(crate) groups_claim: Option<String>,
    #[serde(default)]
    pub(crate) cache_ttl_secs: Option<u64>,
}

/// Raw static API key entry.
/// Maps each `[[api_keys]]` TOML entry.
#[derive(Deserialize)]
pub(crate) struct RawApiKeyEntry {
    pub(crate) key: String,
    pub(crate) user_id: String,
    #[serde(default)]
    pub(crate) tenant_id: Option<String>,
    #[serde(default)]
    pub(crate) groups: Vec<String>,
}

impl fmt::Debug for RawApiKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawApiKeyEntry")
            .field("key", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("tenant_id", &self.tenant_id)
            .field("groups", &self.groups)
            .finish()
    }
}

/// Raw authorization config.
#[derive(Debug, Deserialize)]
pub(crate) struct RawAuthzConfig {
    pub(crate) policy_store_id: Option<String>,
    #[serde(default = "default_cache_ttl_secs")]
    pub(crate) cache_ttl_secs: u64,
    #[serde(default = "default_cache_max_entries")]
    pub(crate) cache_max_entries: usize,
}

fn default_cache_ttl_secs() -> u64 {
    300
}

fn default_cache_max_entries() -> usize {
    10_000
}

/// Raw metrics config.
#[derive(Debug, Deserialize)]
pub(crate) struct RawMetricsConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) listen_addr: Option<String>,
}

/// Raw route mapping.
#[derive(Debug, Deserialize)]
pub(crate) struct RawRouteMapping {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) action: String,
    pub(crate) resource_param: Option<String>,
    pub(crate) feature_gate: Option<String>,
}

/// Raw public route.
#[derive(Debug, Deserialize)]
pub(crate) struct RawPublicRoute {
    pub(crate) method: String,
    pub(crate) path: String,
    #[serde(default = "default_auth_mode")]
    pub(crate) auth_mode: String,
}

fn default_auth_mode() -> String {
    "anonymous".to_string()
}

/// Raw AWS configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct RawAwsConfig {
    pub(crate) region: Option<String>,
    pub(crate) profile: Option<String>,
}

/// Raw cluster configuration.
/// Maps the `[cluster]` TOML section.
#[derive(Debug, Deserialize)]
pub(crate) struct RawClusterConfig {
    pub(crate) redis_url: String,
    #[serde(default = "default_instance_id")]
    pub(crate) instance_id: String,
    #[serde(default = "default_priority")]
    pub(crate) priority: u8,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub(crate) heartbeat_interval_secs: u64,
    #[serde(default = "default_min_quorum")]
    pub(crate) min_quorum: usize,
    pub(crate) listen_cluster_addr: Option<String>,
}

fn default_instance_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn default_priority() -> u8 {
    1
}

fn default_heartbeat_interval_secs() -> u64 {
    5
}

fn default_min_quorum() -> usize {
    1
}

/// Raw entity schema definition.
#[derive(Debug, Deserialize)]
pub(crate) struct RawEntitySchema {
    #[serde(default)]
    pub(crate) member_of: Vec<String>,
    #[serde(default)]
    pub(crate) attributes: HashMap<String, String>,
}

/// Raw schema configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct RawSchemaConfig {
    #[serde(default)]
    pub(crate) entities: HashMap<String, HashMap<String, RawEntitySchema>>,
}

/// Raw policy test definition.
#[derive(Debug, Deserialize)]
pub(crate) struct RawPolicyTest {
    pub(crate) name: String,
    pub(crate) principal: String,
    #[serde(default)]
    pub(crate) groups: Vec<String>,
    pub(crate) tenant: String,
    pub(crate) action: String,
    pub(crate) resource: Option<String>,
    pub(crate) expect: String,
}
