//! Raw serde structs for TOML deserialization.
//!
//! These mirror the TOML shape with `String` fields. The validated domain types
//! are produced via `TryFrom<RawProxyConfig> for ProxyConfig` (Parse Don't Validate).

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

/// Raw authorization config.
#[derive(Debug, Deserialize)]
pub(crate) struct RawAuthzConfig {
    pub(crate) policy_store_id: Option<String>,
    pub(crate) aws_region: Option<String>,
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
