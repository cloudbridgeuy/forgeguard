use std::collections::BTreeMap;

use forgeguard_core::{OrganizationId, ProjectId};
use forgeguard_http::{DefaultPolicy, HttpMethod, PublicAuthMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OrgProxyConfig {
    pub(crate) organization_id: OrganizationId,
    pub(crate) cognito_pool_id: String,
    pub(crate) cognito_jwks_url: String,
    pub(crate) policy_store_id: String,
    pub(crate) project_id: ProjectId,
    pub(crate) upstream_url: String,
    pub(crate) default_policy: DefaultPolicy,
    #[serde(default)]
    pub(crate) routes: Vec<RouteEntry>,
    #[serde(default)]
    pub(crate) public_routes: Vec<PublicRouteEntry>,
    #[serde(default)]
    pub(crate) features: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RouteEntry {
    pub(crate) method: HttpMethod,
    pub(crate) path: String,
    pub(crate) action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resource_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) feature_gate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicRouteEntry {
    pub(crate) method: HttpMethod,
    pub(crate) path: String,
    pub(crate) auth_mode: PublicAuthMode,
}
