//! Authorization context carried alongside a policy query.

use std::collections::HashMap;
use std::net::IpAddr;

use forgeguard_core::{GroupName, TenantId};

/// Contextual information for policy evaluation.
///
/// Carries tenant, group membership, IP address, and arbitrary attributes
/// that policy rules may inspect.
pub struct PolicyContext {
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    ip_address: Option<IpAddr>,
    attributes: HashMap<String, serde_json::Value>,
}

impl PolicyContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self {
            tenant_id: None,
            groups: Vec::new(),
            ip_address: None,
            attributes: HashMap::new(),
        }
    }

    /// Set the tenant ID.
    pub fn with_tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Set group membership.
    pub fn with_groups(mut self, groups: Vec<GroupName>) -> Self {
        self.groups = groups;
        self
    }

    /// Set the source IP address.
    pub fn with_ip_address(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Add an arbitrary attribute.
    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Borrow the tenant ID.
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Borrow the group list.
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }

    /// Borrow the IP address.
    pub fn ip_address(&self) -> Option<IpAddr> {
        self.ip_address
    }

    /// Borrow the attributes map.
    pub fn attributes(&self) -> &HashMap<String, serde_json::Value> {
        &self.attributes
    }
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self::new()
    }
}
