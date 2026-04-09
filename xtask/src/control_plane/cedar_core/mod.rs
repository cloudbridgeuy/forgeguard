pub(crate) mod config;
pub(crate) mod desired;
pub(crate) mod store;
pub(crate) mod sync;

use std::fmt;

/// VP policy store identifier.
///
/// Wraps a raw string to prevent accidental misuse in unrelated contexts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyStoreId(String);

impl PolicyStoreId {
    pub(crate) fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyStoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// Re-export all public items so external callers can continue using
// `cedar_core::CedarSyncConfig`, `cedar_core::SyncPlan`, etc.
pub(crate) use config::CedarSyncConfig;
pub(crate) use desired::build_desired_state;
pub(crate) use store::{format_status, StorePolicy, StoreState, StoreTemplate};

pub(crate) use sync::{compute_sync_plan, format_summary, SyncAction, SyncPlan, SyncResult};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_store_id_display() {
        let id = PolicyStoreId::new("ps-abc123");
        assert_eq!(id.to_string(), "ps-abc123");
        assert_eq!(id.as_str(), "ps-abc123");
    }
}
