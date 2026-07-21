//! Fixtures for Active-org group tests (#117 V2).
//!
//! - `active_org_store` — seeds an `InMemoryOrgStore` with one Active org.
//!   `vp_store_id` in its config is inert data since #117 V2 (group writes no
//!   longer push to Verified Permissions).
//! - `group_body` — builds a POST/PUT `/groups` request body.

use std::sync::Arc;

use crate::store::{build_org_store, OrgStore};

pub(super) fn active_org_store(org_id: &str, vp_store_id: &str) -> Arc<dyn OrgStore> {
    let json = format!(
        r#"{{
            "organizations": {{
                "{org_id}": {{
                    "name": "Active Org",
                    "status": "active",
                    "config": {{
                        "version": "2026-04-07",
                        "project_id": "test-app",
                        "upstream_url": "https://api.example.com",
                        "default_policy": "deny",
                        "vp_store_id": "{vp_store_id}",
                        "routes": [],
                        "public_routes": [],
                        "features": {{}}
                    }}
                }}
            }}
        }}"#
    );
    Arc::new(build_org_store(&json).unwrap())
}

/// Build a POST /groups body. Pass `inherits: &[]` when the group has no
/// parent groups.
pub(super) fn group_body(name: &str, allow: &[&str], inherits: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": name,
        "allow": allow,
        "inherits": inherits,
    }))
    .unwrap()
}
