//! Shared DynamoDB table schema — parsed from
//! `infra/control-plane/schema/forgeguard-orgs.json`.
//!
//! This is the single source of truth for key attribute names and item type
//! patterns, consumed by both the CDK (TypeScript) and Rust at compile time.

use std::collections::HashMap;

use serde::Deserialize;

/// Full table schema parsed from the shared JSON file.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableSchema {
    pub(crate) partition_key: String,
    pub(crate) sort_key: String,
    pub(crate) item_types: HashMap<String, ItemType>,
}

/// One item type definition within the table.
#[derive(Deserialize)]
pub(crate) struct ItemType {
    pub(crate) pk: String,
    pub(crate) sk: String,
}

const SCHEMA_JSON: &str = include_str!("../../../infra/control-plane/schema/forgeguard-orgs.json");

/// Parse the orgs table schema from the compile-time-embedded JSON.
pub(crate) fn orgs_schema() -> &'static TableSchema {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<TableSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| match serde_json::from_str(SCHEMA_JSON) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("BUG: forgeguard-orgs.json schema is invalid: {e}");
            std::process::abort();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_schema() {
        let schema = orgs_schema();
        assert_eq!(schema.partition_key, "PK");
        assert_eq!(schema.sort_key, "SK");

        #[allow(clippy::expect_used)]
        let org = schema
            .item_types
            .get("org")
            .expect("missing 'org' item type");
        assert_eq!(org.pk, "ORG#{org_id}");
        assert_eq!(org.sk, "META");
    }
}
