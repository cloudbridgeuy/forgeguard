//! DynamoDB codec for group items.
//!
//! Pure data manipulation — no I/O, no async, no AWS SDK calls.
//! Only manipulates `HashMap<String, AttributeValue>` values.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authz_core::RbacEntry;
use forgeguard_core::OrganizationId;

use crate::dynamo_store::{pk, sk, ORG_PREFIX};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Prefix for group sort keys in DynamoDB (e.g. `"GROUP#admin"`).
pub(crate) const SK_GROUP_PREFIX: &str = "GROUP#";

/// Build the partition key value for a group item: `"ORG#{org_id}"`.
pub(crate) fn group_pk(org_id: &OrganizationId) -> String {
    format!("{ORG_PREFIX}{org_id}")
}

/// Build the sort key value for a group item: `"GROUP#{name}"`.
pub(crate) fn group_sk(name: &str) -> String {
    format!("{SK_GROUP_PREFIX}{name}")
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn put_s(item: &mut HashMap<String, AttributeValue>, key: &str, value: impl Into<String>) {
    item.insert(key.to_owned(), AttributeValue::S(value.into()));
}

fn get_s(item: &HashMap<String, AttributeValue>, key: &str) -> Result<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .ok_or_else(|| Error::Store(format!("missing or non-string group attribute: {key}")))
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Serialize a group `RbacEntry` + etag into a DynamoDB item map.
///
/// The `config` attribute stores the JSON-serialized `RbacEntry`. The `etag`
/// attribute stores the precomputed etag string (caller's responsibility to
/// compute it via `compute_group_etag` in `pure.rs`).
pub(crate) fn to_group_item(
    org_id: &OrganizationId,
    entry: &RbacEntry,
    etag: &str,
) -> Result<HashMap<String, AttributeValue>> {
    let mut item = HashMap::new();

    put_s(&mut item, pk(), group_pk(org_id));
    put_s(&mut item, sk(), group_sk(&entry.name));

    let config_json = serde_json::to_string(entry)
        .map_err(|e| Error::Store(format!("serialize group entry: {e}")))?;
    put_s(&mut item, "config", config_json);
    put_s(&mut item, "etag", etag);

    Ok(item)
}

/// Deserialize a DynamoDB item into an `(RbacEntry, String)` tuple.
///
/// The `String` is the stored etag. Returns `Error::Store` for any integrity
/// violation (missing attributes, bad JSON, mismatched SK prefix).
pub(crate) fn from_group_item(
    item: &HashMap<String, AttributeValue>,
) -> Result<(RbacEntry, String)> {
    // Verify the SK has the expected prefix and extract the group name suffix.
    let sort_key = get_s(item, sk())?;
    let sk_name = sort_key.strip_prefix(SK_GROUP_PREFIX).ok_or_else(|| {
        Error::Store(format!(
            "group item has unexpected SK (missing {SK_GROUP_PREFIX} prefix): {sort_key:?}"
        ))
    })?;

    let config_json = get_s(item, "config")?;
    let entry: RbacEntry = serde_json::from_str(&config_json)
        .map_err(|e| Error::Store(format!("deserialize group config: {e}")))?;

    let etag = get_s(item, "etag")?;

    // Integrity check: the name in the entry must match the SK suffix.
    if entry.name != sk_name {
        return Err(Error::Store(format!(
            "group item name mismatch: SK says {sk_name:?} but config.name is {:?}",
            entry.name
        )));
    }

    Ok((entry, etag))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::OrganizationId;

    use super::*;
    use crate::handlers::groups::pure::compute_group_etag;

    fn test_org_id() -> OrganizationId {
        OrganizationId::new("org-acme").unwrap()
    }

    fn make_entry(name: &str) -> RbacEntry {
        RbacEntry {
            name: name.to_owned(),
            description: Some("Test role".to_owned()),
            inherits: vec![],
            allow: vec!["cp:x:read".to_owned(), "cp:y:write".to_owned()],
            tenant_scoped: true,
        }
    }

    // -----------------------------------------------------------------------
    // Key helpers
    // -----------------------------------------------------------------------

    #[test]
    fn group_pk_format() {
        let org_id = test_org_id();
        assert_eq!(group_pk(&org_id), "ORG#org-acme");
    }

    #[test]
    fn group_sk_format() {
        assert_eq!(group_sk("admin"), "GROUP#admin");
    }

    // -----------------------------------------------------------------------
    // Round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn to_and_from_group_item_round_trip() {
        let org_id = test_org_id();
        let entry = make_entry("admin");
        let etag = compute_group_etag(&entry).unwrap();

        let item = to_group_item(&org_id, &entry, &etag).unwrap();
        let (recovered_entry, recovered_etag) = from_group_item(&item).unwrap();

        assert_eq!(recovered_entry.name, entry.name);
        assert_eq!(recovered_entry.description, entry.description);
        assert_eq!(recovered_entry.inherits, entry.inherits);
        assert_eq!(recovered_entry.allow, entry.allow);
        assert_eq!(recovered_entry.tenant_scoped, entry.tenant_scoped);
        assert_eq!(recovered_etag, etag);
    }

    #[test]
    fn from_group_item_tampered_etag_attribute_yields_store_error() {
        let org_id = test_org_id();
        let entry = make_entry("member");
        let etag = compute_group_etag(&entry).unwrap();

        let mut item = to_group_item(&org_id, &entry, &etag).unwrap();
        // Tamper the etag attribute with a wrong-type value to force a parse error.
        item.insert("etag".to_owned(), AttributeValue::N("999".to_owned()));

        let err = from_group_item(&item).unwrap_err();
        assert!(
            matches!(err, Error::Store(_)),
            "expected Store error, got: {err:?}"
        );
    }

    #[test]
    fn from_group_item_tampered_config_attribute_yields_store_error() {
        let org_id = test_org_id();
        let entry = make_entry("viewer");
        let etag = compute_group_etag(&entry).unwrap();

        let mut item = to_group_item(&org_id, &entry, &etag).unwrap();
        // Replace config JSON with invalid JSON.
        item.insert(
            "config".to_owned(),
            AttributeValue::S("not-valid-json{".to_owned()),
        );

        let err = from_group_item(&item).unwrap_err();
        assert!(
            matches!(err, Error::Store(_)),
            "expected Store error, got: {err:?}"
        );
    }

    #[test]
    fn from_group_item_missing_sk_prefix_yields_store_error() {
        let org_id = test_org_id();
        let entry = make_entry("admin");
        let etag = compute_group_etag(&entry).unwrap();

        let mut item = to_group_item(&org_id, &entry, &etag).unwrap();
        // Replace SK with something that doesn't have the GROUP# prefix.
        item.insert(sk().to_owned(), AttributeValue::S("META".to_owned()));

        let err = from_group_item(&item).unwrap_err();
        assert!(
            matches!(err, Error::Store(_)),
            "expected Store error, got: {err:?}"
        );
    }

    #[test]
    fn from_group_item_name_mismatch_between_sk_and_config_yields_store_error() {
        let org_id = test_org_id();
        // Build an item for "admin", then tamper the SK to say "member".
        // The config blob still says "admin", so the integrity check must fail.
        let entry = make_entry("admin");
        let etag = compute_group_etag(&entry).unwrap();

        let mut item = to_group_item(&org_id, &entry, &etag).unwrap();
        item.insert(
            sk().to_owned(),
            AttributeValue::S("GROUP#member".to_owned()),
        );

        let err = from_group_item(&item).unwrap_err();
        assert!(
            matches!(err, Error::Store(_)),
            "expected Store error for SK/config name mismatch, got: {err:?}"
        );
    }
}
