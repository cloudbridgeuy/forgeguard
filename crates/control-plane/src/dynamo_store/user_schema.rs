//! DynamoDB codec helpers and condition-expression builders for user-schema
//! CRUD.
//!
//! Most of this file is pure: `build_user_schema_put_condition`,
//! `to_user_schema_item`, and `etaged_user_schema_from_item` are deterministic,
//! no-I/O helpers that live here because they don't need access to
//! `DynamoOrgStore`'s private fields.
//!
//! `recover_user_schema_etag` is the one async/I/O helper. It lives here
//! (rather than in `mod.rs`) because it is a thin wrapper over the public
//! `OrgStore::get_user_schema` method and pairs naturally with the pure
//! `build_user_schema_put_condition` it complements in the `put_user_schema`
//! call-site.
//!
//! The `impl OrgStore for DynamoOrgStore` method bodies that drive the AWS SDK
//! live in [`super`] (`dynamo_store/mod.rs`) — the Imperative Shell.
//!
//! Transiently dead until Step 4 wires handlers to
//! `OrgStore::{get,put}_user_schema`; the impl chain has no live entry point
//! in the lib until then.
#![allow(dead_code)]

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authn_core::UserSchema;
use forgeguard_core::OrganizationId;

use crate::error::{Error, Result};
use crate::etag::Etag;
use crate::store::EtagedUserSchema;

use super::{pk, sk, DynamoOrgStore, ORG_PREFIX};

pub(crate) const SK_USER_SCHEMA: &str = "USER_SCHEMA";

pub(crate) fn user_schema_pk(org_id: &OrganizationId) -> String {
    format!("{ORG_PREFIX}{org_id}")
}

pub(crate) fn to_user_schema_item(
    org_id: &OrganizationId,
    schema: &UserSchema,
    etag: &Etag,
) -> Result<HashMap<String, AttributeValue>> {
    let json = serde_json::to_string(schema)
        .map_err(|e| Error::Store(format!("serialize user_schema: {e}")))?;

    let mut item = HashMap::new();
    item.insert(pk().to_string(), AttributeValue::S(user_schema_pk(org_id)));
    item.insert(
        sk().to_string(),
        AttributeValue::S(SK_USER_SCHEMA.to_string()),
    );
    item.insert("schema".to_string(), AttributeValue::S(json));
    item.insert(
        "etag".to_string(),
        AttributeValue::S(etag.as_str().to_string()),
    );
    Ok(item)
}

pub(crate) fn etaged_user_schema_from_item(
    item: &HashMap<String, AttributeValue>,
) -> Result<EtagedUserSchema> {
    let json = item
        .get("schema")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| Error::Store("user_schema item missing 'schema' attribute".to_string()))?;
    let schema: UserSchema = serde_json::from_str(json)
        .map_err(|e| Error::Store(format!("deserialize user_schema: {e}")))?;

    let etag_str = item
        .get("etag")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| Error::Store("user_schema item missing 'etag' attribute".to_string()))?;
    let etag = Etag::try_new(etag_str)
        .map_err(|e| Error::Store(format!("stored user_schema etag is invalid: {e}")))?;

    Ok(EtagedUserSchema::from_stored(schema, etag))
}

/// Bundled parts of a DynamoDB condition expression for user-schema `PutItem`
/// calls.
///
/// All three fields are derived together from `expected_etag` so a
/// half-formed condition (name without placeholder, placeholder without value)
/// is structurally impossible — Make Impossible States Impossible.
pub(crate) struct UserSchemaConditionParts {
    pub(crate) expression: String,
    pub(crate) names: Vec<(&'static str, &'static str)>,
    pub(crate) values: Vec<(&'static str, AttributeValue)>,
}

/// Build the `PutItem` condition for user-schema create (`expected_etag = None`)
/// and user-schema update (`expected_etag = Some(_)`).
///
/// | `expected_etag` | Expression                                              | Semantics |
/// |-----------------|---------------------------------------------------------|-----------|
/// | `None`          | `attribute_not_exists(#sk_attr)`                        | Row must not already exist (create path). |
/// | `Some(etag)`    | `attribute_exists(#sk_attr) AND #etag = :expected_etag` | Row must exist with the given etag (update path). |
///
/// The SK uniquely identifies the user-schema row within an org's PK partition,
/// so checking `attribute_not_exists(SK)` is the correct create guard.
///
/// Pure: deterministic, no I/O, trivially unit-testable.
/// Functional Core — consumed by `put_user_schema` (Imperative Shell in `mod.rs`).
pub(crate) fn build_user_schema_put_condition(
    expected_etag: Option<&Etag>,
) -> UserSchemaConditionParts {
    match expected_etag {
        None => UserSchemaConditionParts {
            expression: "attribute_not_exists(#sk_attr)".to_string(),
            names: vec![("#sk_attr", sk())],
            values: Vec::new(),
        },
        Some(etag) => UserSchemaConditionParts {
            expression: "attribute_exists(#sk_attr) AND #etag = :expected_etag".to_string(),
            names: vec![("#sk_attr", sk()), ("#etag", "etag")],
            values: vec![(
                ":expected_etag",
                AttributeValue::S(etag.as_str().to_string()),
            )],
        },
    }
}

pub(crate) async fn recover_user_schema_etag(
    store: &DynamoOrgStore,
    org_id: &OrganizationId,
) -> Result<Option<Etag>> {
    use crate::store::OrgStore as _;
    Ok(store
        .get_user_schema(org_id)
        .await?
        .map(|s| s.etag().clone()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use forgeguard_authn_core::user_schema::{StandardAttrName, StandardAttrSpec};

    use super::*;

    fn sample_schema() -> UserSchema {
        let mut standard = BTreeMap::new();
        standard.insert(StandardAttrName::Name, StandardAttrSpec { required: true });
        UserSchema::new(standard, BTreeMap::new())
    }

    fn sample_etag() -> Etag {
        Etag::try_new("\"abcdef0123456789\"").unwrap()
    }

    #[test]
    fn keys_use_org_prefix_and_fixed_sk() {
        let oid = OrganizationId::new("org-x").unwrap();
        assert_eq!(user_schema_pk(&oid), "ORG#org-x");
        assert_eq!(SK_USER_SCHEMA, "USER_SCHEMA");
    }

    #[test]
    fn to_and_from_item_round_trip() {
        let oid = OrganizationId::new("org-rt").unwrap();
        let schema = sample_schema();
        let etag = sample_etag();
        let item = to_user_schema_item(&oid, &schema, &etag).unwrap();

        let back = etaged_user_schema_from_item(&item).unwrap();
        assert_eq!(back.schema(), &schema);
        assert_eq!(back.etag(), &etag);
    }

    #[test]
    fn from_item_missing_schema_attr_is_store_error() {
        let mut item = HashMap::new();
        item.insert("etag".to_owned(), AttributeValue::S("\"x\"".to_owned()));
        match etaged_user_schema_from_item(&item) {
            Err(Error::Store(msg)) => assert!(msg.contains("'schema'")),
            other => panic!("expected Store error, got: {other:?}"),
        }
    }

    #[test]
    fn from_item_missing_etag_attr_is_store_error() {
        let mut item = HashMap::new();
        item.insert("schema".to_owned(), AttributeValue::S("{}".to_owned()));
        match etaged_user_schema_from_item(&item) {
            Err(Error::Store(msg)) => assert!(msg.contains("'etag'")),
            other => panic!("expected Store error, got: {other:?}"),
        }
    }

    #[test]
    fn from_item_malformed_schema_json_is_store_error() {
        let mut item = HashMap::new();
        item.insert(
            "schema".to_string(),
            AttributeValue::S("not-json".to_string()),
        );
        item.insert("etag".to_string(), AttributeValue::S("\"x\"".to_string()));
        match etaged_user_schema_from_item(&item) {
            Err(Error::Store(msg)) => assert!(msg.contains("deserialize user_schema")),
            other => panic!("expected Store error, got: {other:?}"),
        }
    }

    #[test]
    fn from_item_malformed_etag_is_store_error() {
        let mut item = HashMap::new();
        item.insert("schema".to_owned(), AttributeValue::S("{}".to_owned()));
        item.insert("etag".to_owned(), AttributeValue::S(String::new()));
        match etaged_user_schema_from_item(&item) {
            Err(Error::Store(msg)) => assert!(msg.contains("etag is invalid")),
            other => panic!("expected Store error, got: {other:?}"),
        }
    }

    #[test]
    fn without_expected_etag_uses_attribute_not_exists() {
        let parts = build_user_schema_put_condition(None);
        assert_eq!(parts.expression, "attribute_not_exists(#sk_attr)");
        assert_eq!(parts.names, vec![("#sk_attr", sk())]);
        assert!(parts.values.is_empty());
    }

    #[test]
    fn with_expected_etag_uses_attribute_exists_and_etag_clause() {
        let etag = sample_etag();
        let parts = build_user_schema_put_condition(Some(&etag));
        assert_eq!(
            parts.expression,
            "attribute_exists(#sk_attr) AND #etag = :expected_etag"
        );
        assert_eq!(parts.names, vec![("#sk_attr", sk()), ("#etag", "etag")]);
        assert_eq!(
            parts.values,
            vec![(
                ":expected_etag",
                AttributeValue::S(etag.as_str().to_owned()),
            )]
        );
    }
}
