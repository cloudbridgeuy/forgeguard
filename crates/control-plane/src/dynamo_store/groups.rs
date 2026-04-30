//! DynamoDB codec helpers and condition-expression builders for group CRUD.
//!
//! Most of this file is pure: `build_group_put_condition` and
//! `etaged_group_from_item` are deterministic, no-I/O helpers that live here
//! because they don't need access to `DynamoOrgStore`'s private fields.
//!
//! `recover_group_etag` is the one async/I/O helper. It lives here (rather
//! than in `mod.rs`) because it is a thin wrapper over the public
//! `OrgStore::get_group` method and pairs naturally with the pure
//! `build_group_put_condition` it complements in the `put_group` call-site.
//!
//! The `impl OrgStore for DynamoOrgStore` method bodies that drive the AWS SDK
//! live in [`super`] (`dynamo_store/mod.rs`) — the Imperative Shell.

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_core::OrganizationId;

use crate::error::Result;
use crate::store::{EtagedGroup, OrgStore};

use super::{sk, DynamoOrgStore};

// ---------------------------------------------------------------------------
// GroupConditionParts
// ---------------------------------------------------------------------------

/// Bundled parts of a DynamoDB condition expression for group `PutItem` calls.
///
/// All three fields are derived together from `expected_etag` so a
/// half-formed condition (name without placeholder, placeholder without value)
/// is structurally impossible — Make Impossible States Impossible.
pub(crate) struct GroupConditionParts {
    pub(crate) expression: String,
    pub(crate) names: Vec<(&'static str, &'static str)>,
    pub(crate) values: Vec<(&'static str, AttributeValue)>,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Build the `PutItem` condition for group create (`expected_etag = None`) and
/// group update (`expected_etag = Some(_)`).
///
/// | `expected_etag` | Expression                                              | Semantics |
/// |-----------------|---------------------------------------------------------|-----------|
/// | `None`          | `attribute_not_exists(#sk_attr)`                        | Row must not already exist (create path). |
/// | `Some(etag)`    | `attribute_exists(#sk_attr) AND #etag = :expected_etag` | Row must exist with the given etag (update path). |
///
/// The SK uniquely identifies a group row within an org's PK partition, so
/// checking `attribute_not_exists(SK)` is the correct create guard.
///
/// Pure: deterministic, no I/O, trivially unit-testable.
/// Functional Core — consumed by `put_group` (Imperative Shell in `mod.rs`).
pub(crate) fn build_group_put_condition(expected_etag: Option<&str>) -> GroupConditionParts {
    match expected_etag {
        None => GroupConditionParts {
            expression: "attribute_not_exists(#sk_attr)".to_string(),
            names: vec![("#sk_attr", sk())],
            values: Vec::new(),
        },
        Some(etag) => GroupConditionParts {
            expression: "attribute_exists(#sk_attr) AND #etag = :expected_etag".to_string(),
            names: vec![("#sk_attr", sk()), ("#etag", "etag")],
            values: vec![(":expected_etag", AttributeValue::S(etag.to_string()))],
        },
    }
}

/// Recover the current stored etag for a group after a
/// `ConditionalCheckFailedException`.
///
/// Returns `Ok("")` when the group is absent or has no `etag` attribute.
/// This matches the fail-closed contract: if the group never existed, any
/// `If-Match` value is wrong and the empty string tells the handler to emit
/// a `current_etag: ""` body (same as `InMemoryOrgStore`'s
/// `(None, Some(_))` branch in `put_group`).
pub(crate) async fn recover_group_etag(
    store: &DynamoOrgStore,
    org_id: &OrganizationId,
    name: &str,
) -> Result<String> {
    Ok(store
        .get_group(org_id, name)
        .await?
        .map(|g| g.etag().to_string())
        .unwrap_or_default())
}

/// Lift `from_group_item` output into an `EtagedGroup`.
///
/// `from_group_item` returns `Result<(RbacEntry, String)>` (codec design from
/// Group C that was not updated). This tiny wrapper performs the structural
/// conversion so the imperative shell in `mod.rs` stays readable.
pub(crate) fn etaged_group_from_item(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Result<EtagedGroup> {
    let (entry, etag) = crate::handlers::groups::codec::from_group_item(item)?;
    Ok(EtagedGroup::from_stored(entry, etag))
}

// ---------------------------------------------------------------------------
// Pure unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod condition_builder_tests {
    use super::*;

    #[test]
    fn without_expected_etag_uses_attribute_not_exists_on_sk() {
        let parts = build_group_put_condition(None);
        assert_eq!(parts.expression, "attribute_not_exists(#sk_attr)");
        assert_eq!(parts.names, vec![("#sk_attr", sk())]);
        assert!(parts.values.is_empty());
    }

    #[test]
    fn with_expected_etag_uses_attribute_exists_and_etag_clause() {
        let parts = build_group_put_condition(Some("\"abc123\""));
        assert_eq!(
            parts.expression,
            "attribute_exists(#sk_attr) AND #etag = :expected_etag"
        );
        assert_eq!(parts.names, vec![("#sk_attr", sk()), ("#etag", "etag")]);
        assert_eq!(
            parts.values,
            vec![(
                ":expected_etag",
                AttributeValue::S("\"abc123\"".to_string())
            )]
        );
    }

    #[test]
    fn none_and_some_produce_distinct_expressions() {
        let create = build_group_put_condition(None);
        let update = build_group_put_condition(Some("\"x\""));
        assert_ne!(create.expression, update.expression);
    }
}
