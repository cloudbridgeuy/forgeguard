//! DynamoDB serialization for `MembershipRow` (V3 — POST /users stage S3).
//!
//! Layout follows the `membership` item type in
//! `infra/control-plane/schema/forgeguard-orgs.json`:
//!
//! - `PK`  = `USER#{sub}`
//! - `SK`  = `ORG#{org_id}`
//! - `user_id`   (S, required)
//! - `org_id`    (S, required)
//! - `groups`    (L of S, present-but-possibly-empty — never absent)
//! - `joined_at` (S, RFC 3339, required)
//! - `email`     (S, required) — audit metadata for the saga driver
//! - `created_by`(S, required) — audit metadata (the admin sub that issued
//!   the `POST /users` request)
//! - `GSI1PK`    = `ORG#{org_id}` (S, required) — sparse GSI1 inverted index,
//!   listing users per org
//! - `GSI1SK`    = `USER#{sub}` (S, required)
//!
//! `groups` must always be a List, even when empty, because
//! `membership_store.rs::parse_groups` calls `as_l()` and treats a missing
//! attribute as a malformed item (rejecting the principal).

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authn_core::MembershipRow;

use crate::dynamo_store::{
    is_conditional_check_failed, map_sdk_error, pk, sk, DynamoOrgStore, ORG_PREFIX, USER_PREFIX,
};
use crate::error::{Error, Result};
use crate::store::PutMembershipRowParams;

/// Pure serializer — `MembershipRow` → DynamoDB item map.
///
/// Lives outside the trait impl so it can be unit-tested without an SDK
/// client. `groups` is always written as `AttributeValue::L`, even when
/// empty, to satisfy the resolver contract.
pub(crate) fn to_membership_item(row: &MembershipRow) -> HashMap<String, AttributeValue> {
    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert(
        pk().to_owned(),
        AttributeValue::S(format!("{USER_PREFIX}{}", row.sub())),
    );
    item.insert(
        sk().to_owned(),
        AttributeValue::S(format!("{ORG_PREFIX}{}", row.org_id())),
    );
    item.insert(
        "user_id".to_owned(),
        AttributeValue::S(row.sub().to_string()),
    );
    item.insert(
        "org_id".to_owned(),
        AttributeValue::S(row.org_id().to_string()),
    );
    let groups: Vec<AttributeValue> = row
        .groups()
        .iter()
        .map(|g| AttributeValue::S(g.to_string()))
        .collect();
    item.insert("groups".to_owned(), AttributeValue::L(groups));
    item.insert(
        "joined_at".to_owned(),
        AttributeValue::S(row.created_at().to_rfc3339()),
    );
    item.insert(
        "email".to_owned(),
        AttributeValue::S(row.email().to_owned()),
    );
    item.insert(
        "created_by".to_owned(),
        AttributeValue::S(row.created_by().to_string()),
    );
    item.insert(
        "GSI1PK".to_owned(),
        AttributeValue::S(format!("{ORG_PREFIX}{}", row.org_id())),
    );
    item.insert(
        "GSI1SK".to_owned(),
        AttributeValue::S(format!("{USER_PREFIX}{}", row.sub())),
    );
    item
}

/// Persist a membership row with `attribute_not_exists(#sk)` to surface
/// concurrent duplicate writes as [`Error::Conflict`] rather than silently
/// overwriting.
pub(crate) async fn put_membership_row(
    store: &DynamoOrgStore,
    params: PutMembershipRowParams<'_>,
) -> Result<()> {
    let row = params.row;
    let item = to_membership_item(row);

    match store
        .client
        .put_item()
        .table_name(&store.table_name)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(#sk)")
        .expression_attribute_names("#sk", sk())
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(sdk_err) if is_conditional_check_failed(&sdk_err) => Err(Error::Conflict(format!(
            "membership row for user '{}' in org '{}' already exists",
            row.sub(),
            row.org_id()
        ))),
        Err(sdk_err) => Err(map_sdk_error(sdk_err)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::{DateTime, Utc};
    use forgeguard_authn_core::membership::MembershipRowParams;
    use forgeguard_core::{GroupName, OrganizationId, UserId};

    use super::*;

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn sample_row(groups: Vec<&str>) -> MembershipRow {
        MembershipRow::new(MembershipRowParams {
            sub: UserId::new("user-123").unwrap(),
            org_id: OrganizationId::new("acme").unwrap(),
            groups: groups
                .into_iter()
                .map(|g| GroupName::new(g).unwrap())
                .collect(),
            email: "alice@example.com".to_owned(),
            created_at: fixed_time(),
            created_by: UserId::new("admin").unwrap(),
        })
    }

    #[test]
    fn to_item_writes_required_keys() {
        let row = sample_row(vec!["admin", "members"]);
        let item = to_membership_item(&row);

        assert_eq!(
            item.get(pk()).and_then(|v| v.as_s().ok()),
            Some(&"USER#user-123".to_owned())
        );
        assert_eq!(
            item.get(sk()).and_then(|v| v.as_s().ok()),
            Some(&"ORG#acme".to_owned())
        );
        assert_eq!(
            item.get("user_id").and_then(|v| v.as_s().ok()),
            Some(&"user-123".to_owned())
        );
        assert_eq!(
            item.get("org_id").and_then(|v| v.as_s().ok()),
            Some(&"acme".to_owned())
        );
        assert_eq!(
            item.get("email").and_then(|v| v.as_s().ok()),
            Some(&"alice@example.com".to_owned())
        );
        assert_eq!(
            item.get("created_by").and_then(|v| v.as_s().ok()),
            Some(&"admin".to_owned())
        );
        let joined = item.get("joined_at").and_then(|v| v.as_s().ok()).unwrap();
        assert!(joined.starts_with("2026-05-15T12:00:00"));
        assert_eq!(
            item.get("GSI1PK").and_then(|v| v.as_s().ok()),
            Some(&"ORG#acme".to_owned())
        );
        assert_eq!(
            item.get("GSI1SK").and_then(|v| v.as_s().ok()),
            Some(&"USER#user-123".to_owned())
        );
    }

    #[test]
    fn to_item_writes_groups_as_list_even_when_empty() {
        let row = sample_row(vec![]);
        let item = to_membership_item(&row);
        let list = item
            .get("groups")
            .expect("groups must always be present")
            .as_l()
            .expect("groups must always be a List, never a String");
        assert!(list.is_empty());
    }

    #[test]
    fn to_item_groups_are_strings_in_declaration_order() {
        let row = sample_row(vec!["admin", "members"]);
        let item = to_membership_item(&row);
        let list = item.get("groups").unwrap().as_l().unwrap();
        let names: Vec<&str> = list
            .iter()
            .map(|v| v.as_s().expect("group entry must be a String").as_str())
            .collect();
        assert_eq!(names, vec!["admin", "members"]);
    }
}
