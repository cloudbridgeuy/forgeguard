//! DynamoDB-backed membership resolver.
//!
//! Implements [`MembershipResolver`] by performing a `GetItem` against the
//! shared DynamoDB table using `USER#<user_id>` as PK and `ORG#<org_id>` as SK.
//!
//! Wired into `app.rs` in Task 10.

use std::future::Future;
use std::pin::Pin;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_core::{GroupName, OrganizationId, UserId};
use forgeguard_proxy_core::{Membership, MembershipResolver};

use crate::dynamo_store::{pk, sk, ORG_PREFIX};

// Pre-staged — wired in Task 10.
#[allow(dead_code)]
const USER_PREFIX: &str = "USER#";

/// DynamoDB-backed implementation of [`MembershipResolver`].
///
/// Performs a single `GetItem` per call.  Returns `None` when no membership
/// record exists (user is not a member of the org).
// Pre-staged — wired in Task 10.
#[allow(dead_code)]
pub(crate) struct DynamoMembershipResolver {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoMembershipResolver {
    // Pre-staged — wired in Task 10.
    #[allow(dead_code)]
    pub(crate) fn new(client: aws_sdk_dynamodb::Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

impl MembershipResolver for DynamoMembershipResolver {
    fn resolve(
        &self,
        user_id: &UserId,
        org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Option<Membership>> + Send + '_>> {
        let pk_value = format!("{USER_PREFIX}{user_id}");
        let sk_value = format!("{ORG_PREFIX}{org_id}");

        Box::pin(async move {
            let result = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key(pk(), AttributeValue::S(pk_value))
                .key(sk(), AttributeValue::S(sk_value))
                .send()
                .await
                .ok()?;

            let item = result.item?;
            let groups = parse_groups(&item)?;
            Some(Membership::new(groups))
        })
    }
}

/// Parse the `groups` list attribute from a DynamoDB membership item.
///
/// Pure function — no I/O.
///
/// Returns `None` when the `groups` attribute is absent or is not a list.
/// Invalid [`GroupName`] values are silently skipped.
// Pre-staged — called from `resolve`; exported here for exhaustive unit testing.
#[allow(dead_code)]
pub(crate) fn parse_groups(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Option<Vec<GroupName>> {
    let groups_attr = item.get("groups")?;
    let list = groups_attr.as_l().ok()?;
    let groups: Vec<GroupName> = list
        .iter()
        .filter_map(|v| v.as_s().ok())
        .filter_map(|s| GroupName::new(s).ok())
        .collect();
    Some(groups)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use aws_sdk_dynamodb::types::AttributeValue;

    use super::*;

    #[test]
    fn parse_groups_valid() {
        let mut item = HashMap::new();
        item.insert(
            "groups".to_string(),
            AttributeValue::L(vec![
                AttributeValue::S("admin".into()),
                AttributeValue::S("viewer".into()),
            ]),
        );

        let result = parse_groups(&item).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], GroupName::new("admin").unwrap());
        assert_eq!(result[1], GroupName::new("viewer").unwrap());
    }

    #[test]
    fn parse_groups_empty_list() {
        let mut item = HashMap::new();
        item.insert("groups".to_string(), AttributeValue::L(vec![]));

        let result = parse_groups(&item).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_groups_missing_attribute() {
        let item: HashMap<String, AttributeValue> = HashMap::new();

        let result = parse_groups(&item);
        assert!(result.is_none());
    }

    #[test]
    fn parse_groups_skips_invalid_names() {
        // "Admin" fails GroupName::new() — uppercase is rejected by Segment validation.
        let mut item = HashMap::new();
        item.insert(
            "groups".to_string(),
            AttributeValue::L(vec![
                AttributeValue::S("admin".into()),
                AttributeValue::S("Admin".into()),
            ]),
        );

        let result = parse_groups(&item).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], GroupName::new("admin").unwrap());
    }
}
