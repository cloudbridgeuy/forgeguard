//! DynamoDB-backed membership resolver.
//!
//! Implements [`MembershipResolver`] by performing a `GetItem` against the
//! shared DynamoDB table using `USER#<user_id>` as PK and `ORG#<org_id>` as SK.
//!
//! Wired into `app.rs` in Task 10.

// Pre-staged — entire module is wired in Task 10.
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_core::{GroupName, OrganizationId, UserId};
use forgeguard_proxy_core::{Membership, MembershipResolver};

use crate::dynamo_store::{pk, sk, ORG_PREFIX};

const USER_PREFIX: &str = "USER#";

/// DynamoDB-backed implementation of [`MembershipResolver`].
///
/// Performs a single `GetItem` per call.  Returns `None` when no membership
/// record exists (user is not a member of the org).
pub(crate) struct DynamoMembershipResolver {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoMembershipResolver {
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
            let result = match self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key(pk(), AttributeValue::S(pk_value))
                .key(sk(), AttributeValue::S(sk_value))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "DynamoDB GetItem failed for membership lookup; treating as not a member"
                    );
                    return None;
                }
            };

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
pub(crate) fn parse_groups(item: &HashMap<String, AttributeValue>) -> Option<Vec<GroupName>> {
    let list = item.get("groups")?.as_l().ok()?;
    Some(
        list.iter()
            .filter_map(|v| v.as_s().ok())
            .filter_map(|s| GroupName::new(s).ok())
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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

    #[test]
    fn parse_groups_wrong_attribute_type() {
        // Data corruption: `groups` stored as String instead of List → treated as absent.
        let mut item = HashMap::new();
        item.insert("groups".to_string(), AttributeValue::S("admin".into()));

        assert!(parse_groups(&item).is_none());
    }
}
