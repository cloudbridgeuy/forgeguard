//! DynamoDB codec helpers for group reads.
//!
//! `etaged_group_from_item` is a deterministic, no-I/O helper that lives here
//! because it doesn't need access to `DynamoOrgStore`'s private fields.
//!
//! The `impl OrgStore for DynamoOrgStore` method bodies that drive the AWS SDK
//! live in [`super`] (`dynamo_store/mod.rs`) — the Imperative Shell.

use aws_sdk_dynamodb::types::AttributeValue;

use crate::error::Result;
use crate::etag::Etag;
use crate::store::EtagedGroup;

/// Lift `from_group_item` output into an `EtagedGroup`.
///
/// `from_group_item` returns `Result<(RbacEntry, String)>` (codec design from
/// Group C that was not updated). This tiny wrapper performs the structural
/// conversion so the imperative shell in `mod.rs` stays readable.
pub(crate) fn etaged_group_from_item(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Result<EtagedGroup> {
    let (entry, etag) = crate::handlers::groups::codec::from_group_item(item)?;
    Ok(EtagedGroup::from_stored(entry, Etag::try_new(etag)?))
}
