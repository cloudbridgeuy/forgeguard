//! Imperative shell for group `PutItem` writes.
//!
//! Validation, RBAC conversion, ETag, and attribute layout all live in
//! `super::pure`. No VP push — every seeded org is Draft.

use forgeguard_authz_core::RbacEntry;

use color_eyre::eyre::{eyre, Context, Result};

use crate::control_plane::seed_core::SeedOrg;

use super::pure;
use super::SeedContext;

/// Validate every org's groups up-front, then write only after all pass.
///
/// A dangling inherit (or cycle, or invalid name) in **any** org aborts the
/// seed before a single `PutItem` lands — satisfies the V5 acceptance
/// criterion that the seed exits non-zero with the offending name and zero
/// DynamoDB mutations on validation failure. Within an org, groups are
/// emitted in alphabetical order by `entry.name` for deterministic logs.
pub(crate) async fn write_groups(ctx: &SeedContext<'_>, orgs: &[SeedOrg]) -> Result<()> {
    let mut validated: Vec<(&str, Vec<RbacEntry>)> = Vec::with_capacity(orgs.len());
    for org in orgs {
        let mut entries = pure::seed_groups_to_rbac_entries(org.groups());
        pure::validate_seed_groups(&entries)
            .map_err(|e| eyre!("group validation failed for org '{}': {e}", org.org_id()))?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        validated.push((org.org_id(), entries));
    }

    for (org_id, entries) in &validated {
        for entry in entries {
            let etag = pure::compute_group_etag(entry)
                .map_err(|e| eyre!("compute etag for group '{org_id}/{}': {e}", entry.name))?;
            let attrs = pure::seed_group_to_dynamodb_attrs(org_id, entry, &etag, ctx.now)
                .map_err(|e| eyre!("build group attrs for '{org_id}/{}': {e}", entry.name))?;

            let mut request = ctx.dynamo.put_item().table_name(&ctx.table_name);
            for (name, value) in attrs {
                request = request.item(name, value);
            }
            request.send().await.with_context(|| {
                format!("DynamoDB PutItem group '{org_id}/{}' failed", entry.name)
            })?;

            println!(
                "  Seeded group '{org_id}/{}' (inherits={:?})",
                entry.name, entry.inherits
            );
        }
    }
    Ok(())
}
