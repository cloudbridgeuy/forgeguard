//! Imperative shell for the org `PutItem` writes.
//!
//! All decisions (attribute layout, status string, ETag) live in
//! `super::pure`. This file is glue: build attrs, call DDB, log.

use color_eyre::eyre::{eyre, Context, Result};

use crate::control_plane::seed_core::SeedOrg;

use super::pure;
use super::SeedContext;

/// Write every seeded org to DynamoDB as `OrgStatus::Draft`. Destructive —
/// re-running rotates the row in place (no conditional check).
pub(crate) async fn write_orgs(ctx: &SeedContext<'_>, orgs: &[SeedOrg]) -> Result<()> {
    for org in orgs {
        let attrs = pure::seed_org_to_dynamodb_attrs(org, ctx.now)
            .map_err(|e| eyre!("build org attrs for '{}': {e}", org.org_id()))?;

        let mut request = ctx.dynamo.put_item().table_name(&ctx.table_name);
        for (name, value) in attrs {
            request = request.item(name, value);
        }
        request
            .send()
            .await
            .with_context(|| format!("DynamoDB PutItem org '{}' failed", org.org_id()))?;

        println!(
            "  Seeded organization '{}' (status={})",
            org.org_id(),
            pure::seed_org_to_status_attr()
        );
    }
    Ok(())
}
