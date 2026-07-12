//! Imperative shell for the V6 user-schema `PutItem` writes.
//!
//! Phase 2 of the seed pipeline (between `write_orgs` and `write_groups`).
//! Consumes the `UserSchema`s produced by `pure::preflight_validate` in Phase 0,
//! computes each one's content-addressed etag, then PutItems the row at
//! `PK=ORG#{org_id}, SK=USER_SCHEMA` using the same attribute layout as
//! `forgeguard_control_plane::dynamo_store::user_schema::to_user_schema_item`.
//!
//! Unconditional `PutItem` — teardown already cleared any prior row, and the
//! seed always wins. A later CP `PUT /user_schema` with `If-Match` round-trips
//! cleanly against the etag the seed writes here (same xxh64 recipe).

use color_eyre::eyre::{eyre, Context, Result};
use forgeguard_authn_core::UserSchema;

use crate::control_plane::seed_core::SeedOrg;

use super::pure;
use super::SeedContext;

/// Write the `USER_SCHEMA` row for every seeded org.
///
/// `schemas` is the Phase 0 output, aligned by index with `orgs`. Etag + DDB
/// attribute build still happen inside this function; both are pure but kept
/// out of Phase 0 to keep the pre-flight focused on validation. A failure
/// here aborts the seed; teardown has already wiped any prior rows so half a
/// pass leaves no orphan state.
pub(crate) async fn write_user_schemas(
    ctx: &SeedContext<'_>,
    orgs: &[SeedOrg],
    schemas: &[UserSchema],
) -> Result<()> {
    debug_assert_eq!(orgs.len(), schemas.len(), "preflight schemas must align");

    for (org, schema) in orgs.iter().zip(schemas) {
        let etag = pure::compute_user_schema_etag(schema)
            .map_err(|e| eyre!("compute user_schema etag for org '{}': {e}", org.org_id()))?;
        let attrs = pure::user_schema_to_dynamodb_attrs(org.org_id(), schema, &etag)
            .map_err(|e| eyre!("build user_schema attrs for org '{}': {e}", org.org_id()))?;

        let mut request = ctx.dynamo.put_item().table_name(&ctx.table_name);
        for (name, value) in attrs {
            request = request.item(name, value);
        }
        request.send().await.with_context(|| {
            format!(
                "DynamoDB PutItem user_schema for org '{}' failed",
                org.org_id()
            )
        })?;

        println!(
            "  Seeded user_schema for org '{}' ({} standard, {} custom)",
            org.org_id(),
            schema.standard().len(),
            schema.custom().len(),
        );
    }
    Ok(())
}
