//! Imperative shell for the V6 user-schema `PutItem` writes.
//!
//! Phase 2 of the seed pipeline (between `write_orgs` and `write_groups`).
//! Converts each org's declared `SeedUserSchema` into the domain `UserSchema`,
//! computes its content-addressed etag, then PutItems the row at
//! `PK=ORG#{org_id}, SK=USER_SCHEMA` using the same attribute layout as
//! `forgeguard_control_plane::dynamo_store::user_schema::to_user_schema_item`.
//!
//! Unconditional `PutItem` — teardown already cleared any prior row, and the
//! seed always wins. A later CP `PUT /user_schema` with `If-Match` round-trips
//! cleanly against the etag the seed writes here (same xxh64 recipe).

use aws_sdk_dynamodb::types::AttributeValue;
use color_eyre::eyre::{eyre, Context, Result};
use forgeguard_authn_core::UserSchema;

use crate::control_plane::seed_core::SeedOrg;

use super::pure;
use super::SeedContext;

/// Write the `USER_SCHEMA` row for every seeded org.
///
/// Two-pass loop: first convert every org's `SeedUserSchema` into the domain
/// `UserSchema` and build the `PutItem` payloads; only when every conversion
/// succeeds do we start issuing DDB writes. A malformed schema on org N aborts
/// the seed before org 1's row is touched, satisfying the V6 "abort before any
/// DDB write" invariant even when `run()` has not yet wired a Phase 0 pre-flight.
pub(crate) async fn write_user_schemas(ctx: &SeedContext<'_>, orgs: &[SeedOrg]) -> Result<()> {
    let prepared = orgs
        .iter()
        .map(prepare_user_schema_write)
        .collect::<Result<Vec<_>>>()?;

    for prep in prepared {
        let mut request = ctx.dynamo.put_item().table_name(&ctx.table_name);
        for (name, value) in prep.attrs {
            request = request.item(name, value);
        }
        request.send().await.with_context(|| {
            format!(
                "DynamoDB PutItem user_schema for org '{}' failed",
                prep.org_id
            )
        })?;

        println!(
            "  Seeded user_schema for org '{}' ({} standard, {} custom)",
            prep.org_id,
            prep.schema.standard().len(),
            prep.schema.custom().len(),
        );
    }
    Ok(())
}

struct PreparedSchemaWrite {
    org_id: String,
    schema: UserSchema,
    attrs: Vec<(String, AttributeValue)>,
}

fn prepare_user_schema_write(org: &SeedOrg) -> Result<PreparedSchemaWrite> {
    let schema = pure::seed_user_schema_to_domain(org.user_schema())
        .map_err(|e| eyre!("user_schema for org '{}' is invalid: {e}", org.org_id()))?;
    let etag = pure::compute_user_schema_etag(&schema)
        .map_err(|e| eyre!("compute user_schema etag for org '{}': {e}", org.org_id()))?;
    let attrs = pure::user_schema_to_dynamodb_attrs(org.org_id(), &schema, &etag)
        .map_err(|e| eyre!("build user_schema attrs for org '{}': {e}", org.org_id()))?;
    Ok(PreparedSchemaWrite {
        org_id: org.org_id().to_owned(),
        schema,
        attrs,
    })
}
