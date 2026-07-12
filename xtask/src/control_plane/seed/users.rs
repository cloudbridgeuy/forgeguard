//! Imperative shell for V6 user provisioning (Phase 4 of the seed pipeline).
//!
//! `update_user_pool` (only when the org declares a custom attribute) →
//! `admin_create_user` → recover-on-`UsernameExists` → PutItem the membership
//! row with `attribute_not_exists(#sk)` so a re-run skips silently rather than
//! overwriting an existing row (R3 in the V6 plan).
//!
//! V6 `seed.toml` declares only standard attributes (`name`), so the
//! `update_user_pool` branch never fires today; it's wired up so a future
//! `seed.toml` with custom attrs works without code changes. The Cognito API
//! rejects `admin_create_user` for an undeclared custom attr — the guard
//! exists to push that failure up-front rather than per-user.

use color_eyre::eyre::{eyre, Context, Result};
use forgeguard_authn::user_pool::UserPoolClient;
use forgeguard_authn_core::membership::MembershipRowParams;
use forgeguard_authn_core::user_pool::{CreateUserParams, PoolId, UpdatePoolParams};
use forgeguard_authn_core::{
    schema_to_cognito_attrs, validate_attributes, MembershipRow, UserPoolError, UserSchema,
};
use forgeguard_core::{GroupName, OrganizationId, UserId};

use crate::control_plane::seed_core::{SeedOrg, SeedUser};

use super::pure;
use super::SeedContext;

/// `email_verified` is a Cognito invariant injected on every seeded user,
/// never declared in `seed.toml`. Matches the V3 `POST /users` saga handler.
const EMAIL_VERIFIED_KEY: &str = "email_verified";
const EMAIL_VERIFIED_VALUE: &str = "true";

/// Sentinel principal recorded as `created_by` on every seeded membership row.
/// Lowercase + dash only so it satisfies `UserId`'s `Segment` validation.
const SEED_CREATED_BY: &str = "xtask-seed";

/// Provision every declared user for one org: create them in Cognito, then
/// write the membership row.
///
/// Pure validation already ran in `run()`'s Phase 0; this re-validates per
/// user so the function contract reads cleanly without leaning on the caller.
pub(crate) async fn write_users(
    ctx: &SeedContext<'_>,
    org: &SeedOrg,
    user_pool_client: &dyn UserPoolClient,
    schema: &UserSchema,
) -> Result<()> {
    let pool_id = PoolId::try_new(org.cognito_user_pool_id()).map_err(|e| {
        eyre!(
            "invalid cognito_user_pool_id for org '{}': {e}",
            org.org_id()
        )
    })?;
    let org_id = OrganizationId::new(org.org_id())
        .map_err(|e| eyre!("invalid org_id '{}': {e}", org.org_id()))?;

    sync_pool_custom_attrs(org, &pool_id, user_pool_client, schema).await?;

    for user in org.users() {
        provision_user(
            ctx,
            ProvisionUserParams {
                org,
                user,
                pool_id: &pool_id,
                org_id: &org_id,
                user_pool_client,
                schema,
            },
        )
        .await?;
    }
    Ok(())
}

/// Materialise any custom attributes the org declares into the Cognito pool.
///
/// `update_user_pool` is skipped when `schema.custom` is empty (the V6
/// `seed.toml` case) — there is nothing to add and the call is not free.
/// When there are custom attrs, we push the full attribute list and tolerate
/// `AttributeAlreadyExists` as success so a re-run is idempotent (mirrors V4
/// schema-apply behaviour).
async fn sync_pool_custom_attrs(
    org: &SeedOrg,
    pool_id: &PoolId,
    user_pool_client: &dyn UserPoolClient,
    schema: &UserSchema,
) -> Result<()> {
    if schema.custom().is_empty() {
        return Ok(());
    }
    let params = UpdatePoolParams {
        pool_id: pool_id.clone(),
        schema_attrs: schema_to_cognito_attrs(schema),
    };
    match user_pool_client.update_user_pool(params).await {
        Ok(()) => {
            println!(
                "  Synced {} custom attribute(s) into pool for org '{}'",
                schema.custom().len(),
                org.org_id()
            );
            Ok(())
        }
        Err(UserPoolError::AttributeAlreadyExists { name }) => {
            println!(
                "  Custom attribute '{}' already in pool for org '{}' (tolerating)",
                name,
                org.org_id()
            );
            Ok(())
        }
        Err(err) => Err(eyre!(
            "update_user_pool failed for org '{}': {err}",
            org.org_id()
        )),
    }
}

struct ProvisionUserParams<'a> {
    org: &'a SeedOrg,
    user: &'a SeedUser,
    pool_id: &'a PoolId,
    org_id: &'a OrganizationId,
    user_pool_client: &'a dyn UserPoolClient,
    schema: &'a UserSchema,
}

async fn provision_user(ctx: &SeedContext<'_>, params: ProvisionUserParams<'_>) -> Result<()> {
    let ProvisionUserParams {
        org,
        user,
        pool_id,
        org_id,
        user_pool_client,
        schema,
    } = params;

    let mut attributes = pure::seed_user_attrs_to_domain(user);
    validate_attributes(schema, &attributes).map_err(|errs| {
        eyre!(
            "attribute validation failed for user '{}' in org '{}': {errs:?}",
            user.email(),
            org.org_id()
        )
    })?;
    attributes.insert(
        EMAIL_VERIFIED_KEY.to_owned(),
        EMAIL_VERIFIED_VALUE.to_owned(),
    );

    let create_params = CreateUserParams {
        pool_id: pool_id.clone(),
        email: user.email().to_owned(),
        attributes,
    };

    let sub = match user_pool_client.admin_create_user(create_params).await {
        Ok(sub) => sub,
        Err(UserPoolError::UsernameExists) => {
            let existing = user_pool_client
                .admin_get_user(pool_id, user.email())
                .await
                .with_context(|| {
                    format!(
                        "user '{}' already exists in pool but admin_get_user failed",
                        user.email()
                    )
                })?;
            println!(
                "  User '{}' already exists in Cognito (recovered sub for idempotency)",
                user.email()
            );
            existing
        }
        Err(err) => {
            return Err(eyre!(
                "admin_create_user failed for '{}' in org '{}': {err}",
                user.email(),
                org.org_id()
            ));
        }
    };

    let groups: Vec<GroupName> = user
        .groups()
        .iter()
        .map(|g| GroupName::new(g.as_str()))
        .collect::<Result<_, _>>()
        .map_err(|e| {
            eyre!(
                "invalid group name in user '{}' membership: {e}",
                user.email()
            )
        })?;

    let row = MembershipRow::new(MembershipRowParams {
        sub: sub.clone(),
        org_id: org_id.clone(),
        groups,
        email: user.email().to_owned(),
        created_at: ctx.now,
        created_by: UserId::new(SEED_CREATED_BY)
            .map_err(|e| eyre!("internal: invalid SEED_CREATED_BY sentinel: {e}"))?,
    });

    let attrs = pure::membership_row_to_dynamo_attrs(&row);

    let mut request = ctx
        .dynamo
        .put_item()
        .table_name(&ctx.table_name)
        .condition_expression("attribute_not_exists(#sk)")
        .expression_attribute_names("#sk", "SK");
    for (name, value) in attrs {
        request = request.item(name, value);
    }

    match request.send().await {
        Ok(_) => {
            println!(
                "  Seeded user '{}' in org '{}' (sub={})",
                user.email(),
                org.org_id(),
                sub
            );
            Ok(())
        }
        Err(sdk_err) if is_conditional_check_failed(&sdk_err) => {
            println!(
                "  User '{}' already has a membership row in org '{}' (skipping)",
                user.email(),
                org.org_id()
            );
            Ok(())
        }
        Err(sdk_err) => Err(sdk_err).with_context(|| {
            format!(
                "DynamoDB PutItem membership for '{}' in org '{}' failed",
                user.email(),
                org.org_id()
            )
        }),
    }
}

/// `PutItem`-flavored CCFE matcher. Mirrors
/// `forgeguard_control_plane::dynamo_store::is_conditional_check_failed`.
fn is_conditional_check_failed(
    sdk_err: &aws_sdk_dynamodb::error::SdkError<
        aws_sdk_dynamodb::operation::put_item::PutItemError,
    >,
) -> bool {
    matches!(
        sdk_err,
        aws_sdk_dynamodb::error::SdkError::ServiceError(e)
            if e.err().is_conditional_check_failed_exception()
    )
}
