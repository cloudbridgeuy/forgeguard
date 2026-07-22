//! Imperative shell for V0 cleanup. Every helper is glue around an AWS SDK
//! call; all decisions delegate to `super::pure`.
//!
//! ## V5 invariant
//! The `seed` command tears down V0 state before re-seeding. We delete:
//! - Cognito users in the CP **dashboard** pool whose username matches the
//!   seeded `org-{id}-*` shape.
//! - DynamoDB membership rows (`PK=USER#{sub}, SK=ORG#*`) for every deleted
//!   user.
//!
//! Failures are fatal; partial teardown is a knowable, recoverable state
//! (re-run the seed). No retries.

use aws_sdk_dynamodb::types::AttributeValue;
use color_eyre::eyre::{Context, Result};

use super::pure;
use super::SeedContext;

/// Summary of what teardown removed; emitted as a single block by the
/// orchestrator.
#[derive(Debug, Default)]
pub(crate) struct TeardownReport {
    pub(crate) users: Vec<String>,
    pub(crate) membership_rows: u32,
}

/// Delete every Cognito user matching the seeded `org-{id}-*` shape and
/// every DynamoDB membership row owned by those users' subs.
pub(crate) async fn teardown_users(ctx: &SeedContext<'_>) -> Result<TeardownReport> {
    let mut matches: Vec<(String, Option<String>)> = Vec::new();

    let mut paginator = ctx
        .cognito
        .list_users()
        .user_pool_id(&ctx.pool_id)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("Cognito ListUsers failed")?;
        for user in page.users() {
            let Some(username) = user.username() else {
                continue;
            };
            if !pure::is_seeded_username(username, &ctx.scope) {
                continue;
            }
            let sub = user
                .attributes()
                .iter()
                .find(|a| a.name() == "sub")
                .and_then(|a| a.value())
                .map(str::to_owned);
            matches.push((username.to_owned(), sub));
        }
    }

    matches.sort_by(|a, b| a.0.cmp(&b.0));

    let mut report = TeardownReport::default();
    for (username, sub) in &matches {
        ctx.cognito
            .admin_delete_user()
            .user_pool_id(&ctx.pool_id)
            .username(username)
            .send()
            .await
            .with_context(|| format!("Cognito AdminDeleteUser '{username}' failed"))?;
        println!("  Deleted Cognito user '{username}'");
        report.users.push(username.clone());

        if let Some(sub) = sub {
            report.membership_rows += delete_membership_rows(ctx, sub).await?;
        } else {
            eprintln!(
                "  warn: Cognito user '{username}' has no 'sub' attribute; \
                 membership rows (if any) must be cleaned up by hand"
            );
        }
    }

    Ok(report)
}

async fn delete_membership_rows(ctx: &SeedContext<'_>, sub: &str) -> Result<u32> {
    let pk_value = pure::membership_pk_for_user(sub);
    let mut deleted = 0u32;
    let mut exclusive_start_key: Option<std::collections::HashMap<String, AttributeValue>> = None;

    loop {
        let mut request = ctx
            .dynamo
            .query()
            .table_name(&ctx.table_name)
            .key_condition_expression("#pk = :pk AND begins_with(#sk, :prefix)")
            .expression_attribute_names("#pk", "PK")
            .expression_attribute_names("#sk", "SK")
            .expression_attribute_values(":pk", AttributeValue::S(pk_value.clone()))
            .expression_attribute_values(":prefix", AttributeValue::S("ORG#".to_owned()));
        if let Some(key) = exclusive_start_key {
            request = request.set_exclusive_start_key(Some(key));
        }
        let result = request
            .send()
            .await
            .with_context(|| format!("DynamoDB Query for membership rows of '{sub}' failed"))?;

        for item in result.items.unwrap_or_default() {
            let Some(AttributeValue::S(pk)) = item.get("PK").cloned() else {
                continue;
            };
            let Some(AttributeValue::S(sk)) = item.get("SK").cloned() else {
                continue;
            };
            ctx.dynamo
                .delete_item()
                .table_name(&ctx.table_name)
                .key("PK", AttributeValue::S(pk.clone()))
                .key("SK", AttributeValue::S(sk.clone()))
                .send()
                .await
                .with_context(|| format!("DynamoDB DeleteItem membership '{pk}'/'{sk}' failed"))?;
            deleted += 1;
        }

        match result.last_evaluated_key {
            Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
            _ => break,
        }
    }

    if deleted > 0 {
        println!("  Deleted {deleted} membership row(s) for sub '{sub}'");
    }
    Ok(deleted)
}
