//! `cargo xtask control-plane seed` — tear down V0 state, then re-seed
//! organizations into DynamoDB as `OrgStatus::Draft`.
//!
//! ## V6 invariant
//! Every seeded org is `Draft`; Cognito users are created in Phase 4.
//! Group writes are pure event appends for every org status (#117 V2).
//!
//! ## 1Password dependencies
//! - `op://forgeguard-{env}/dynamodb/table-name` — DDB table for the seed.
//! - `op://forgeguard-{env}/cognito/user-pool-id` — CP dashboard pool the
//!   teardown phase scans for `org-{id}-*` users.

mod groups;
mod orgs;
mod pure;
mod teardown;
mod users;

#[cfg(all(test, feature = "dynamodb-tests"))]
mod integration_tests;

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use chrono::{DateTime, Utc};
use clap::Args;
use color_eyre::eyre::{self, Context, Result};
use forgeguard_authn::user_pool::{AwsCognitoUserPoolClient, UserPoolClient};

use super::op::{build_aws_config, read_op};
use super::op_core::{build_vault_name, ForgeguardEnv};
use super::seed_core::{DynamoTarget, SeedConfig};

use groups::write_groups;
use orgs::write_orgs;
use pure::SeededOrgScope;
use teardown::teardown_users;
use users::write_users;

/// Wiring carried into every imperative-shell helper.
pub(crate) struct SeedContext<'a> {
    pub(crate) dynamo: &'a aws_sdk_dynamodb::Client,
    pub(crate) cognito: &'a aws_sdk_cognitoidentityprovider::Client,
    pub(crate) user_pool_client: &'a dyn UserPoolClient,
    pub(crate) table_name: String,
    pub(crate) pool_id: String,
    pub(crate) config: &'a SeedConfig,
    pub(crate) scope: SeededOrgScope,
    pub(crate) now: DateTime<Utc>,
}

/// CLI arguments for the seed subcommand.
#[derive(Args)]
pub(crate) struct SeedArgs {
    /// Seed configuration file.
    #[arg(long, default_value = "xtask/seed.toml")]
    config: String,

    /// Environment (prod only — do not use dev).
    #[arg(long, default_value = "prod", env = "FORGEGUARD_ENV")]
    env: ForgeguardEnv,

    /// 1Password account ID.
    #[arg(
        long,
        default_value = "YYN6IHBFRRD5RCLU63J46WPKMA",
        env = "FORGEGUARD_OP_ACCOUNT"
    )]
    op_account: String,

    /// AWS region.
    #[arg(long, default_value = "us-east-2", env = "AWS_REGION")]
    region: String,

    /// AWS profile.
    #[arg(long, default_value = "admin", env = "AWS_PROFILE")]
    profile: String,

    /// DynamoDB endpoint URL for local dev (e.g. `http://127.0.0.1:8000`).
    /// When set, `--dynamodb-table` is required and the 1Password lookup
    /// for the prod table name is skipped.
    #[arg(long)]
    dynamodb_endpoint: Option<String>,

    /// DynamoDB table name. Required when `--dynamodb-endpoint` is set.
    /// Ignored otherwise (prod reads the name from 1Password).
    #[arg(long)]
    dynamodb_table: Option<String>,
}

/// Owned wiring produced by `build_seed_context`. The orchestrator borrows
/// from it to construct the short-lived `SeedContext<'_>`.
struct SeedWiring {
    dynamo: aws_sdk_dynamodb::Client,
    cognito: aws_sdk_cognitoidentityprovider::Client,
    user_pool_client: AwsCognitoUserPoolClient,
    table_name: String,
    pool_id: String,
    config: SeedConfig,
    scope: SeededOrgScope,
    target: DynamoTarget,
}

/// Thin wiring: parse args, build SDK clients, read 1Password keys.
/// No domain logic; no AWS effects beyond client construction.
async fn build_seed_context(args: &SeedArgs) -> Result<SeedWiring> {
    let raw = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read seed config: {}", args.config))?;
    let config: SeedConfig = toml::from_str(&raw).context("failed to parse seed config")?;

    let target =
        DynamoTarget::from_cli_args(args.dynamodb_endpoint.clone(), args.dynamodb_table.clone())
            .map_err(|e| eyre::eyre!("{e}"))?;

    let sdk_config = build_aws_config(&args.profile, &args.region).await?;
    let dynamo = match &target {
        DynamoTarget::Prod => aws_sdk_dynamodb::Client::new(&sdk_config),
        DynamoTarget::Local { endpoint, .. } => build_local_dynamo_client(endpoint),
    };
    let cognito = aws_sdk_cognitoidentityprovider::Client::new(&sdk_config);
    let user_pool_client = AwsCognitoUserPoolClient::new(cognito.clone());

    let vault = build_vault_name(args.env);
    let op_account = Some(args.op_account.as_str());

    let table_name = match &target {
        DynamoTarget::Prod => read_op(&vault, "dynamodb", "table-name", op_account)?,
        DynamoTarget::Local { table, .. } => table.clone(),
    };
    let pool_id = read_op(&vault, "cognito", "user-pool-id", op_account)?;

    let scope = SeededOrgScope::new(
        config
            .organizations()
            .iter()
            .map(|o| o.org_id().to_owned())
            .collect(),
    )
    .map_err(|e| eyre::eyre!("{e}"))?;

    Ok(SeedWiring {
        dynamo,
        cognito,
        user_pool_client,
        table_name,
        pool_id,
        config,
        scope,
        target,
    })
}

pub(crate) async fn run(args: &SeedArgs) -> Result<()> {
    let wiring = build_seed_context(args).await?;
    let SeedWiring {
        dynamo,
        cognito,
        user_pool_client,
        table_name,
        pool_id,
        config,
        scope,
        target,
    } = wiring;
    let ctx = SeedContext {
        dynamo: &dynamo,
        cognito: &cognito,
        user_pool_client: &user_pool_client,
        table_name,
        pool_id,
        config: &config,
        scope,
        now: Utc::now(),
    };

    match &target {
        DynamoTarget::Prod => println!("DynamoDB: prod table '{}'", ctx.table_name),
        DynamoTarget::Local { endpoint, .. } => {
            println!("DynamoDB: local '{endpoint}' table '{}'", ctx.table_name)
        }
    }
    println!();

    println!("== Phase 0: validate seed config ==");
    let schemas = pure::preflight_validate(ctx.config.organizations())
        .map_err(|e| eyre::eyre!("seed pre-flight failed: {e}"))?;
    println!(
        "Validated {} org(s); every user schema parsed and every declared attribute checked.",
        schemas.len()
    );
    println!();

    println!("== Teardown phase ==");
    let report = teardown_users(&ctx).await?;
    println!(
        "Tore down {} user(s), {} membership row(s).",
        report.users.len(),
        report.membership_rows
    );
    println!();

    println!("== Re-seed phase ==");
    write_orgs(&ctx, ctx.config.organizations()).await?;
    write_groups(&ctx, ctx.config.organizations()).await?;
    for (org, schema) in ctx.config.organizations().iter().zip(&schemas) {
        write_users(&ctx, org, ctx.user_pool_client, schema).await?;
    }

    println!();
    println!("Seed complete. All seeded orgs are Draft; users created in Cognito and DDB.");
    Ok(())
}

/// Build a DynamoDB client pointed at a local endpoint (dynamodb-local).
///
/// Uses dummy static credentials — dynamodb-local doesn't validate them but
/// the AWS SDK requires some provider to be configured.
fn build_local_dynamo_client(endpoint: &str) -> aws_sdk_dynamodb::Client {
    let credentials = Credentials::new("test", "test", None, None, "static");
    let dynamo_config = aws_sdk_dynamodb::config::Builder::new()
        .endpoint_url(endpoint)
        .region(Region::new("us-east-2"))
        .credentials_provider(credentials)
        .behavior_version(BehaviorVersion::latest())
        .build();

    aws_sdk_dynamodb::Client::from_conf(dynamo_config)
}

/// Verify the committed `xtask/seed.toml` parses as the V6-shape `SeedConfig`
/// and passes the same `preflight_validate` pure helper the orchestrator runs
/// before any AWS call. A green test here proves a real
/// `cargo xtask control-plane seed` run will not fail Phase 0 on
/// `xtask/seed.toml`.
///
/// Negative cases (dangling inherit, cycle, invalid name, malformed schema,
/// missing required attr) live in `seed/pure/tests.rs` so this test stays
/// focused on the V6 shape of the committed file.
#[cfg(test)]
mod seed_toml_shape_tests {
    #![allow(clippy::unwrap_used)]
    use std::fs;

    use crate::control_plane::seed_core::SeedConfig;

    use super::pure::preflight_validate;

    fn load_seed_config() -> SeedConfig {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("seed.toml");
        let raw = fs::read_to_string(path).unwrap();
        toml::from_str(&raw).unwrap()
    }

    #[test]
    fn seed_toml_parses_into_v6_shape() {
        let config = load_seed_config();
        let orgs = config.organizations();
        assert_eq!(orgs.len(), 2, "expected exactly two seeded orgs");

        let names: Vec<&str> = orgs.iter().map(|o| o.org_id()).collect();
        assert_eq!(names, ["org-acme", "org-globex"]);
        assert!(
            !names.contains(&"forgeguard"),
            "seed.toml must not declare the platform org `forgeguard` (see plan §10)"
        );

        for org in orgs {
            let group_names: Vec<&str> = org.groups().iter().map(|g| g.name()).collect();
            assert_eq!(
                group_names,
                ["member", "admin", "owner"],
                "org '{}' must declare member/admin/owner",
                org.org_id()
            );

            assert_eq!(
                org.users().len(),
                2,
                "org '{}' must declare exactly two users",
                org.org_id()
            );

            let name_spec = org
                .user_schema()
                .standard()
                .get("name")
                .unwrap_or_else(|| panic!("org '{}' must declare `name` schema", org.org_id()));
            assert!(
                name_spec.required(),
                "org '{}' `name` must be required",
                org.org_id()
            );
            assert!(
                org.user_schema().custom().is_empty(),
                "org '{}' declares no custom attrs in V6",
                org.org_id()
            );

            for user in org.users() {
                let name = user.attributes().get("name").unwrap_or_else(|| {
                    panic!("user '{}' must declare a `name` attribute", user.email())
                });
                assert!(
                    !name.is_empty(),
                    "user '{}' `name` attribute must be non-empty",
                    user.email()
                );
            }
        }
    }

    #[test]
    fn seed_toml_passes_preflight() {
        let config = load_seed_config();
        let schemas = preflight_validate(config.organizations()).unwrap_or_else(|e| {
            panic!("seed.toml failed Phase 0 preflight: {e}");
        });
        assert_eq!(schemas.len(), config.organizations().len());
    }
}
