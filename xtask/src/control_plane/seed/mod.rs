//! `cargo xtask control-plane seed` — tear down V0 state, then re-seed
//! organizations into DynamoDB as `OrgStatus::Draft`.
//!
//! ## V5 invariant
//! No Cognito users, no VP push. Per-org Cognito pools and the V3 Active-org
//! VP write-path are owned by the saga ticket (separate from #102); user
//! provisioning lives in issue #100.
//!
//! ## 1Password dependencies
//! - `op://forgeguard-{env}/dynamodb/table-name` — DDB table for the seed.
//! - `op://forgeguard-{env}/cognito/user-pool-id` — CP dashboard pool the
//!   teardown phase scans for `org-{id}-*` users.
//! - `op://forgeguard-{env}/verified-permissions/policy-store-id` — same
//!   CP-dogfood VP store `cargo xtask control-plane cedar sync` writes to;
//!   the teardown phase removes any V0-era `cp-rbac-*` policies it finds.

mod groups;
mod orgs;
mod pure;
mod teardown;

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use chrono::{DateTime, Utc};
use clap::Args;
use color_eyre::eyre::{self, Context, Result};

use super::op::{build_aws_config, read_op};
use super::op_core::{build_vault_name, ForgeguardEnv};
use super::seed_core::{DynamoTarget, SeedConfig};

use groups::write_groups;
use orgs::write_orgs;
use pure::SeededOrgScope;
use teardown::{teardown_cp_vp_policies, teardown_users};

/// Wiring carried into every imperative-shell helper.
pub(crate) struct SeedContext<'a> {
    pub(crate) dynamo: &'a aws_sdk_dynamodb::Client,
    pub(crate) cognito: &'a aws_sdk_cognitoidentityprovider::Client,
    pub(crate) vp: &'a aws_sdk_verifiedpermissions::Client,
    pub(crate) table_name: String,
    pub(crate) pool_id: String,
    pub(crate) cp_dogfood_policy_store_id: String,
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
    vp: aws_sdk_verifiedpermissions::Client,
    table_name: String,
    pool_id: String,
    cp_dogfood_policy_store_id: String,
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
    let vp = aws_sdk_verifiedpermissions::Client::new(&sdk_config);

    let vault = build_vault_name(args.env);
    let op_account = Some(args.op_account.as_str());

    let table_name = match &target {
        DynamoTarget::Prod => read_op(&vault, "dynamodb", "table-name", op_account)?,
        DynamoTarget::Local { table, .. } => table.clone(),
    };
    let pool_id = read_op(&vault, "cognito", "user-pool-id", op_account)?;
    let cp_dogfood_policy_store_id = read_op(
        &vault,
        "verified-permissions",
        "policy-store-id",
        op_account,
    )?;

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
        vp,
        table_name,
        pool_id,
        cp_dogfood_policy_store_id,
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
        vp,
        table_name,
        pool_id,
        cp_dogfood_policy_store_id,
        config,
        scope,
        target,
    } = wiring;
    let ctx = SeedContext {
        dynamo: &dynamo,
        cognito: &cognito,
        vp: &vp,
        table_name,
        pool_id,
        cp_dogfood_policy_store_id,
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

    println!("== Teardown phase ==");
    let mut report = teardown_users(&ctx).await?;
    report.cp_vp_policies = teardown_cp_vp_policies(&ctx).await?;
    println!(
        "Tore down {} user(s), {} membership row(s), {} VP policy(ies).",
        report.users.len(),
        report.membership_rows,
        report.cp_vp_policies
    );
    println!();

    println!("== Re-seed phase ==");
    write_orgs(&ctx, ctx.config.organizations()).await?;
    write_groups(&ctx, ctx.config.organizations()).await?;

    println!();
    println!("Seed complete. All seeded orgs are Draft; no Cognito users created.");
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
