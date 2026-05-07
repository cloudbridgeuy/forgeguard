//! `cargo xtask control-plane seed` — seed organizations into DynamoDB.
//!
//! Creates organizations as `OrgStatus::Draft`. User provisioning has moved
//! to issue #100 (per-org Cognito pools land via the saga ticket separately
//! from #102). This file is a transitional shim — issue #102 V5 splits it
//! into `seed/{mod,pure,teardown,orgs,groups}.rs`.

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use clap::Args;
use color_eyre::eyre::{self, Context, Result};

use super::op::{build_aws_config, read_op};
use super::op_core::{build_vault_name, ForgeguardEnv};
use super::schema::orgs_schema;
use super::seed_core::{DynamoTarget, SeedConfig};

#[allow(dead_code)] // consumers land in Tasks 4–6 of the V5 plan
mod pure;
#[allow(dead_code)] // consumed by the orchestrator in Task 6 of the V5 plan
mod teardown;

use pure::SeededOrgScope;

/// Wiring carried into every imperative-shell helper. Only the fields a given
/// helper needs are read; Task 6 will narrow this back down once the
/// orchestrator moves into `seed/mod.rs`.
#[allow(dead_code)] // populated by Task 6's `build_seed_context`
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

pub(crate) async fn run(args: &SeedArgs) -> Result<()> {
    let vault = build_vault_name(args.env);
    let op_account = Some(args.op_account.as_str());

    let raw = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read seed config: {}", args.config))?;
    let config: SeedConfig = toml::from_str(&raw).context("failed to parse seed config")?;

    let target =
        DynamoTarget::from_cli_args(args.dynamodb_endpoint.clone(), args.dynamodb_table.clone())
            .map_err(|e| eyre::eyre!(e))?;

    let sdk_config = build_aws_config(&args.profile, &args.region).await?;

    let (dynamo_client, table_name) = match &target {
        DynamoTarget::Prod => {
            let table_name = read_op(&vault, "dynamodb", "table-name", op_account)?;
            let client = aws_sdk_dynamodb::Client::new(&sdk_config);
            (client, table_name)
        }
        DynamoTarget::Local { endpoint, table } => {
            let client = build_local_dynamo_client(endpoint);
            (client, table.clone())
        }
    };

    match &target {
        DynamoTarget::Prod => println!("DynamoDB: prod table '{table_name}'"),
        DynamoTarget::Local { endpoint, .. } => {
            println!("DynamoDB: local '{endpoint}' table '{table_name}'")
        }
    }
    println!();

    seed_organizations(&dynamo_client, &table_name, &config).await?;

    println!();
    println!("Seed complete.");
    Ok(())
}

async fn seed_organizations(
    client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    config: &SeedConfig,
) -> Result<()> {
    let schema = orgs_schema();
    let org_type = schema
        .item_types
        .get("org")
        .ok_or_else(|| eyre::eyre!("missing 'org' item type in schema"))?;

    let now = chrono::Utc::now().to_rfc3339();

    let default_config = serde_json::json!({
        "version": "2026-04-17",
        "project_id": "seed-test",
        "upstream_url": "http://localhost:8080",
        "default_policy": "deny"
    });
    let config_json =
        serde_json::to_string(&default_config).context("failed to serialize default org config")?;
    let etag = format!("\"{:016x}\"", 0u64);

    for org in config.organizations() {
        println!("Seeding organization '{}'...", org.org_id());

        let pk_value = org_type.pk.replace("{org_id}", org.org_id());

        client
            .put_item()
            .table_name(table_name)
            .item(&schema.partition_key, AttributeValue::S(pk_value))
            .item(&schema.sort_key, AttributeValue::S(org_type.sk.clone()))
            .item("name", AttributeValue::S(org.name().to_string()))
            .item("status", AttributeValue::S("draft".to_string()))
            .item("created_at", AttributeValue::S(now.clone()))
            .item("updated_at", AttributeValue::S(now.clone()))
            .item("config", AttributeValue::S(config_json.clone()))
            .item("etag", AttributeValue::S(etag.clone()))
            .send()
            .await
            .with_context(|| format!("failed to seed organization '{}'", org.org_id()))?;

        println!("  OK");
    }

    println!("Seeded {} organization(s).", config.organizations().len());
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
