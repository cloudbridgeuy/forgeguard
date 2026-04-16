//! `cargo xtask control-plane dev` — one-shot local development environment.
//!
//! Starts DynamoDB Local, creates the table, seeds organizations, then launches
//! the control-plane binary.  Ctrl-C the control plane to exit; the container
//! is stopped automatically via `ContainerGuard`.

use std::collections::HashMap;
use std::path::Path;

use aws_sdk_dynamodb::config::Credentials;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use aws_sdk_dynamodb::Client;
use clap::Args;
use color_eyre::eyre::{self, Context, Result};
use serde::Deserialize;

use super::dynamo_local::{
    detect_container_runtime, discover_port, start_container, wait_for_dynamodb, ContainerGuard,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// CLI arguments for the dev subcommand.
#[derive(Args)]
pub(crate) struct DevArgs {
    /// DynamoDB table name to create.
    #[arg(
        long,
        default_value = "forgeguard-orgs-dev",
        env = "FORGEGUARD_CP_DYNAMODB_TABLE"
    )]
    table: String,

    /// Listen address for the control plane.
    #[arg(long, default_value = "127.0.0.1:3001", env = "FORGEGUARD_CP_LISTEN")]
    listen: String,

    /// Seed organizations from a JSON file.
    #[arg(long, default_value = "examples/control-plane/orgs.test.json")]
    seed: String,

    /// Extra arguments forwarded to the control-plane binary (after `--`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    extra: Vec<String>,
}

// ---------------------------------------------------------------------------
// Functional Core — seed data types (pure, no I/O)
// ---------------------------------------------------------------------------

/// Top-level shape of the seed JSON file.
#[derive(Deserialize)]
struct SeedFile {
    organizations: HashMap<String, SeedOrg>,
}

/// One organization entry in the seed JSON.
#[derive(Deserialize)]
struct SeedOrg {
    name: String,
    config: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Imperative Shell
// ---------------------------------------------------------------------------

/// Build a DynamoDB client pointed at a local endpoint.
async fn build_client(port: u16) -> Result<Client> {
    let endpoint_url = format!("http://127.0.0.1:{port}");

    let credentials = Credentials::new("test", "test", None, None, "static");
    let dynamo_config = aws_sdk_dynamodb::config::Builder::new()
        .endpoint_url(&endpoint_url)
        .region(aws_sdk_dynamodb::config::Region::new("us-east-2"))
        .credentials_provider(credentials)
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .build();

    Ok(Client::from_conf(dynamo_config))
}

/// Create the DynamoDB table with PK (HASH) + SK (RANGE) on PAY_PER_REQUEST.
async fn create_table(client: &Client, table: &str) -> Result<()> {
    println!("Creating DynamoDB table '{table}'...");

    client
        .create_table()
        .table_name(table)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("PK")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .context("failed to build PK attribute definition")?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("SK")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .context("failed to build SK attribute definition")?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("PK")
                .key_type(KeyType::Hash)
                .build()
                .context("failed to build PK key schema")?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("SK")
                .key_type(KeyType::Range)
                .build()
                .context("failed to build SK key schema")?,
        )
        .billing_mode(BillingMode::PayPerRequest)
        .send()
        .await
        .context("failed to create DynamoDB table")?;

    println!("Table '{table}' created.");
    Ok(())
}

/// Read the seed file and insert each organization into DynamoDB.
async fn seed_organizations(client: &Client, table: &str, seed_path: &str) -> Result<()> {
    let seed_path = Path::new(seed_path);
    let raw = std::fs::read_to_string(seed_path)
        .with_context(|| format!("failed to read seed file: {}", seed_path.display()))?;

    let seed: SeedFile = serde_json::from_str(&raw).context("failed to parse seed JSON")?;

    let now = chrono::Utc::now().to_rfc3339();

    for (org_id, org) in &seed.organizations {
        println!("Seeding organization '{org_id}'...");

        let config_json =
            serde_json::to_string(&org.config).context("failed to serialize org config")?;

        client
            .put_item()
            .table_name(table)
            .item(
                "PK",
                aws_sdk_dynamodb::types::AttributeValue::S(format!("ORG#{org_id}")),
            )
            .item(
                "SK",
                aws_sdk_dynamodb::types::AttributeValue::S("META".to_string()),
            )
            .item(
                "org_id",
                aws_sdk_dynamodb::types::AttributeValue::S(org_id.clone()),
            )
            .item(
                "name",
                aws_sdk_dynamodb::types::AttributeValue::S(org.name.clone()),
            )
            .item(
                "status",
                aws_sdk_dynamodb::types::AttributeValue::S("active".to_string()),
            )
            .item(
                "created_at",
                aws_sdk_dynamodb::types::AttributeValue::S(now.clone()),
            )
            .item(
                "updated_at",
                aws_sdk_dynamodb::types::AttributeValue::S(now.clone()),
            )
            .item(
                "config",
                aws_sdk_dynamodb::types::AttributeValue::S(config_json),
            )
            .send()
            .await
            .with_context(|| format!("failed to seed organization '{org_id}'"))?;
    }

    println!("Seeded {} organization(s).", seed.organizations.len());
    Ok(())
}

/// Launch `cargo run -p forgeguard_control_plane` as a child process and wait for it to exit.
fn launch_control_plane(table: &str, listen: &str, port: u16, extra: &[String]) -> Result<()> {
    let endpoint = format!("http://127.0.0.1:{port}");

    println!("Launching control plane (listen: {listen}, table: {table}, endpoint: {endpoint})...");
    println!("Press Ctrl-C to stop.");

    let mut args = vec![
        "run",
        "-p",
        "forgeguard_control_plane",
        "--",
        "--store",
        "dynamodb",
        "--dynamodb-table",
        table,
        "--listen",
        listen,
    ];
    let extra_refs: Vec<&str> = extra.iter().map(String::as_str).collect();
    args.extend_from_slice(&extra_refs);

    let status = duct::cmd("cargo", &args)
        .env("AWS_ENDPOINT_URL", &endpoint)
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("AWS_REGION", "us-east-2")
        .unchecked()
        .run()
        .context("failed to launch control plane")?;

    if !status.status.success() {
        eyre::bail!(
            "control plane exited with non-zero status: {}",
            status.status
        );
    }
    Ok(())
}

/// Orchestrate the full dev environment lifecycle.
pub(crate) async fn run(args: &DevArgs) -> Result<()> {
    let runtime = detect_container_runtime()?;
    let container_id = start_container(runtime)?;

    println!("Container: {container_id}");

    let _guard = ContainerGuard::new(runtime, container_id.clone());

    let port = discover_port(runtime, &container_id)?;
    wait_for_dynamodb(port)?;

    let client = build_client(port).await?;
    create_table(&client, &args.table).await?;
    seed_organizations(&client, &args.table, &args.seed).await?;

    launch_control_plane(&args.table, &args.listen, port, &args.extra)?;

    Ok(())
}
