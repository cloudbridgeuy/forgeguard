//! `cargo xtask control-plane seed` — seed organizations and test users.
//!
//! Creates organizations in DynamoDB and Cognito users for manual QA.
//! Passwords are auto-generated and stored in 1Password.
//! Idempotent by PK/SK: re-running rotates passwords and overwrites
//! membership items (including `joined_at`). Accepted for a dev-only
//! fixture; production membership writes must use conditional puts.

use aws_sdk_dynamodb::types::AttributeValue;
use clap::Args;
use color_eyre::eyre::{self, Context, Result};

use super::op::{build_aws_config, read_op, store_in_op};
use super::op_core::{build_vault_name, ForgeguardEnv};
use super::schema::orgs_schema;
use super::seed_core::{DynamoTarget, SeedConfig};

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

    let pool_id = read_op(&vault, "cognito", "user-pool-id", op_account)?;
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

    let cognito_client = aws_sdk_cognitoidentityprovider::Client::new(&sdk_config);

    match &target {
        DynamoTarget::Prod => println!("DynamoDB: prod table '{table_name}'"),
        DynamoTarget::Local { endpoint, .. } => {
            println!("DynamoDB: local '{endpoint}' table '{table_name}'")
        }
    }
    println!("Cognito user pool: {pool_id}");
    println!();

    seed_organizations(&dynamo_client, &table_name, &config).await?;
    seed_users(SeedUsersParams {
        client: &cognito_client,
        dynamo_client: &dynamo_client,
        pool_id: &pool_id,
        table_name: &table_name,
        vault: &vault,
        op_account,
        config: &config,
    })
    .await?;

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
            .item(
                &schema.partition_key,
                aws_sdk_dynamodb::types::AttributeValue::S(pk_value),
            )
            .item(
                &schema.sort_key,
                aws_sdk_dynamodb::types::AttributeValue::S(org_type.sk.clone()),
            )
            .item(
                "name",
                aws_sdk_dynamodb::types::AttributeValue::S(org.name().to_string()),
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
                aws_sdk_dynamodb::types::AttributeValue::S(config_json.clone()),
            )
            .item(
                "etag",
                aws_sdk_dynamodb::types::AttributeValue::S(etag.clone()),
            )
            .send()
            .await
            .with_context(|| format!("failed to seed organization '{}'", org.org_id()))?;

        println!("  OK");
    }

    println!("Seeded {} organization(s).", config.organizations().len());
    Ok(())
}

/// Parameters for [`seed_users`].
///
/// Bundled into a struct because the function exceeds the five-argument
/// threshold enforced by `clippy.toml` (`too-many-arguments-threshold = 5`).
struct SeedUsersParams<'a> {
    client: &'a aws_sdk_cognitoidentityprovider::Client,
    dynamo_client: &'a aws_sdk_dynamodb::Client,
    pool_id: &'a str,
    table_name: &'a str,
    vault: &'a str,
    op_account: Option<&'a str>,
    config: &'a SeedConfig,
}

async fn seed_users(p: SeedUsersParams<'_>) -> Result<()> {
    use aws_sdk_cognitoidentityprovider::types::{AttributeType, MessageActionType};

    let SeedUsersParams {
        client,
        dynamo_client,
        pool_id,
        table_name,
        vault,
        op_account,
        config,
    } = p;

    let schema = orgs_schema();
    let now = chrono::Utc::now().to_rfc3339();

    for user in config.users() {
        println!("Seeding user '{}'...", user.username());

        // 1. Create user (or capture sub from existing user).
        let create_result = client
            .admin_create_user()
            .user_pool_id(pool_id)
            .username(user.username())
            .user_attributes(
                AttributeType::builder()
                    .name("email")
                    .value(user.email())
                    .build()
                    .context("failed to build email attribute")?,
            )
            .user_attributes(
                AttributeType::builder()
                    .name("email_verified")
                    .value("true")
                    .build()
                    .context("failed to build email_verified attribute")?,
            )
            .message_action(MessageActionType::Suppress)
            .send()
            .await;

        let user_sub = match create_result {
            Ok(resp) => {
                println!("  Created user");
                // AdminCreateUserOutput::user() -> UserType; UserType::attributes() -> &[AttributeType].
                resp.user()
                    .and_then(|u| extract_sub(u.attributes()))
                    .ok_or_else(|| eyre::eyre!("sub not returned for '{}'", user.username()))?
                    .to_owned()
            }
            Err(err) if is_username_exists_error(&err) => {
                println!("  User exists, fetching sub...");
                let existing = client
                    .admin_get_user()
                    .user_pool_id(pool_id)
                    .username(user.username())
                    .send()
                    .await
                    .with_context(|| format!("failed to get user '{}'", user.username()))?;
                // AdminGetUserOutput::user_attributes() -> &[AttributeType] (note the different method name).
                extract_sub(existing.user_attributes())
                    .ok_or_else(|| eyre::eyre!("sub not found for '{}'", user.username()))?
                    .to_owned()
            }
            Err(err) => {
                return Err(err).context(format!("failed to create user '{}'", user.username()))
            }
        };

        // 2. Set permanent password (rotates on re-run).
        let password = generate_password()?;
        client
            .admin_set_user_password()
            .user_pool_id(pool_id)
            .username(user.username())
            .password(&password)
            .permanent(true)
            .send()
            .await
            .with_context(|| format!("failed to set password for '{}'", user.username()))?;
        println!("  Password set");

        // 3. Write one DynamoDB membership item per membership entry.
        let pk_value = format!("USER#{user_sub}");
        for membership in user.memberships() {
            let sk_value = format!("ORG#{}", membership.org_id());
            let groups_list: Vec<AttributeValue> = membership
                .groups()
                .iter()
                .map(|g| AttributeValue::S(g.to_string()))
                .collect();

            dynamo_client
                .put_item()
                .table_name(table_name)
                .item(&schema.partition_key, AttributeValue::S(pk_value.clone()))
                .item(&schema.sort_key, AttributeValue::S(sk_value))
                .item("user_id", AttributeValue::S(user_sub.clone()))
                .item("org_id", AttributeValue::S(membership.org_id().to_string()))
                .item("groups", AttributeValue::L(groups_list))
                .item("joined_at", AttributeValue::S(now.clone()))
                .send()
                .await
                .with_context(|| {
                    format!(
                        "failed to write membership for '{}' in '{}'",
                        user.username(),
                        membership.org_id()
                    )
                })?;
            println!(
                "  Membership: {} (groups: {:?})",
                membership.org_id(),
                membership.groups()
            );
        }

        // 4. Store password in 1Password.
        let item_name = format!("test-user-{}", user.username());
        store_in_op(vault, &item_name, "password", &password, op_account)?;
        println!("  Password stored in 1Password (op://{vault}/{item_name}/password)");
    }

    println!("Seeded {} user(s).", config.users().len());
    Ok(())
}

/// Returns the value of the `sub` attribute from a Cognito attribute slice,
/// or `None` if the attribute is absent or has no value.
fn extract_sub(attrs: &[aws_sdk_cognitoidentityprovider::types::AttributeType]) -> Option<&str> {
    attrs
        .iter()
        .find(|a| a.name() == "sub")
        .and_then(|a| a.value())
}

fn generate_password() -> Result<String> {
    let random = duct::cmd!("openssl", "rand", "-base64", "24")
        .read()
        .context("failed to generate random password via openssl")?;
    // Prefix ensures all Cognito password policy classes are covered:
    // uppercase (F), lowercase (g), digit (1), symbol (!)
    Ok(format!("Fg1!{}", random.trim()))
}

fn is_username_exists_error(
    err: &aws_sdk_cognitoidentityprovider::error::SdkError<
        aws_sdk_cognitoidentityprovider::operation::admin_create_user::AdminCreateUserError,
    >,
) -> bool {
    matches!(
        err,
        aws_sdk_cognitoidentityprovider::error::SdkError::ServiceError(e)
            if e.err().is_username_exists_exception()
    )
}

/// Build a DynamoDB client pointed at a local endpoint (dynamodb-local).
///
/// Uses dummy static credentials — dynamodb-local doesn't validate them but
/// the AWS SDK requires some provider to be configured.
fn build_local_dynamo_client(endpoint: &str) -> aws_sdk_dynamodb::Client {
    use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};

    let credentials = Credentials::new("test", "test", None, None, "static");
    let config = aws_sdk_dynamodb::config::Builder::new()
        .endpoint_url(endpoint)
        .region(Region::new("us-east-2"))
        .credentials_provider(credentials)
        .behavior_version(BehaviorVersion::latest())
        .build();

    aws_sdk_dynamodb::Client::from_conf(config)
}
