//! `cargo xtask control-plane seed` — seed organizations and test users.
//!
//! Creates organizations in DynamoDB and Cognito users for manual QA.
//! Passwords are auto-generated and stored in 1Password.
//! Idempotent: re-running rotates passwords and updates group membership.

use clap::Args;
use color_eyre::eyre::{self, Context, Result};

use super::op::{build_aws_config, read_op, store_in_op};
use super::op_core::{build_vault_name, ForgeguardEnv};
use super::schema::orgs_schema;
use super::seed_core::SeedConfig;

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
}

pub(crate) async fn run(args: &SeedArgs) -> Result<()> {
    let vault = build_vault_name(args.env);
    let op_account = Some(args.op_account.as_str());

    let raw = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read seed config: {}", args.config))?;
    let config: SeedConfig = toml::from_str(&raw).context("failed to parse seed config")?;

    let table_name = read_op(&vault, "dynamodb", "table-name", op_account)?;
    let pool_id = read_op(&vault, "cognito", "user-pool-id", op_account)?;

    println!("Table: {table_name}");
    println!("User pool: {pool_id}");
    println!();

    let sdk_config = build_aws_config(&args.profile, &args.region).await?;
    let dynamo_client = aws_sdk_dynamodb::Client::new(&sdk_config);
    let cognito_client = aws_sdk_cognitoidentityprovider::Client::new(&sdk_config);

    seed_organizations(&dynamo_client, &table_name, &config).await?;
    seed_users(&cognito_client, &pool_id, &vault, op_account, &config).await?;

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

async fn seed_users(
    client: &aws_sdk_cognitoidentityprovider::Client,
    pool_id: &str,
    vault: &str,
    op_account: Option<&str>,
    config: &SeedConfig,
) -> Result<()> {
    use aws_sdk_cognitoidentityprovider::types::{AttributeType, MessageActionType};

    for user in config.users() {
        println!("Seeding user '{}'...", user.username());

        // 1. Create user (or skip if already exists).
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
            .user_attributes(
                AttributeType::builder()
                    .name("custom:org_id")
                    .value(user.org_id())
                    .build()
                    .context("failed to build org_id attribute")?,
            )
            .message_action(MessageActionType::Suppress)
            .send()
            .await;

        match create_result {
            Ok(_) => println!("  Created user"),
            Err(err) => {
                if is_username_exists_error(&err) {
                    println!("  User exists, updating...");
                } else {
                    return Err(err)
                        .context(format!("failed to create user '{}'", user.username()));
                }
            }
        }

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

        // 3. Update group membership — remove from all, add to target.
        let groups_resp = client
            .admin_list_groups_for_user()
            .user_pool_id(pool_id)
            .username(user.username())
            .send()
            .await
            .with_context(|| format!("failed to list groups for '{}'", user.username()))?;

        for group in groups_resp.groups() {
            if let Some(name) = group.group_name() {
                if name != user.group() {
                    client
                        .admin_remove_user_from_group()
                        .user_pool_id(pool_id)
                        .username(user.username())
                        .group_name(name)
                        .send()
                        .await
                        .with_context(|| {
                            format!("failed to remove '{}' from group '{name}'", user.username())
                        })?;
                    println!("  Removed from group '{name}'");
                }
            }
        }

        client
            .admin_add_user_to_group()
            .user_pool_id(pool_id)
            .username(user.username())
            .group_name(user.group())
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to add '{}' to group '{}'",
                    user.username(),
                    user.group()
                )
            })?;
        println!("  Added to group '{}'", user.group());

        // 4. Store password in 1Password.
        let item_name = format!("test-user-{}", user.username());
        store_in_op(vault, &item_name, "password", &password, op_account)?;
        println!("  Password stored in 1Password (op://{vault}/{item_name}/password)");
    }

    println!("Seeded {} user(s).", config.users().len());
    Ok(())
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
