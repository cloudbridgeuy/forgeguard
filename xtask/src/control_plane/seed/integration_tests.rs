//! DynamoDB-local integration tests for the seed shell.
//!
//! Gated behind the `dynamodb-tests` Cargo feature so the default `cargo test`
//! still runs offline. `cargo xtask control-plane test` enables the feature and
//! injects `DYNAMODB_ENDPOINT` pointing at a freshly-started `dynamodb-local`
//! container.
//!
//! ## What's covered here
//!
//! - **Happy path** — `write_orgs` + `write_groups` produce one CONFIG row plus
//!   one GROUP row per declared role (4 rows for the V5 seed shape), and the
//!   CONFIG row's `status` attribute is `"draft"`.
//! - **Idempotency** — re-running the seed against the same table is a no-op:
//!   row count unchanged, no errors.
//! - **Negative — dangling inherit** — `write_groups` aborts before any
//!   `PutItem`; the offending parent name surfaces in the error string.
//! - **Negative — cycle** — `write_groups` aborts; the word `cycle` appears in
//!   the error string (case-insensitive).
//!
//! Pure validate-path negatives (invalid name, parser errors) live in
//! `seed/pure/tests.rs` and don't need DynamoDB.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, KeySchemaElement, KeyType, ProvisionedThroughput,
    ScalarAttributeType,
};
use chrono::Utc;
use tokio::sync::OnceCell;

use crate::control_plane::seed_core::SeedConfig;

use super::groups::write_groups;
use super::orgs::write_orgs;
use super::pure::SeededOrgScope;
use super::SeedContext;

const SEED_TOML: &str = r#"
[[organization]]
org_id = "org-acme"
name = "Acme Corp"
cognito_user_pool_id = "us-east-2_acme"

[[organization.group]]
name = "member"
description = "Read-only org access"
allow = ["cp-organization-read"]

[[organization.group]]
name = "admin"
description = "Org management"
inherits = ["member"]
allow = ["cp-organization-update"]

[[organization.group]]
name = "owner"
description = "Full org access"
inherits = ["admin"]
allow = ["cp-organization-delete"]
"#;

async fn warm_engine_once(client: &aws_sdk_dynamodb::Client) {
    static WARMED: OnceCell<()> = OnceCell::const_new();
    WARMED
        .get_or_init(|| async {
            const MAX_ATTEMPTS: u32 = 25;
            const BACKOFF: Duration = Duration::from_millis(200);
            for _ in 0..MAX_ATTEMPTS {
                if client.list_tables().send().await.is_ok() {
                    return;
                }
                tokio::time::sleep(BACKOFF).await;
            }
            panic!("DynamoDB Local did not become ready");
        })
        .await;
}

async fn test_client() -> aws_sdk_dynamodb::Client {
    let endpoint =
        std::env::var("DYNAMODB_ENDPOINT").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(aws_config::Region::new("us-east-2"))
        .test_credentials()
        .load()
        .await;
    let client = aws_sdk_dynamodb::Client::new(&config);
    warm_engine_once(&client).await;
    client
}

fn unique_table_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("xtask-seed-test-{ts}-{n}")
}

async fn create_test_table(client: &aws_sdk_dynamodb::Client, table_name: &str) {
    client
        .create_table()
        .table_name(table_name)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("PK")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("SK")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("PK")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("SK")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(5)
                .write_capacity_units(5)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

/// Stub clients for the surfaces these tests don't exercise. The seed
/// helpers under test (`write_orgs`, `write_groups`) only touch DynamoDB; the
/// Cognito + VP clients are present so `SeedContext` typechecks. They point at
/// `127.0.0.1:0` so an accidental request fails fast with a connect error
/// rather than silently hitting `dynamodb-local`.
async fn build_stub_cognito_and_vp() -> (
    aws_sdk_cognitoidentityprovider::Client,
    aws_sdk_verifiedpermissions::Client,
) {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url("http://127.0.0.1:0")
        .region(aws_config::Region::new("us-east-2"))
        .test_credentials()
        .load()
        .await;
    (
        aws_sdk_cognitoidentityprovider::Client::new(&config),
        aws_sdk_verifiedpermissions::Client::new(&config),
    )
}

async fn count_org_rows(
    client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    org_id: &str,
) -> usize {
    client
        .query()
        .table_name(table_name)
        .key_condition_expression("PK = :pk")
        .expression_attribute_values(":pk", AttributeValue::S(format!("ORG#{org_id}")))
        .send()
        .await
        .unwrap()
        .items
        .unwrap_or_default()
        .len()
}

#[tokio::test]
async fn seed_happy_path_writes_one_config_and_three_group_rows() {
    let dynamo = test_client().await;
    let table = unique_table_name();
    create_test_table(&dynamo, &table).await;
    let (cognito, vp) = build_stub_cognito_and_vp().await;
    let config: SeedConfig = toml::from_str(SEED_TOML).unwrap();
    let scope = SeededOrgScope::new(vec!["org-acme".to_owned()]).unwrap();

    let ctx = SeedContext {
        dynamo: &dynamo,
        cognito: &cognito,
        vp: &vp,
        table_name: table.clone(),
        pool_id: "stub".to_owned(),
        cp_dogfood_policy_store_id: "stub".to_owned(),
        config: &config,
        scope,
        now: Utc::now(),
    };

    write_orgs(&ctx, ctx.config.organizations()).await.unwrap();
    write_groups(&ctx, ctx.config.organizations())
        .await
        .unwrap();

    let items = dynamo
        .query()
        .table_name(&table)
        .key_condition_expression("PK = :pk")
        .expression_attribute_values(":pk", AttributeValue::S("ORG#org-acme".to_owned()))
        .send()
        .await
        .unwrap()
        .items
        .unwrap_or_default();
    assert_eq!(items.len(), 4, "expected 1 META + 3 GROUP rows");

    let meta = items
        .iter()
        .find(|i| {
            i.get("SK")
                .and_then(|v| v.as_s().ok())
                .is_some_and(|s| s == "META")
        })
        .expect("META row present");
    assert_eq!(
        meta.get("status").and_then(|v| v.as_s().ok()).unwrap(),
        "draft"
    );
}

#[tokio::test]
async fn seed_is_idempotent() {
    let dynamo = test_client().await;
    let table = unique_table_name();
    create_test_table(&dynamo, &table).await;
    let (cognito, vp) = build_stub_cognito_and_vp().await;
    let config: SeedConfig = toml::from_str(SEED_TOML).unwrap();
    let scope = SeededOrgScope::new(vec!["org-acme".to_owned()]).unwrap();

    let ctx = SeedContext {
        dynamo: &dynamo,
        cognito: &cognito,
        vp: &vp,
        table_name: table.clone(),
        pool_id: "stub".to_owned(),
        cp_dogfood_policy_store_id: "stub".to_owned(),
        config: &config,
        scope,
        now: Utc::now(),
    };

    write_orgs(&ctx, ctx.config.organizations()).await.unwrap();
    write_groups(&ctx, ctx.config.organizations())
        .await
        .unwrap();
    let first = count_org_rows(&dynamo, &table, "org-acme").await;

    write_orgs(&ctx, ctx.config.organizations()).await.unwrap();
    write_groups(&ctx, ctx.config.organizations())
        .await
        .unwrap();
    let second = count_org_rows(&dynamo, &table, "org-acme").await;

    assert_eq!(first, 4);
    assert_eq!(second, first, "second run must not change row count");
}

#[tokio::test]
async fn seed_dangling_inherit_aborts_before_any_put() {
    let dynamo = test_client().await;
    let table = unique_table_name();
    create_test_table(&dynamo, &table).await;
    let (cognito, vp) = build_stub_cognito_and_vp().await;
    let toml_str = r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[[organization.group]]
name = "broken"
inherits = ["nonexistent"]
allow = []
"#;
    let config: SeedConfig = toml::from_str(toml_str).unwrap();
    let scope = SeededOrgScope::new(vec!["org-acme".to_owned()]).unwrap();

    let ctx = SeedContext {
        dynamo: &dynamo,
        cognito: &cognito,
        vp: &vp,
        table_name: table.clone(),
        pool_id: "stub".to_owned(),
        cp_dogfood_policy_store_id: "stub".to_owned(),
        config: &config,
        scope,
        now: Utc::now(),
    };

    let err = write_groups(&ctx, ctx.config.organizations())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent"),
        "error must mention dangling parent: {msg}"
    );

    assert_eq!(
        count_org_rows(&dynamo, &table, "org-acme").await,
        0,
        "no rows must be written when validation fails"
    );
}

#[tokio::test]
async fn seed_cycle_aborts_before_any_put() {
    let dynamo = test_client().await;
    let table = unique_table_name();
    create_test_table(&dynamo, &table).await;
    let (cognito, vp) = build_stub_cognito_and_vp().await;
    let toml_str = r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[[organization.group]]
name = "a"
inherits = ["b"]
allow = []

[[organization.group]]
name = "b"
inherits = ["a"]
allow = []
"#;
    let config: SeedConfig = toml::from_str(toml_str).unwrap();
    let scope = SeededOrgScope::new(vec!["org-acme".to_owned()]).unwrap();

    let ctx = SeedContext {
        dynamo: &dynamo,
        cognito: &cognito,
        vp: &vp,
        table_name: table.clone(),
        pool_id: "stub".to_owned(),
        cp_dogfood_policy_store_id: "stub".to_owned(),
        config: &config,
        scope,
        now: Utc::now(),
    };

    let err = write_groups(&ctx, ctx.config.organizations())
        .await
        .unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(msg.contains("cycle"), "error must mention cycle: {msg}");

    assert_eq!(
        count_org_rows(&dynamo, &table, "org-acme").await,
        0,
        "no rows must be written when validation fails"
    );
}
