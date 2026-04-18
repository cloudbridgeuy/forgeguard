//! `forgeguard policies sync` — sync Cedar policies and schema to AWS Verified Permissions.

use std::path::Path;

use aws_sdk_verifiedpermissions::types::SchemaDefinition;
use color_eyre::eyre::{bail, Result, WrapErr};
use forgeguard_core::{compile_all_to_cedar, generate_cedar_schema};
use forgeguard_http::load_config;
use tracing::info;

use crate::aws::{self, AwsConfigParams};

/// Run the sync subcommand.
///
/// Validates first, then syncs to AWS Verified Permissions (unless `--dry-run`).
pub(crate) async fn run(
    config_path: &Path,
    profile: Option<&str>,
    region: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let config = load_config(config_path)
        .wrap_err_with(|| format!("failed to load config from '{}'", config_path.display()))?;

    let compiled_policies =
        compile_all_to_cedar(config.policies(), config.groups(), config.project_id())
            .wrap_err("failed to compile Cedar policies")?;

    let actions: Vec<_> = config.routes().iter().map(|r| r.action().clone()).collect();

    let entity_config = config.schema().to_entity_config();
    let schema = generate_cedar_schema(
        config.policies(),
        &actions,
        config.project_id(),
        entity_config.as_ref(),
    );

    info!(
        policies = compiled_policies.len(),
        "validation succeeded, {} policies compiled",
        compiled_policies.len()
    );

    if dry_run {
        println!("--- Cedar Schema (dry-run) ---");
        println!("{schema}");
        println!();
        for (i, policy) in compiled_policies.iter().enumerate() {
            println!("--- Policy {} (dry-run) ---", i + 1);
            println!("{policy}");
            println!();
        }
        println!("Dry-run complete. No changes synced to AWS.");
        return Ok(());
    }

    // Resolve the policy store ID from config.
    let authz = config
        .authz()
        .ok_or_else(|| color_eyre::eyre::eyre!("[authz] section missing from config"))?;
    let policy_store_id = authz.policy_store_id();

    // Build AWS SDK config.
    let sdk_config = aws::build_sdk_config(&AwsConfigParams {
        config: config.aws(),
        profile,
        region,
    })
    .await;

    let client = aws_sdk_verifiedpermissions::Client::new(&sdk_config);

    // Sync schema.
    info!("syncing Cedar schema to policy store '{policy_store_id}'...");
    client
        .put_schema()
        .policy_store_id(policy_store_id)
        .definition(SchemaDefinition::CedarJson(schema))
        .send()
        .await
        .wrap_err("failed to put Cedar schema")?;
    info!("schema synced successfully");

    // Sync policies.
    for (i, policy_body) in compiled_policies.iter().enumerate() {
        let statement = aws_sdk_verifiedpermissions::types::StaticPolicyDefinition::builder()
            .statement(policy_body.as_str())
            .build()
            .wrap_err_with(|| format!("failed to build static policy definition {}", i + 1))?;

        let definition = aws_sdk_verifiedpermissions::types::PolicyDefinition::Static(statement);

        info!("creating policy {}...", i + 1);
        let result = client
            .create_policy()
            .policy_store_id(policy_store_id)
            .definition(definition)
            .send()
            .await;

        match result {
            Ok(output) => {
                info!(
                    policy_id = output.policy_id(),
                    "policy {} created successfully",
                    i + 1
                );
            }
            Err(e) => {
                bail!("failed to create policy {}: {e}", i + 1);
            }
        }
    }

    println!(
        "Sync complete: schema + {} policies synced to policy store '{policy_store_id}'.",
        compiled_policies.len()
    );

    Ok(())
}
