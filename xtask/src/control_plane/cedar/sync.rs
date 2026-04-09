use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{self, Result};

use crate::control_plane::cedar_core;
use crate::control_plane::cedar_io;
use crate::control_plane::op;

#[derive(Args)]
pub(crate) struct SyncArgs {
    /// Path to the forgeguard.toml configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Dry-run mode: show what would be synced without making changes.
    #[arg(long)]
    dry_run: bool,
}

pub(crate) async fn run(
    args: &SyncArgs,
    op_account: Option<&str>,
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<()> {
    // 1. Preflight
    op::run_preflight()?;
    let region = region.ok_or_else(|| eyre::eyre!("--region or AWS_REGION is required"))?;
    let profile = profile.ok_or_else(|| eyre::eyre!("--profile or AWS_PROFILE is required"))?;

    // 2. Parse config
    let config = cedar_io::parse_cedar_config(&args.config)?;
    println!("Parsed config from {}", args.config.display());

    // 3. Resolve policy store ID (op:// or plain)
    let store_id = cedar_io::resolve_policy_store_id(&config.policy_store_id, op_account)?;
    println!("Policy store: {store_id}");

    // 4. Read schema file if [schema] section present
    let schema_content = match &config.schema {
        Some(schema_cfg) => {
            let content = cedar_io::read_schema_file(&args.config, &schema_cfg.path)?;
            println!("Schema: loaded from {}", schema_cfg.path);
            Some(content)
        }
        None => {
            println!("Schema: none configured");
            None
        }
    };

    // 5. Build desired state
    let desired = cedar_core::build_desired_state(&config, schema_content);

    // 6. Dry-run gate
    if args.dry_run {
        println!("\n--- Dry-run mode ---");
        print_summary(&desired);
        println!("No changes synced to AWS.");
        return Ok(());
    }

    // 7. Build AWS config and VP client
    let aws_config = op::build_aws_config(profile, region).await?;
    let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

    // 8. Push schema to VP (if present)
    if let Some(schema) = &desired.schema {
        println!("Pushing schema to VP...");
        cedar_io::put_schema(&vp_client, &store_id, schema).await?;
        println!("Schema synced successfully.");
    }

    // 9. Print summary
    print_summary(&desired);
    println!("Sync complete.");

    Ok(())
}

fn print_summary(desired: &cedar_core::DesiredState) {
    let schema_status = if desired.schema.is_some() {
        "present"
    } else {
        "none"
    };
    println!("\nSummary:");
    println!("  Schema: {schema_status}");
    println!("  Templates: {}", desired.templates.len());
    for t in &desired.templates {
        print_entry(&t.name, t.description.as_deref(), &t.statement);
    }
    println!(
        "  Policies: {} (Cedar only, RBAC skipped in V2)",
        desired.policies.len()
    );
    for p in &desired.policies {
        print_entry(&p.name, p.description.as_deref(), &p.statement);
    }
}

fn print_entry(name: &str, description: Option<&str>, statement: &str) {
    println!("    - {name}");
    if let Some(desc) = description {
        println!("      {desc}");
    }
    let preview = statement.lines().next().unwrap_or("");
    println!("      {preview}");
}
