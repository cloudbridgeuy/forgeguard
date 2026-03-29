//! `forgeguard policies` subcommands.

mod sync;
mod test;
mod validate;

use std::path::Path;

use clap::Subcommand;
use color_eyre::eyre::Result;

/// Subcommands under `forgeguard policies`.
#[derive(Debug, Subcommand)]
pub(crate) enum PoliciesCommand {
    /// Validate Cedar policies and schema locally (no AWS calls).
    Validate {
        /// Output as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Sync compiled Cedar policies and schema to AWS Verified Permissions.
    Sync {
        /// AWS profile override.
        #[arg(long)]
        profile: Option<String>,

        /// AWS region override.
        #[arg(long)]
        region: Option<String>,

        /// Print compiled output without syncing to AWS.
        #[arg(long)]
        dry_run: bool,
    },

    /// Test authorization decisions against AWS Verified Permissions.
    Test {
        /// AWS profile override.
        #[arg(long)]
        profile: Option<String>,

        /// AWS region override.
        #[arg(long)]
        region: Option<String>,

        /// Path to an external test scenarios file (TOML).
        #[arg(long)]
        tests: Option<String>,

        /// Principal identity for a single CLI test.
        #[arg(long)]
        principal: Option<String>,

        /// Comma-separated groups for a single CLI test.
        #[arg(long)]
        groups: Option<String>,

        /// Tenant for a single CLI test.
        #[arg(long)]
        tenant: Option<String>,

        /// Action (namespace:verb:entity) for a single CLI test.
        #[arg(long)]
        action: Option<String>,

        /// Resource (namespace::entity::id) for a single CLI test.
        #[arg(long)]
        resource: Option<String>,

        /// Expected result: "allow" or "deny".
        #[arg(long)]
        expect: Option<String>,
    },
}

impl PoliciesCommand {
    pub(crate) async fn run(&self, config_path: &Path) -> Result<()> {
        match self {
            Self::Validate { json } => validate::run(config_path, *json),
            Self::Sync {
                profile,
                region,
                dry_run,
            } => sync::run(config_path, profile.as_deref(), region.as_deref(), *dry_run).await,
            Self::Test {
                profile,
                region,
                tests,
                principal,
                groups,
                tenant,
                action,
                resource,
                expect,
            } => {
                let cli_flags = test::CliTestFlags {
                    principal: principal.as_deref(),
                    groups: groups.as_deref(),
                    tenant: tenant.as_deref(),
                    action: action.as_deref(),
                    resource: resource.as_deref(),
                    expect: expect.as_deref(),
                };
                test::run(
                    config_path,
                    profile.as_deref(),
                    region.as_deref(),
                    tests.as_deref(),
                    &cli_flags,
                )
                .await
            }
        }
    }
}
