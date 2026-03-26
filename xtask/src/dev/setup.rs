use clap::Args;
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct SetupArgs {
    /// Deploy Cognito user pool and seed test users
    #[arg(long)]
    pub cognito: bool,
    /// Delete and recreate test users
    #[arg(long)]
    pub force: bool,
    /// Print what would happen without executing
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(_args: &SetupArgs) -> Result<()> {
    Ok(())
}
