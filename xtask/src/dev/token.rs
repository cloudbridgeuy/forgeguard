use clap::Args;
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct TokenArgs {
    /// Username to authenticate as
    #[arg(long)]
    pub user: String,
    /// Decode and pretty-print the JWT claims
    #[arg(long)]
    pub decode: bool,
}

pub async fn run(_args: &TokenArgs) -> Result<()> {
    Ok(())
}
