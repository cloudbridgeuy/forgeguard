use clap::Args;
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct UsersArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(_args: &UsersArgs) -> Result<()> {
    Ok(())
}
