//! See <https://github.com/matklad/cargo-xtask/>
//!
//! This binary defines various auxiliary build commands, which are not
//! expressible with just `cargo`.
//!
//! The binary is integrated into the `cargo` command line by using an
//! alias in `.cargo/config`.

mod lint;

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

#[derive(Parser)]
#[command(name = "xtask", about = "ForgeGuard development tasks")]
struct App {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run code quality checks (fmt, check, clippy, test, dependency analysis)
    Lint(lint::LintArgs),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let app = App::parse();

    match app.command {
        Commands::Lint(args) => lint::run(&args),
    }
}
