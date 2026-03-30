//! `forgeguard check` — validate a configuration file.

use std::path::Path;

use color_eyre::eyre::Result;
use owo_colors::OwoColorize;

/// Run config validation.
///
/// Loads the config, reports errors or prints OK, and returns errors through
/// the normal `Result` flow so color-eyre handles display consistently.
pub(crate) fn run(config_path: &Path) -> Result<()> {
    let config = forgeguard_http::load_config(config_path)
        .map_err(|e| color_eyre::eyre::eyre!("config error: {e}"))?;

    println!(
        "{} {} (project: {}, {} routes, {} public routes, {} flags)",
        "Config OK".green().bold(),
        config_path.display(),
        config.project_id(),
        config.routes().len(),
        config.public_routes().len(),
        config.features().flags.len(),
    );
    Ok(())
}
