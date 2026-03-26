use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use url::Url;

use forgeguard_http::DefaultPolicy;

/// ForgeGuard auth-enforcing reverse proxy.
#[derive(Debug, Parser)]
#[command(name = "forgeguard-proxy", version, about)]
pub(crate) struct App {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose logging (debug level).
    #[arg(long, global = true, env = "FORGEGUARD_VERBOSE")]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Start the proxy server.
    Run(RunOptions),
}

/// Options for the `run` subcommand.
#[derive(Debug, clap::Args)]
pub(crate) struct RunOptions {
    /// Path to the configuration file.
    #[arg(long, default_value = "forgeguard.toml", env = "FORGEGUARD_CONFIG")]
    pub config: PathBuf,

    /// Override the listen address.
    #[arg(long, env = "FORGEGUARD_LISTEN")]
    pub listen: Option<SocketAddr>,

    /// Override the upstream URL.
    #[arg(long, env = "FORGEGUARD_UPSTREAM")]
    pub upstream: Option<Url>,

    /// Override the default policy (passthrough or deny).
    #[arg(long, env = "FORGEGUARD_DEFAULT_POLICY", value_parser = parse_default_policy)]
    pub default_policy: Option<DefaultPolicy>,
}

fn parse_default_policy(s: &str) -> std::result::Result<DefaultPolicy, String> {
    match s.to_lowercase().as_str() {
        "passthrough" => Ok(DefaultPolicy::Passthrough),
        "deny" => Ok(DefaultPolicy::Deny),
        other => Err(format!(
            "unknown default policy: '{other}' (expected 'passthrough' or 'deny')"
        )),
    }
}
