use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// ForgeGuard control plane API server.
#[derive(Debug, Parser)]
#[command(name = "forgeguard-control-plane", version, about)]
pub(crate) struct Cli {
    /// Path to the organization config JSON file.
    #[arg(long, env = "FORGEGUARD_CP_CONFIG")]
    pub config: PathBuf,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:3001", env = "FORGEGUARD_CP_LISTEN")]
    pub listen: SocketAddr,

    /// Log level filter (e.g., info, debug, trace).
    #[arg(long, default_value = "info", env = "FORGEGUARD_CP_LOG_LEVEL")]
    pub log_level: String,
}
