use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Store backend for organization data.
#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum StoreBackend {
    Memory,
    #[value(name = "dynamodb")]
    DynamoDb,
}

/// ForgeGuard control plane API server.
#[derive(Debug, Parser)]
#[command(name = "forgeguard-control-plane", version, about)]
pub(crate) struct Cli {
    /// Store backend to use for organization data.
    #[arg(long, default_value = "memory", env = "FORGEGUARD_CP_STORE")]
    pub store: StoreBackend,

    /// Path to the organization config JSON file (required when --store=memory).
    #[arg(long, env = "FORGEGUARD_CP_CONFIG")]
    pub config: Option<PathBuf>,

    /// DynamoDB table name (required when --store=dynamodb).
    #[arg(long, env = "FORGEGUARD_CP_DYNAMODB_TABLE")]
    pub dynamodb_table: Option<String>,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:3001", env = "FORGEGUARD_CP_LISTEN")]
    pub listen: SocketAddr,

    /// Log level filter (e.g., info, debug, trace).
    #[arg(long, default_value = "info", env = "FORGEGUARD_CP_LOG_LEVEL")]
    pub log_level: String,
}
