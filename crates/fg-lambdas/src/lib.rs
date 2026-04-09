#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Shared utilities for ForgeGuard Lambda binaries.
//!
//! Each binary in `src/bin/` is a thin imperative shell. This module provides
//! common initialization (tracing, AWS clients) so each binary stays minimal.

use tracing_subscriber::EnvFilter;

/// Initialize JSON-formatted tracing for Lambda.
///
/// Uses `AWS_LAMBDA_LOG_LEVEL` if set, otherwise defaults to `info`.
/// Output is JSON for CloudWatch Logs structured querying.
pub fn init_tracing() {
    let filter =
        EnvFilter::try_from_env("AWS_LAMBDA_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(false)
        .without_time() // Lambda adds its own timestamp
        .init();
}
