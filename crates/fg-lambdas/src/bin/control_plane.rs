#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Lambda entry point for the control-plane API.
//!
//! Wraps the Axum router from `forgeguard_control_plane` with `lambda_http`
//! so it can serve requests behind a Lambda function URL.

use lambda_http::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    fg_lambdas::init_tracing();

    if let Err(e) = color_eyre::install() {
        tracing::warn!("color_eyre already installed: {e}");
    }

    let table_name = std::env::var("TABLE_NAME")
        .map_err(|_| Error::from("TABLE_NAME environment variable is required"))?;

    tracing::info!(%table_name, "building control-plane router");

    let router = forgeguard_control_plane::app::dynamodb_router(&table_name)
        .await
        .map_err(|e| Error::from(format!("failed to build router: {e:#}")))?;

    lambda_http::run(router).await
}
