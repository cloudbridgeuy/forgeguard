#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Lambda entry point for the control-plane API.
//!
//! Wraps the Axum router from `forgeguard_control_plane` with `lambda_http`
//! so it can serve requests behind a Lambda function URL.

use forgeguard_control_plane::app::AuthConfig;
use lambda_http::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    fg_lambdas::init_tracing();

    if let Err(e) = color_eyre::install() {
        tracing::warn!("color_eyre already installed: {e}");
    }

    let table_name = std::env::var("TABLE_NAME")
        .map_err(|_| Error::from("TABLE_NAME environment variable is required"))?;

    let auth = match std::env::var("FORGEGUARD_CP_JWKS_URL") {
        Ok(jwks_url) => {
            let issuer = std::env::var("FORGEGUARD_CP_ISSUER").map_err(|_| {
                Error::from("FORGEGUARD_CP_ISSUER is required when FORGEGUARD_CP_JWKS_URL is set")
            })?;
            let audience = std::env::var("FORGEGUARD_CP_AUDIENCE").ok();
            let policy_store_id = std::env::var("FORGEGUARD_CP_POLICY_STORE_ID").map_err(|_| {
                Error::from(
                    "FORGEGUARD_CP_POLICY_STORE_ID is required when FORGEGUARD_CP_JWKS_URL is set",
                )
            })?;
            let config = AuthConfig::new(&jwks_url, issuer, audience, policy_store_id)
                .map_err(|e| Error::from(format!("invalid auth config: {e:#}")))?;
            Some(config)
        }
        Err(_) => {
            tracing::warn!("FORGEGUARD_CP_JWKS_URL not set, running without auth");
            None
        }
    };

    tracing::info!(%table_name, "building control-plane router");

    let router = forgeguard_control_plane::app::dynamodb_router(&table_name, auth.as_ref())
        .await
        .map_err(|e| Error::from(format!("failed to build router: {e:#}")))?;

    lambda_http::run(router).await
}
