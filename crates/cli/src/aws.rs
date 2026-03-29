//! AWS SDK configuration builder.
//!
//! Pure function: builds an `aws_config::SdkConfig` from TOML config + CLI
//! overrides + environment variables.
//!
//! Precedence: CLI flag -> env var -> `[aws]` config -> SDK default chain.

use aws_config::BehaviorVersion;
use forgeguard_http::AwsConfig;

/// Parameters for building the AWS SDK configuration.
pub(crate) struct AwsConfigParams<'a> {
    /// `[aws]` section from the TOML config.
    pub(crate) config: &'a AwsConfig,
    /// CLI `--profile` override.
    pub(crate) profile: Option<&'a str>,
    /// CLI `--region` override.
    pub(crate) region: Option<&'a str>,
}

/// Build an `aws_config::SdkConfig` with the given precedence chain.
///
/// CLI flag > env var > `[aws]` config section > SDK default chain.
pub(crate) async fn build_sdk_config(params: &AwsConfigParams<'_>) -> aws_config::SdkConfig {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());

    // Resolve profile: CLI flag first, then config file.
    // The `AWS_PROFILE` env var is handled automatically by the SDK default chain.
    let profile = params.profile.or(params.config.profile());
    if let Some(profile) = profile {
        loader = loader.profile_name(profile);
    }

    // Resolve region: CLI flag first, then config file.
    // The `AWS_REGION` / `AWS_DEFAULT_REGION` env vars are handled by the SDK.
    let region = params.region.or(params.config.region());
    if let Some(region) = region {
        loader = loader.region(aws_config::Region::new(region.to_owned()));
    }

    loader.load().await
}
