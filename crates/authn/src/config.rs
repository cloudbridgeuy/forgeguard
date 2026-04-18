//! JWT resolver configuration.

use std::time::Duration;

use url::Url;

/// Configuration for the Cognito JWT identity resolver.
///
/// Private fields with a constructor that sets sensible defaults for claim names.
/// Builder methods allow overriding individual settings.
#[derive(Debug, Clone)]
pub struct JwtResolverConfig {
    jwks_url: Url,
    issuer: String,
    audience: Option<String>,
    user_id_claim: String,
    cache_ttl: Duration,
}

impl JwtResolverConfig {
    /// Create a new config with required fields and sensible defaults.
    ///
    /// Defaults:
    /// - `user_id_claim`: `"sub"`
    /// - `cache_ttl`: 1 hour
    /// - `audience`: None
    pub fn new(jwks_url: Url, issuer: impl Into<String>) -> Self {
        Self {
            jwks_url,
            issuer: issuer.into(),
            audience: None,
            user_id_claim: "sub".to_string(),
            cache_ttl: Duration::from_secs(3600),
        }
    }

    /// Set the expected audience claim.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Override the claim name used to extract the user ID.
    pub fn with_user_id_claim(mut self, claim: impl Into<String>) -> Self {
        self.user_id_claim = claim.into();
        self
    }

    /// Override the JWKS cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// The JWKS endpoint URL.
    pub fn jwks_url(&self) -> &Url {
        &self.jwks_url
    }

    /// The expected token issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The expected audience claim, if configured.
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// The claim name used to extract the user ID.
    pub fn user_id_claim(&self) -> &str {
        &self.user_id_claim
    }

    /// The JWKS cache time-to-live.
    pub fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_url() -> Url {
        Url::parse(
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc/.well-known/jwks.json",
        )
        .unwrap()
    }

    #[test]
    fn defaults_are_correct() {
        let config = JwtResolverConfig::new(
            test_url(),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
        );

        assert_eq!(config.user_id_claim(), "sub");
        assert_eq!(config.cache_ttl(), Duration::from_secs(3600));
        assert!(config.audience().is_none());
    }

    #[test]
    fn jwks_url_getter() {
        let url = test_url();
        let config = JwtResolverConfig::new(url.clone(), "issuer");
        assert_eq!(config.jwks_url(), &url);
    }

    #[test]
    fn issuer_getter() {
        let config = JwtResolverConfig::new(test_url(), "my-issuer");
        assert_eq!(config.issuer(), "my-issuer");
    }

    #[test]
    fn with_audience_sets_value() {
        let config = JwtResolverConfig::new(test_url(), "issuer").with_audience("my-audience");
        assert_eq!(config.audience(), Some("my-audience"));
    }

    #[test]
    fn with_user_id_claim_overrides_default() {
        let config = JwtResolverConfig::new(test_url(), "issuer").with_user_id_claim("email");
        assert_eq!(config.user_id_claim(), "email");
    }

    #[test]
    fn with_cache_ttl_overrides_default() {
        let config =
            JwtResolverConfig::new(test_url(), "issuer").with_cache_ttl(Duration::from_secs(300));
        assert_eq!(config.cache_ttl(), Duration::from_secs(300));
    }

    #[test]
    fn builder_chaining_works() {
        let config = JwtResolverConfig::new(test_url(), "issuer")
            .with_audience("aud")
            .with_user_id_claim("email")
            .with_cache_ttl(Duration::from_secs(60));

        assert_eq!(config.audience(), Some("aud"));
        assert_eq!(config.user_id_claim(), "email");
        assert_eq!(config.cache_ttl(), Duration::from_secs(60));
    }
}
