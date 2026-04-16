//! Cognito JWT identity resolver — I/O shell.

use std::future::Future;
use std::pin::Pin;

use forgeguard_authn_core::credential::Credential;
use forgeguard_authn_core::identity::Identity;
use forgeguard_authn_core::jwt_claims::JwtClaims;
use forgeguard_authn_core::resolver::IdentityResolver;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tracing::instrument;

use crate::claims::map_claims;
use crate::config::JwtResolverConfig;
use crate::error::{Error, Result};
use crate::jwks::JwksCache;

/// Cognito JWT identity resolver.
///
/// Implements `IdentityResolver` by:
/// 1. Extracting the `kid` from the JWT header.
/// 2. Fetching the corresponding key from the JWKS cache.
/// 3. Verifying the JWT signature and standard claims.
/// 4. Mapping validated claims to an `Identity`.
pub struct CognitoJwtResolver {
    cache: JwksCache,
    config: JwtResolverConfig,
}

impl CognitoJwtResolver {
    /// Create a new resolver with the given configuration.
    pub fn new(config: JwtResolverConfig) -> Self {
        let cache = JwksCache::new(config.clone());
        Self { cache, config }
    }

    /// Decode and verify a JWT, returning a trusted `Identity`.
    #[instrument(skip(self, token), fields(resolver = "cognito_jwt"))]
    async fn verify_token(&self, token: &str) -> Result<Identity> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Error::TokenDecode(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| Error::TokenDecode("JWT header missing 'kid' field".to_string()))?;

        let key = self.cache.get_key(&kid).await?;
        let claims = decode_token(token, &key, &self.config)?;

        map_claims(&claims, &self.config)
    }
}

/// Decode and validate the JWT using `jsonwebtoken`.
fn decode_token(token: &str, key: &DecodingKey, config: &JwtResolverConfig) -> Result<JwtClaims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[config.issuer()]);

    if let Some(aud) = config.audience() {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }

    let token_data =
        jsonwebtoken::decode::<JwtClaims>(token, key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => Error::SignatureInvalid,
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                Error::Core(forgeguard_authn_core::Error::TokenExpired)
            }
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                Error::Core(forgeguard_authn_core::Error::InvalidIssuer {
                    expected: config.issuer().to_string(),
                    actual: "unknown".to_string(),
                })
            }
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                Error::Core(forgeguard_authn_core::Error::InvalidAudience)
            }
            _ => Error::TokenDecode(e.to_string()),
        })?;

    Ok(token_data.claims)
}

impl IdentityResolver for CognitoJwtResolver {
    fn name(&self) -> &'static str {
        "cognito_jwt"
    }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = forgeguard_authn_core::Result<Identity>> + Send + '_>> {
        // Extract token synchronously so the credential borrow doesn't need
        // to outlive the async block (the trait's `'_` is tied to `&self`).
        let token = match credential {
            Credential::Bearer(token) => token.clone(),
            _ => {
                return Box::pin(std::future::ready(Err(
                    forgeguard_authn_core::Error::InvalidCredential(format!(
                        "expected Bearer credential, got {}",
                        credential.type_name()
                    )),
                )))
            }
        };

        Box::pin(async move {
            self.verify_token(&token).await.map_err(|e| match e {
                Error::Core(core_err) => core_err,
                other => forgeguard_authn_core::Error::MalformedToken(other.to_string()),
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    use super::*;

    /// Generate an RSA key pair for testing.
    fn test_rsa_keys() -> (EncodingKey, DecodingKey) {
        // Use a pre-generated 2048-bit RSA key pair for deterministic tests.
        let rsa_private = include_str!("../tests/fixtures/rsa_private.pem");
        let rsa_public = include_str!("../tests/fixtures/rsa_public.pem");

        let encoding = EncodingKey::from_rsa_pem(rsa_private.as_bytes()).unwrap();
        let decoding = DecodingKey::from_rsa_pem(rsa_public.as_bytes()).unwrap();
        (encoding, decoding)
    }

    fn test_claims() -> JwtClaims {
        JwtClaims {
            sub: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1-abc".to_string(),
            aud: Some("test-client".to_string()),
            exp: (chrono::Utc::now().timestamp() + 3600) as u64,
            iat: chrono::Utc::now().timestamp() as u64,
            token_use: "access".to_string(),
            scope: Some("openid".to_string()),
            cognito_groups: Some(vec!["admins".to_string()]),
            custom_claims: {
                let mut m = HashMap::new();
                m.insert("custom:org_id".to_string(), json!("acme-corp"));
                m
            },
        }
    }

    fn test_config() -> JwtResolverConfig {
        let url = url::Url::parse(
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1-abc/.well-known/jwks.json",
        )
        .unwrap();
        JwtResolverConfig::new(
            url,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1-abc",
        )
        .with_audience("test-client")
    }

    fn sign_token(claims: &JwtClaims, encoding_key: &EncodingKey, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(&header, claims, encoding_key).unwrap()
    }

    /// Construct a `SignedRequest` credential for testing.
    fn make_signed_request() -> Credential {
        Credential::SignedRequest {
            key_id: "key-001".into(),
            timestamp: 1_700_000_000_000,
            signature: "v1:AAAA".into(),
            trace_id: "trace-abc".into(),
            identity_headers: vec![("X-ForgeGuard-Org-Id".into(), "org-123".into())],
        }
    }

    #[test]
    fn can_resolve_bearer_returns_true() {
        let config = test_config();
        let resolver = CognitoJwtResolver::new(config);
        let cred = Credential::Bearer("some-token".to_string());
        assert!(resolver.can_resolve(&cred));
    }

    #[test]
    fn can_resolve_api_key_returns_false() {
        let config = test_config();
        let resolver = CognitoJwtResolver::new(config);
        let cred = Credential::ApiKey("some-key".to_string());
        assert!(!resolver.can_resolve(&cred));
    }

    #[test]
    fn can_resolve_signed_request_returns_false() {
        let config = test_config();
        let resolver = CognitoJwtResolver::new(config);
        assert!(!resolver.can_resolve(&make_signed_request()));
    }

    #[test]
    fn name_returns_cognito_jwt() {
        let config = test_config();
        let resolver = CognitoJwtResolver::new(config);
        assert_eq!(resolver.name(), "cognito_jwt");
    }

    #[test]
    fn decode_token_with_valid_signature() {
        let (encoding_key, decoding_key) = test_rsa_keys();
        let claims = test_claims();
        let config = test_config();

        let token = sign_token(&claims, &encoding_key, "test-kid");
        let decoded = decode_token(&token, &decoding_key, &config).unwrap();

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.iss, claims.iss);
    }

    #[test]
    fn decode_token_invalid_signature_returns_error() {
        let (encoding_key, _) = test_rsa_keys();
        let claims = test_claims();
        let config = test_config();

        let token = sign_token(&claims, &encoding_key, "test-kid");

        // Use a different key to verify — should fail.
        let other_private = include_str!("../tests/fixtures/rsa_private2.pem");
        let other_public = include_str!("../tests/fixtures/rsa_public2.pem");
        let _ = EncodingKey::from_rsa_pem(other_private.as_bytes()).unwrap();
        let wrong_key = DecodingKey::from_rsa_pem(other_public.as_bytes()).unwrap();

        let result = decode_token(&token, &wrong_key, &config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::SignatureInvalid));
    }

    #[test]
    fn decode_token_expired_returns_error() {
        let (encoding_key, decoding_key) = test_rsa_keys();
        let mut claims = test_claims();
        claims.exp = 1_000_000; // far in the past
        let config = test_config();

        let token = sign_token(&claims, &encoding_key, "test-kid");
        let result = decode_token(&token, &decoding_key, &config);
        assert!(result.is_err());
    }

    #[test]
    fn decode_token_wrong_issuer_returns_error() {
        let (encoding_key, decoding_key) = test_rsa_keys();
        let mut claims = test_claims();
        claims.iss = "https://evil.example.com".to_string();
        let config = test_config();

        let token = sign_token(&claims, &encoding_key, "test-kid");
        let result = decode_token(&token, &decoding_key, &config);
        assert!(result.is_err());
    }

    #[test]
    fn decode_token_no_audience_validation_when_not_configured() {
        let (encoding_key, decoding_key) = test_rsa_keys();
        let claims = test_claims();
        let url = url::Url::parse(
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1-abc/.well-known/jwks.json",
        )
        .unwrap();
        let config = JwtResolverConfig::new(
            url,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1-abc",
        );
        // No audience set — should not validate.
        let token = sign_token(&claims, &encoding_key, "test-kid");
        let result = decode_token(&token, &decoding_key, &config);
        assert!(result.is_ok());
    }
}
