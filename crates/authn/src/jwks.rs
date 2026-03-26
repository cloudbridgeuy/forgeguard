//! JWKS cache and fetcher.

use std::collections::HashMap;
use std::time::Instant;

use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::instrument;

use crate::config::JwtResolverConfig;
use crate::error::{Error, Result};

/// A cached entry: raw JWK data for reconstructing `DecodingKey` on demand.
struct CachedJwk {
    /// The raw RSA components needed to build a `DecodingKey`.
    n: String,
    e: String,
}

/// JWKS cache with TTL-based expiry and on-miss fetching.
///
/// Stores raw JWK data keyed by `kid`. Since `DecodingKey` is not `Clone`,
/// we store the raw RSA modulus (`n`) and exponent (`e`) and reconstruct
/// `DecodingKey` on each access.
pub(crate) struct JwksCache {
    cache: RwLock<HashMap<String, CachedJwk>>,
    last_fetch: RwLock<Option<Instant>>,
    client: reqwest::Client,
    config: JwtResolverConfig,
}

impl JwksCache {
    /// Create a new JWKS cache.
    pub(crate) fn new(config: JwtResolverConfig) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            last_fetch: RwLock::new(None),
            client: reqwest::Client::new(),
            config,
        }
    }

    /// Get a `DecodingKey` for the given key ID.
    ///
    /// Returns from cache if present and not expired. Otherwise fetches
    /// the JWKS endpoint and caches all keys.
    #[instrument(skip(self), fields(kid = %kid))]
    pub(crate) async fn get_key(&self, kid: &str) -> Result<DecodingKey> {
        // Check if cache is fresh and contains the key.
        if !self.is_expired().await {
            let cache = self.cache.read().await;
            if let Some(jwk) = cache.get(kid) {
                return DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                    .map_err(|e| Error::TokenDecode(format!("failed to build decoding key: {e}")));
            }
        }

        // Cache miss or expired — fetch fresh JWKS.
        self.fetch_jwks().await?;

        // Try again after fetch.
        let cache = self.cache.read().await;
        let jwk = cache
            .get(kid)
            .ok_or_else(|| Error::KeyNotFound(kid.to_string()))?;

        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| Error::TokenDecode(format!("failed to build decoding key: {e}")))
    }

    /// Check if the cache has expired based on TTL.
    async fn is_expired(&self) -> bool {
        let last = self.last_fetch.read().await;
        match *last {
            Some(instant) => instant.elapsed() > self.config.cache_ttl(),
            None => true,
        }
    }

    /// Fetch the JWKS from the configured endpoint and populate the cache.
    #[instrument(skip(self))]
    async fn fetch_jwks(&self) -> Result<()> {
        let url = self.config.jwks_url().as_str();
        tracing::debug!(url, "fetching JWKS");

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::JwksFetch(e.to_string()))?;

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| Error::JwksFetch(format!("failed to parse JWKS response: {e}")))?;

        let mut cache = self.cache.write().await;
        cache.clear();

        for key in &jwks.keys {
            // Only cache RSA keys with a kid.
            if key.kty == "RSA" {
                if let (Some(kid), Some(n), Some(e)) = (&key.kid, &key.n, &key.e) {
                    cache.insert(
                        kid.clone(),
                        CachedJwk {
                            n: n.clone(),
                            e: e.clone(),
                        },
                    );
                }
            }
        }

        let mut last = self.last_fetch.write().await;
        *last = Some(Instant::now());

        tracing::debug!(key_count = cache.len(), "JWKS cache refreshed");
        Ok(())
    }
}

/// The JWKS endpoint response.
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// A single JWK entry.
#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
    #[allow(dead_code)]
    alg: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "use")]
    use_: Option<String>,
}
