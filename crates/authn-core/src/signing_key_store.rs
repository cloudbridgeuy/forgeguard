//! Async key store for Ed25519 public key lookup.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::signing::VerifyingKey;
use crate::{Error, Result};

/// Async key store for Ed25519 public key lookup.
///
/// Implementations handle key status checking (active/rotating),
/// expiry validation, and PEM parsing. Callers receive a ready-to-use
/// [`VerifyingKey`] or an error.
pub trait SigningKeyStore: Send + Sync {
    /// Look up a verifying key by organization and key ID.
    fn get_key(
        &self,
        org_id: &str,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifyingKey>> + Send + '_>>;
}

/// In-memory key store for tests.
pub struct InMemorySigningKeyStore {
    /// Map of `(org_id, key_id)` to [`VerifyingKey`].
    keys: HashMap<(String, String), VerifyingKey>,
}

impl InMemorySigningKeyStore {
    /// Create a new store from a pre-populated map.
    pub fn new(keys: HashMap<(String, String), VerifyingKey>) -> Self {
        Self { keys }
    }
}

impl SigningKeyStore for InMemorySigningKeyStore {
    fn get_key(
        &self,
        org_id: &str,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifyingKey>> + Send + '_>> {
        let result = self
            .keys
            .get(&(org_id.to_string(), key_id.to_string()))
            .cloned()
            .ok_or_else(|| {
                Error::InvalidCredential(format!("no active key '{key_id}' for org '{org_id}'"))
            });
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::signing::SigningKey;

    #[tokio::test]
    async fn get_key_returns_known_key() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = VerifyingKey::from(&sk);

        let mut keys = HashMap::new();
        keys.insert(("org-1".to_string(), "key-1".to_string()), vk.clone());

        let store = InMemorySigningKeyStore::new(keys);
        let result = store.get_key("org-1", "key-1").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn get_key_unknown_returns_error() {
        let store = InMemorySigningKeyStore::new(HashMap::new());
        let result = store.get_key("org-1", "key-1").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no active key 'key-1' for org 'org-1'"),
            "unexpected error message: {msg}"
        );
    }
}
