//! Optional Ed25519 signing of injected `X-Fg-*` headers.
//!
//! Key material is injected at construction — the library never fetches
//! keys (imperative shell stays in the embedding app). Use the org key
//! registered with the control plane (`org.key_generated`).

use forgeguard_authn_core::signing::{KeyId, SigningKey};

/// Org signing key + key id for outbound `X-Fg-*` header signing.
///
/// Without a `SigningConfig`, headers are injected unsigned (dev mode).
pub struct SigningConfig {
    key: SigningKey,
    key_id: KeyId,
}

impl SigningConfig {
    /// From already-parsed key material.
    pub fn new(key: SigningKey, key_id: KeyId) -> Self {
        Self { key, key_id }
    }

    /// Parse a PKCS#8 PEM private key (parse-don't-validate at the boundary;
    /// reading the PEM off disk is the caller's job).
    pub fn from_pkcs8_pem(pem: &str, key_id: KeyId) -> forgeguard_authn_core::Result<Self> {
        Ok(Self {
            key: SigningKey::from_pkcs8_pem(pem)?,
            key_id,
        })
    }

    pub(crate) fn key(&self) -> &SigningKey {
        &self.key
    }

    pub(crate) fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_pem() -> String {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        sk.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn from_pkcs8_pem_constructs() {
        let key_id = KeyId::try_from("proxy-prod-01".to_string()).unwrap();
        let config = SigningConfig::from_pkcs8_pem(&test_pem(), key_id).unwrap();
        assert_eq!(config.key_id().as_str(), "proxy-prod-01");
    }

    #[test]
    fn from_pkcs8_pem_rejects_garbage() {
        let key_id = KeyId::try_from("k".to_string()).unwrap();
        assert!(SigningConfig::from_pkcs8_pem("not a pem", key_id).is_err());
    }

    #[test]
    fn new_from_parsed_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let key_id = KeyId::try_from("k-1".to_string()).unwrap();
        let config = SigningConfig::new(key, key_id);
        assert_eq!(config.key_id().as_str(), "k-1");
    }
}
