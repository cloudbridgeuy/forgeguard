//! Ed25519 signed-request identity resolver — I/O shell.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use forgeguard_authn_core::credential::Credential;
use forgeguard_authn_core::identity::{Identity, IdentityParams};
use forgeguard_authn_core::resolver::IdentityResolver;
use forgeguard_authn_core::signing::{
    parse_signature_header, verify, CanonicalPayload, Timestamp, TimestampValidator,
};
use forgeguard_authn_core::signing_key_store::SigningKeyStore;
use forgeguard_core::{TenantId, UserId};
use tracing::instrument;

/// Default maximum allowed drift between request timestamp and server time.
const DEFAULT_MAX_DRIFT: Duration = Duration::from_secs(300);

/// Header name used to locate the organization ID (case-insensitive match).
const ORG_ID_HEADER: &str = "x-forgeguard-org-id";

/// Fields extracted from a `SignedRequest` credential for verification.
struct SignedRequestFields {
    key_id: String,
    timestamp: u64,
    signature: String,
    trace_id: String,
    identity_headers: Vec<(String, String)>,
}

/// Ed25519 signed-request identity resolver.
///
/// Validates BYOC proxy requests by:
/// 1. Extracting the org ID from identity headers.
/// 2. Looking up the public key from the [`SigningKeyStore`].
/// 3. Rebuilding the canonical payload and verifying the signature.
/// 4. Checking the request timestamp falls within the drift window.
pub struct Ed25519SignatureResolver<S> {
    key_store: S,
    timestamp_validator: TimestampValidator,
}

impl<S: SigningKeyStore> Ed25519SignatureResolver<S> {
    /// Create a resolver with the default 5-minute drift window.
    pub fn new(key_store: S) -> Self {
        Self {
            key_store,
            timestamp_validator: TimestampValidator::new(DEFAULT_MAX_DRIFT),
        }
    }

    /// Create a resolver with a custom drift window.
    pub fn with_max_drift(key_store: S, max_drift: Duration) -> Self {
        Self {
            key_store,
            timestamp_validator: TimestampValidator::new(max_drift),
        }
    }

    /// Core verification logic, extracted for instrumentation.
    #[instrument(skip(self, fields), fields(resolver = "ed25519", key_id = %fields.key_id))]
    async fn verify_signed_request(
        &self,
        fields: &SignedRequestFields,
    ) -> forgeguard_authn_core::Result<Identity> {
        // 1. Extract org_id from identity_headers (case-insensitive).
        let org_id = fields
            .identity_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(ORG_ID_HEADER))
            .map(|(_, value)| value.as_str())
            .ok_or(forgeguard_authn_core::Error::MissingOrgId)?;

        // 2. Look up the public key.
        let public_key = self.key_store.get_key(org_id, &fields.key_id).await?;

        // 3. Rebuild canonical payload.
        let ts = Timestamp::from_millis(fields.timestamp);
        let payload = CanonicalPayload::new(&fields.trace_id, ts, &fields.identity_headers);

        // 4. Parse and verify signature.
        let parsed_sig = parse_signature_header(&fields.signature)?;
        verify(&public_key, &payload, &parsed_sig)?;

        // 5. Check timestamp drift.
        let now = Timestamp::from_system_time(SystemTime::now());
        self.timestamp_validator.check(ts, now)?;

        // 6. Build identity.
        let user_id = UserId::new(&fields.key_id).map_err(|e| {
            forgeguard_authn_core::Error::InvalidCredential(format!("invalid key_id: {e}"))
        })?;
        let tenant_id = TenantId::new(org_id).map_err(|e| {
            forgeguard_authn_core::Error::InvalidCredential(format!("invalid org_id: {e}"))
        })?;

        Ok(Identity::new(IdentityParams {
            user_id,
            tenant_id: Some(tenant_id),
            groups: vec![],
            expiry: None,
            resolver: "ed25519",
            extra: None,
        }))
    }
}

impl<S: SigningKeyStore> IdentityResolver for Ed25519SignatureResolver<S> {
    fn name(&self) -> &'static str {
        "ed25519"
    }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::SignedRequest { .. })
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = forgeguard_authn_core::Result<Identity>> + Send + '_>> {
        // Extract fields synchronously so the credential borrow doesn't need
        // to outlive the async block (the trait's `'_` is tied to `&self`).
        let fields = match credential {
            Credential::SignedRequest {
                key_id,
                timestamp,
                signature,
                trace_id,
                identity_headers,
            } => SignedRequestFields {
                key_id: key_id.clone(),
                timestamp: *timestamp,
                signature: signature.clone(),
                trace_id: trace_id.clone(),
                identity_headers: identity_headers.clone(),
            },
            _ => {
                return Box::pin(std::future::ready(Err(
                    forgeguard_authn_core::Error::InvalidCredential(format!(
                        "expected SignedRequest credential, got {}",
                        credential.type_name()
                    )),
                )))
            }
        };

        Box::pin(async move { self.verify_signed_request(&fields).await })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine as _;
    use forgeguard_authn_core::signing::{sign, KeyId, SigningKey, VerifyingKey};
    use forgeguard_authn_core::signing_key_store::InMemorySigningKeyStore;

    use super::*;

    /// Build an `InMemorySigningKeyStore` containing a single key.
    fn test_store(org_id: &str, key_id: &str, vk: VerifyingKey) -> InMemorySigningKeyStore {
        InMemorySigningKeyStore::new(HashMap::from([(
            (org_id.to_string(), key_id.to_string()),
            vk,
        )]))
    }

    /// Build a valid `SignedRequest` credential by signing with the given key.
    fn make_valid_credential(
        sk: &SigningKey,
        key_id_str: &str,
        org_id: &str,
        timestamp: u64,
    ) -> Credential {
        let key_id = KeyId::try_from(key_id_str.to_string()).unwrap();
        let ts = Timestamp::from_millis(timestamp);
        let trace_id = "trace-test-123";
        let identity_headers = vec![
            ("x-forgeguard-org-id".to_string(), org_id.to_string()),
            ("x-forgeguard-user-id".to_string(), "alice".to_string()),
        ];

        let payload = CanonicalPayload::new(trace_id, ts, &identity_headers);
        let signed = sign(sk, &key_id, &payload, ts, trace_id.to_string());

        Credential::SignedRequest {
            key_id: key_id_str.to_string(),
            timestamp,
            signature: signed.signature_header_value(),
            trace_id: trace_id.to_string(),
            identity_headers,
        }
    }

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    /// Return a timestamp representing "now" for test purposes.
    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn can_resolve_signed_request_returns_true() {
        let (_, vk) = test_keypair();
        let store = test_store("org-1", "key-1", vk);
        let resolver = Ed25519SignatureResolver::new(store);

        let cred = Credential::SignedRequest {
            key_id: "key-1".into(),
            timestamp: 1_700_000_000_000,
            signature: "v1:AAAA".into(),
            trace_id: "trace-abc".into(),
            identity_headers: vec![("x-forgeguard-org-id".into(), "org-1".into())],
        };

        assert!(resolver.can_resolve(&cred));
    }

    #[test]
    fn can_resolve_bearer_returns_false() {
        let (_, vk) = test_keypair();
        let store = test_store("org-1", "key-1", vk);
        let resolver = Ed25519SignatureResolver::new(store);

        let cred = Credential::Bearer("some-token".into());
        assert!(!resolver.can_resolve(&cred));
    }

    #[tokio::test]
    async fn resolve_valid_signature_returns_identity() {
        let (sk, vk) = test_keypair();
        let store = test_store("org-1", "key-1", vk);
        let resolver = Ed25519SignatureResolver::new(store);

        let ts = now_millis();
        let cred = make_valid_credential(&sk, "key-1", "org-1", ts);

        let identity = resolver.resolve(&cred).await.unwrap();

        assert_eq!(identity.user_id().as_str(), "key-1");
        assert_eq!(identity.tenant_id().unwrap().as_str(), "org-1");
        assert!(identity.groups().is_empty());
        assert!(identity.expiry().is_none());
        assert_eq!(identity.resolver(), "ed25519");
    }

    #[tokio::test]
    async fn resolve_invalid_signature_returns_error() {
        let (sk, vk) = test_keypair();
        let store = test_store("org-1", "key-1", vk);
        let resolver = Ed25519SignatureResolver::new(store);

        let ts = now_millis();
        let mut cred = make_valid_credential(&sk, "key-1", "org-1", ts);

        // Tamper with the signature.
        if let Credential::SignedRequest {
            ref mut signature, ..
        } = cred
        {
            // Replace with a different valid-format but wrong signature.
            let bad_bytes = [0u8; 64];
            let b64 = base64::engine::general_purpose::STANDARD.encode(bad_bytes);
            *signature = format!("v1:{b64}");
        }

        let result = resolver.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, forgeguard_authn_core::Error::SignatureInvalid),
            "expected SignatureInvalid, got: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_unknown_key_returns_error() {
        let (sk, _vk) = test_keypair();
        // Store is empty — no keys registered.
        let store = InMemorySigningKeyStore::new(HashMap::new());
        let resolver = Ed25519SignatureResolver::new(store);

        let ts = now_millis();
        let cred = make_valid_credential(&sk, "key-unknown", "org-1", ts);

        let result = resolver.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no active key"),
            "expected key-not-found error, got: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_missing_org_id_returns_error() {
        let (sk, vk) = test_keypair();
        let store = test_store("org-1", "key-1", vk);
        let resolver = Ed25519SignatureResolver::new(store);

        let ts = now_millis();
        let key_id = KeyId::try_from("key-1".to_string()).unwrap();
        let timestamp = Timestamp::from_millis(ts);
        let trace_id = "trace-test";
        // No x-forgeguard-org-id header.
        let identity_headers = vec![("x-forgeguard-user-id".to_string(), "alice".to_string())];
        let payload = CanonicalPayload::new(trace_id, timestamp, &identity_headers);
        let signed = sign(&sk, &key_id, &payload, timestamp, trace_id.to_string());

        let cred = Credential::SignedRequest {
            key_id: "key-1".to_string(),
            timestamp: ts,
            signature: signed.signature_header_value(),
            trace_id: trace_id.to_string(),
            identity_headers,
        };

        let result = resolver.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, forgeguard_authn_core::Error::MissingOrgId),
            "expected MissingOrgId, got: {err}"
        );
    }

    #[tokio::test]
    async fn resolve_expired_timestamp_returns_error() {
        let (sk, vk) = test_keypair();
        let store = test_store("org-1", "key-1", vk);
        // Use a very tight drift window so a stale timestamp fails.
        let resolver = Ed25519SignatureResolver::with_max_drift(store, Duration::from_secs(1));

        // Timestamp from 10 minutes ago.
        let stale_ts = now_millis() - 600_000;
        let cred = make_valid_credential(&sk, "key-1", "org-1", stale_ts);

        let result = resolver.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, forgeguard_authn_core::Error::TimestampDrift(_)),
            "expected TimestampDrift, got: {err}"
        );
    }
}
