//! In-memory API key resolver. Pure, no I/O.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use forgeguard_core::{GroupName, TenantId, UserId};

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::identity::{Identity, IdentityParams};
use crate::resolver::IdentityResolver;

/// Metadata for a static API key entry.
pub struct ApiKeyEntry {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
}

impl ApiKeyEntry {
    /// Create a new API key entry.
    pub fn new(user_id: UserId, tenant_id: Option<TenantId>, groups: Vec<GroupName>) -> Self {
        Self {
            user_id,
            tenant_id,
            groups,
        }
    }
}

/// In-memory API key resolver. Keys are loaded from config at startup.
/// No I/O — the key map is passed in at construction time.
pub struct StaticApiKeyResolver {
    keys: HashMap<String, ApiKeyEntry>,
}

impl StaticApiKeyResolver {
    /// Create a new resolver with the given key map.
    pub fn new(keys: HashMap<String, ApiKeyEntry>) -> Self {
        Self { keys }
    }
}

impl IdentityResolver for StaticApiKeyResolver {
    fn name(&self) -> &'static str {
        "static_api_key"
    }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::ApiKey(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
        let result = match credential {
            Credential::ApiKey(key) => match self.keys.get(key.as_str()) {
                Some(entry) => Ok(Identity::new(IdentityParams {
                    user_id: entry.user_id.clone(),
                    tenant_id: entry.tenant_id.clone(),
                    groups: entry.groups.clone(),
                    expiry: None, // API keys don't expire via this resolver
                    resolver: "static_api_key",
                    extra: None,
                })),
                None => Err(Error::InvalidCredential("unknown API key".into())),
            },
            Credential::Bearer(_) | Credential::SignedRequest { .. } => Err(
                Error::InvalidCredential("expected ApiKey credential".into()),
            ),
        };
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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

    /// Helper: build a resolver with one known key.
    fn make_resolver() -> StaticApiKeyResolver {
        let mut keys = HashMap::new();
        keys.insert(
            "key_valid_123".to_owned(),
            ApiKeyEntry::new(
                UserId::new("alice").unwrap(),
                Some(TenantId::new("acme-corp").unwrap()),
                vec![
                    GroupName::new("admin").unwrap(),
                    GroupName::new("backend-team").unwrap(),
                ],
            ),
        );
        StaticApiKeyResolver::new(keys)
    }

    #[tokio::test]
    async fn known_key_resolves_to_correct_identity() {
        let resolver = make_resolver();
        let cred = Credential::ApiKey("key_valid_123".into());

        assert!(resolver.can_resolve(&cred));

        let identity = resolver.resolve(&cred).await.unwrap();

        assert_eq!(identity.user_id().as_str(), "alice");
        assert_eq!(identity.tenant_id().unwrap().as_str(), "acme-corp");

        let group_names: Vec<&str> = identity
            .groups()
            .iter()
            .map(forgeguard_core::GroupName::as_str)
            .collect();
        assert_eq!(group_names, vec!["admin", "backend-team"]);

        assert!(identity.expiry().is_none());
        assert_eq!(identity.resolver(), "static_api_key");
        assert!(identity.extra().is_none());
    }

    #[tokio::test]
    async fn unknown_key_returns_invalid_credential() {
        let resolver = make_resolver();
        let cred = Credential::ApiKey("key_unknown_999".into());

        assert!(resolver.can_resolve(&cred));

        let err = resolver.resolve(&cred).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidCredential(ref msg) if msg.contains("unknown API key")),
            "expected InvalidCredential with 'unknown API key', got: {err}",
        );
    }

    #[test]
    fn bearer_credential_returns_can_resolve_false() {
        let resolver = make_resolver();
        let cred = Credential::Bearer("some-jwt-token".into());

        assert!(!resolver.can_resolve(&cred));
    }

    #[test]
    fn signed_request_credential_returns_can_resolve_false() {
        let resolver = make_resolver();
        assert!(!resolver.can_resolve(&make_signed_request()));
    }

    #[tokio::test]
    async fn bearer_credential_returns_error_on_resolve() {
        let resolver = make_resolver();
        let cred = Credential::Bearer("some-jwt-token".into());

        let err = resolver.resolve(&cred).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidCredential(ref msg) if msg.contains("expected ApiKey")),
            "expected InvalidCredential with 'expected ApiKey', got: {err}",
        );
    }
}
