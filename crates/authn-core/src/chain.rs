//! Identity resolution chain — tries resolvers in order.

use std::sync::Arc;

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::resolver::IdentityResolver;

/// Tries identity resolvers in order. First one that can resolve the
/// credential owns the outcome — success or failure, the chain stops.
///
/// Mirrors the AWS SDK's DefaultCredentialsChain pattern.
pub struct IdentityChain {
    resolvers: Vec<Arc<dyn IdentityResolver>>,
}

impl IdentityChain {
    /// Create a new chain with the given resolvers (tried in order).
    pub fn new(resolvers: Vec<Arc<dyn IdentityResolver>>) -> Self {
        Self { resolvers }
    }

    /// Resolve a credential into an Identity.
    /// First resolver that `can_resolve()` owns the outcome.
    pub async fn resolve(&self, credential: &Credential) -> Result<Identity> {
        for resolver in &self.resolvers {
            if !resolver.can_resolve(credential) {
                continue;
            }
            return resolver.resolve(credential).await;
        }
        Err(Error::NoResolver {
            credential_type: credential.type_name().to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use forgeguard_core::{GroupName, TenantId, UserId};

    use super::*;

    // -- Mock resolvers -------------------------------------------------------

    /// A resolver that handles Bearer credentials and succeeds.
    struct BearerResolver;

    impl IdentityResolver for BearerResolver {
        fn name(&self) -> &'static str {
            "bearer-resolver"
        }

        fn can_resolve(&self, credential: &Credential) -> bool {
            matches!(credential, Credential::Bearer(_))
        }

        fn resolve(
            &self,
            _credential: &Credential,
        ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(Identity::new(
                UserId::new("bearer-user").unwrap(),
                Some(TenantId::new("tenant-a").unwrap()),
                vec![GroupName::new("users").unwrap()],
                None,
                "bearer-resolver",
                None,
            ))))
        }
    }

    /// A resolver that handles ApiKey credentials and succeeds.
    struct ApiKeyResolver;

    impl IdentityResolver for ApiKeyResolver {
        fn name(&self) -> &'static str {
            "api-key-resolver"
        }

        fn can_resolve(&self, credential: &Credential) -> bool {
            matches!(credential, Credential::ApiKey(_))
        }

        fn resolve(
            &self,
            _credential: &Credential,
        ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(Identity::new(
                UserId::new("apikey-user").unwrap(),
                Some(TenantId::new("tenant-b").unwrap()),
                vec![GroupName::new("service-accounts").unwrap()],
                None,
                "api-key-resolver",
                None,
            ))))
        }
    }

    /// A resolver that claims to handle Bearer but always fails.
    struct FailingBearerResolver;

    impl IdentityResolver for FailingBearerResolver {
        fn name(&self) -> &'static str {
            "failing-bearer-resolver"
        }

        fn can_resolve(&self, credential: &Credential) -> bool {
            matches!(credential, Credential::Bearer(_))
        }

        fn resolve(
            &self,
            _credential: &Credential,
        ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
            Box::pin(std::future::ready(Err(Error::InvalidCredential(
                "token verification failed".to_owned(),
            ))))
        }
    }

    /// A resolver that never claims any credential.
    struct NeverResolver;

    impl IdentityResolver for NeverResolver {
        fn name(&self) -> &'static str {
            "never-resolver"
        }

        fn can_resolve(&self, _credential: &Credential) -> bool {
            false
        }

        fn resolve(
            &self,
            _credential: &Credential,
        ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
            unreachable!("should never be called")
        }
    }

    // -- Tests ----------------------------------------------------------------

    #[tokio::test]
    async fn bearer_resolved_by_first_resolver() {
        let chain = IdentityChain::new(vec![Arc::new(BearerResolver), Arc::new(ApiKeyResolver)]);
        let cred = Credential::Bearer("tok_abc".into());
        let identity = chain.resolve(&cred).await.unwrap();
        assert_eq!(identity.user_id().as_str(), "bearer-user");
        assert_eq!(identity.resolver(), "bearer-resolver");
    }

    #[tokio::test]
    async fn api_key_resolved_by_second_resolver() {
        let chain = IdentityChain::new(vec![Arc::new(BearerResolver), Arc::new(ApiKeyResolver)]);
        let cred = Credential::ApiKey("key_xyz".into());
        let identity = chain.resolve(&cred).await.unwrap();
        assert_eq!(identity.user_id().as_str(), "apikey-user");
        assert_eq!(identity.resolver(), "api-key-resolver");
    }

    #[tokio::test]
    async fn resolver_that_cannot_resolve_is_skipped() {
        let chain = IdentityChain::new(vec![Arc::new(NeverResolver), Arc::new(BearerResolver)]);
        let cred = Credential::Bearer("tok_abc".into());
        let identity = chain.resolve(&cred).await.unwrap();
        assert_eq!(identity.resolver(), "bearer-resolver");
    }

    #[tokio::test]
    async fn failing_resolver_stops_chain_with_error() {
        // FailingBearerResolver claims Bearer but fails.
        // BearerResolver also handles Bearer but should never be reached.
        let chain = IdentityChain::new(vec![
            Arc::new(FailingBearerResolver),
            Arc::new(BearerResolver),
        ]);
        let cred = Credential::Bearer("tok_abc".into());
        let result = chain.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::InvalidCredential(_)),
            "expected InvalidCredential, got: {err}"
        );
    }

    #[tokio::test]
    async fn no_resolver_matches_returns_no_resolver_error() {
        let chain = IdentityChain::new(vec![Arc::new(NeverResolver)]);
        let cred = Credential::Bearer("tok_abc".into());
        let result = chain.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::NoResolver { .. }),
            "expected NoResolver, got: {err}"
        );
    }

    #[tokio::test]
    async fn empty_chain_returns_no_resolver_error() {
        let chain = IdentityChain::new(vec![]);
        let cred = Credential::ApiKey("key_xyz".into());
        let result = chain.resolve(&cred).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::NoResolver { .. }),
            "expected NoResolver, got: {err}"
        );
    }
}
