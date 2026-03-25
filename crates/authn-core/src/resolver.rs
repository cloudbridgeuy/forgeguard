//! Pluggable identity resolution trait.

use std::future::Future;
use std::pin::Pin;

use crate::credential::Credential;
use crate::error::Result;
use crate::identity::Identity;

/// Each resolver knows whether it can handle a credential type
/// and how to resolve it into a trusted Identity.
///
/// Modeled after `aws_credential_types::provider::ProvideCredentials`.
pub trait IdentityResolver: Send + Sync {
    /// Name for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Can this resolver handle this credential type?
    /// Fast, synchronous check — typically just a match on the variant.
    fn can_resolve(&self, credential: &Credential) -> bool;

    /// Validate the credential and produce a trusted Identity.
    /// Async because I/O implementations (JWKS fetch, token introspection)
    /// will need it.
    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>>;
}
