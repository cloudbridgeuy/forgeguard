//! Canonical `X-Fg-*` header names — the single wire namespace (#111 V2).
//!
//! One constant per header so producers (proxy, forgeguard-axum) and
//! consumers (resolvers, pipeline) cannot drift. Values are lowercase; HTTP
//! header names are case-insensitive and Pingora/Axum normalize to lowercase.
//!
//! `xtask` intentionally repeats these as literals (it minimizes workspace
//! deps — see CLAUDE.md); `xtask/tests/signing_compat.rs` pins compatibility.
//!
//! `X_FG_REVISION` doubles as the control plane's *response* revision-token
//! header (optimistic locking, `X-Fg-Revision`) and as the decision
//! projection's forwarded-request header — same name, different direction
//! and surface (CP responses vs decision projection on forwarded requests),
//! so they cannot collide on one message.

/// Common prefix for all ForgeGuard headers.
pub const X_FG_PREFIX: &str = "x-fg-";

/// Authenticated user id.
pub const X_FG_USER_ID: &str = "x-fg-user-id";
/// Tenant id, when resolved.
pub const X_FG_TENANT_ID: &str = "x-fg-tenant-id";
/// Comma-joined group names.
pub const X_FG_GROUPS: &str = "x-fg-groups";
/// Which resolver produced the identity.
pub const X_FG_AUTH_PROVIDER: &str = "x-fg-auth-provider";
/// Principal FGRN.
pub const X_FG_PRINCIPAL: &str = "x-fg-principal";
/// Resolved feature flags (JSON).
pub const X_FG_FEATURES: &str = "x-fg-features";
/// Client IP as seen at the edge.
pub const X_FG_CLIENT_IP: &str = "x-fg-client-ip";
/// Org id for membership resolution (pipeline Phase 5b).
pub const X_FG_ORG_ID: &str = "x-fg-org-id";

/// Signing contract: request trace id.
pub const X_FG_TRACE_ID: &str = "x-fg-trace-id";
/// Signing contract: Unix-millis timestamp.
pub const X_FG_TIMESTAMP: &str = "x-fg-timestamp";
/// Signing contract: key id for rotation.
pub const X_FG_KEY_ID: &str = "x-fg-key-id";
/// Signing contract: `v1:{base64}` Ed25519 signature.
pub const X_FG_SIGNATURE: &str = "x-fg-signature";

/// Decision projection: principal's org-unit ancestry (`root/eng/...`).
pub const X_FG_SCOPE_PATH: &str = "x-fg-scope-path";
/// Decision projection: comma-joined granted verbs.
pub const X_FG_ENTITLEMENTS: &str = "x-fg-entitlements";
/// Decision projection: store revision that decided.
pub const X_FG_REVISION: &str = "x-fg-revision";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn all_constants_are_lowercase_and_prefixed() {
        for name in [
            X_FG_USER_ID,
            X_FG_TENANT_ID,
            X_FG_GROUPS,
            X_FG_AUTH_PROVIDER,
            X_FG_PRINCIPAL,
            X_FG_FEATURES,
            X_FG_CLIENT_IP,
            X_FG_ORG_ID,
            X_FG_TRACE_ID,
            X_FG_TIMESTAMP,
            X_FG_KEY_ID,
            X_FG_SIGNATURE,
            X_FG_SCOPE_PATH,
            X_FG_ENTITLEMENTS,
            X_FG_REVISION,
        ] {
            assert!(name.starts_with(X_FG_PREFIX), "{name}");
            assert_eq!(name, name.to_lowercase());
        }
    }
}
