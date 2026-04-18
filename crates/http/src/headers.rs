//! Identity header injection for upstream requests.

use std::net::IpAddr;

use forgeguard_authn_core::Identity;
use forgeguard_core::ResolvedFlags;

// ---------------------------------------------------------------------------
// IdentityProjection
// ---------------------------------------------------------------------------

/// Per-request identity data to inject as upstream headers.
///
/// Constructed from an `Identity` plus optional resolved feature flags and client IP.
pub struct IdentityProjection {
    user_id: String,
    tenant_id: Option<String>,
    groups: Vec<String>,
    auth_provider: String,
    principal_fgrn: Option<String>,
    features_json: Option<String>,
    client_ip: Option<IpAddr>,
}

impl IdentityProjection {
    /// Construct from an `Identity`, optional resolved flags, and optional client IP.
    pub fn new(
        identity: &Identity,
        resolved_flags: Option<&ResolvedFlags>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let features_json = resolved_flags.and_then(|flags| {
            if flags.is_empty() {
                None
            } else {
                serde_json::to_string(flags).ok()
            }
        });

        Self {
            user_id: identity.user_id().as_str().to_string(),
            tenant_id: identity.tenant_id().map(|t| t.as_str().to_string()),
            groups: identity
                .groups()
                .iter()
                .map(|g| g.as_str().to_string())
                .collect(),
            auth_provider: identity.resolver().to_string(),
            principal_fgrn: None, // Populated by the proxy layer when tenant is known
            features_json,
            client_ip,
        }
    }

    /// Set the principal FGRN (computed externally because it needs tenant + project context).
    pub fn with_principal_fgrn(mut self, fgrn: String) -> Self {
        self.principal_fgrn = Some(fgrn);
        self
    }

    /// The user ID.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The tenant ID, if present.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// The group names.
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    /// Which auth provider resolved this identity.
    pub fn auth_provider(&self) -> &str {
        &self.auth_provider
    }

    /// The principal FGRN, if set.
    pub fn principal_fgrn(&self) -> Option<&str> {
        self.principal_fgrn.as_deref()
    }

    /// The features JSON, if any flags were resolved.
    pub fn features_json(&self) -> Option<&str> {
        self.features_json.as_deref()
    }

    /// The client IP, if present.
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }
}

// ---------------------------------------------------------------------------
// Header injection
// ---------------------------------------------------------------------------

/// Produce `X-ForgeGuard-*` header pairs from an identity projection.
///
/// Returns owned pairs — the proxy layer maps to its own header types.
pub fn inject_headers(projection: &IdentityProjection) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(7);

    headers.push((
        "x-forgeguard-user-id".to_string(),
        projection.user_id.clone(),
    ));

    if let Some(ref tenant) = projection.tenant_id {
        headers.push(("x-forgeguard-tenant-id".to_string(), tenant.clone()));
    }

    if !projection.groups.is_empty() {
        headers.push((
            "x-forgeguard-groups".to_string(),
            projection.groups.join(","),
        ));
    }

    headers.push((
        "x-forgeguard-auth-provider".to_string(),
        projection.auth_provider.clone(),
    ));

    if let Some(ref fgrn) = projection.principal_fgrn {
        headers.push(("x-forgeguard-principal".to_string(), fgrn.clone()));
    }

    if let Some(ref features) = projection.features_json {
        headers.push(("x-forgeguard-features".to_string(), features.clone()));
    }

    if let Some(ip) = projection.client_ip {
        headers.push(("x-forgeguard-client-ip".to_string(), ip.to_string()));
    }

    headers
}

/// Produce `X-ForgeGuard-*` headers with an optional Ed25519 signature.
///
/// When `signing` is `Some`, the identity headers are signed and four additional
/// headers are appended: `x-forgeguard-trace-id`, `x-forgeguard-timestamp`,
/// `x-forgeguard-key-id`, and `x-forgeguard-signature`.
///
/// When `signing` is `None`, this is equivalent to [`inject_headers`].
pub fn inject_signed_headers(
    projection: &IdentityProjection,
    signing: Option<(
        &forgeguard_authn_core::signing::SigningKey,
        &forgeguard_authn_core::signing::KeyId,
    )>,
    trace_id: &str,
    now: forgeguard_authn_core::signing::Timestamp,
) -> Vec<(String, String)> {
    let mut headers = inject_headers(projection);

    if let Some((key, key_id)) = signing {
        let payload =
            forgeguard_authn_core::signing::CanonicalPayload::new(trace_id, now, &headers);
        let signed =
            forgeguard_authn_core::signing::sign(key, key_id, &payload, now, trace_id.to_string());

        headers.push((
            "x-forgeguard-trace-id".to_string(),
            signed.trace_id_header_value().to_string(),
        ));
        headers.push((
            "x-forgeguard-timestamp".to_string(),
            signed.timestamp_header_value(),
        ));
        headers.push((
            "x-forgeguard-key-id".to_string(),
            signed.key_id_header_value(),
        ));
        headers.push((
            "x-forgeguard-signature".to_string(),
            signed.signature_header_value(),
        ));
    }

    headers
}

/// Produce a single client-IP header pair.
///
/// Used for anonymous or failed-opportunistic requests where no identity is available.
pub fn inject_client_ip(ip: IpAddr) -> (String, String) {
    ("x-forgeguard-client-ip".to_string(), ip.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_authn_core::IdentityParams;
    use forgeguard_core::{GroupName, PrincipalKind, TenantId, UserId};

    use super::*;

    fn make_identity(tenant: Option<&str>, groups: &[&str]) -> Identity {
        Identity::new(IdentityParams {
            user_id: UserId::new("alice").unwrap(),
            tenant_id: tenant.map(|t| TenantId::new(t).unwrap()),
            groups: groups.iter().map(|g| GroupName::new(*g).unwrap()).collect(),
            expiry: None,
            resolver: "jwt",
            extra: None,
            principal_kind: PrincipalKind::User,
        })
    }

    #[test]
    fn basic_header_injection() {
        let identity = make_identity(Some("acme-corp"), &["admin", "ops"]);
        let projection = IdentityProjection::new(&identity, None, None);
        let headers = inject_headers(&projection);

        let map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(map["x-forgeguard-user-id"], "alice");
        assert_eq!(map["x-forgeguard-tenant-id"], "acme-corp");
        assert_eq!(map["x-forgeguard-groups"], "admin,ops");
        assert_eq!(map["x-forgeguard-auth-provider"], "jwt");
    }

    #[test]
    fn no_tenant_no_groups() {
        let identity = make_identity(None, &[]);
        let projection = IdentityProjection::new(&identity, None, None);
        let headers = inject_headers(&projection);

        let keys: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"x-forgeguard-tenant-id"));
        assert!(!keys.contains(&"x-forgeguard-groups"));
        assert!(keys.contains(&"x-forgeguard-user-id"));
        assert!(keys.contains(&"x-forgeguard-auth-provider"));
    }

    #[test]
    fn with_client_ip() {
        let identity = make_identity(None, &[]);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let projection = IdentityProjection::new(&identity, None, Some(ip));
        let headers = inject_headers(&projection);

        let map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(map["x-forgeguard-client-ip"], "192.168.1.1");
    }

    #[test]
    fn with_principal_fgrn() {
        let identity = make_identity(None, &[]);
        let projection = IdentityProjection::new(&identity, None, None)
            .with_principal_fgrn("fgrn:my-app:acme:iam:user:alice".to_string());
        let headers = inject_headers(&projection);

        let map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            map["x-forgeguard-principal"],
            "fgrn:my-app:acme:iam:user:alice"
        );
    }

    #[test]
    fn inject_client_ip_only() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let (key, value) = inject_client_ip(ip);
        assert_eq!(key, "x-forgeguard-client-ip");
        assert_eq!(value, "10.0.0.1");
    }

    #[test]
    fn with_resolved_flags_empty() {
        let identity = make_identity(None, &[]);
        let flags = ResolvedFlags::default();
        // Empty flags should not produce a header
        let projection = IdentityProjection::new(&identity, Some(&flags), None);
        let headers = inject_headers(&projection);
        let keys: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"x-forgeguard-features"));
    }

    #[test]
    fn with_resolved_flags_non_empty() {
        let identity = make_identity(None, &[]);
        let flags: ResolvedFlags = serde_json::from_str(r#"{"flags":{"beta":true}}"#).unwrap();
        // Non-empty flags should produce a header
        let projection = IdentityProjection::new(&identity, Some(&flags), None);
        let headers = inject_headers(&projection);
        let keys: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"x-forgeguard-features"));
    }
}
