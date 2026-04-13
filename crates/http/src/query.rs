//! Authn→authz glue: build a `PolicyQuery` from HTTP-layer types.

use std::net::IpAddr;

use forgeguard_authn_core::Identity;
use forgeguard_authz_core::context::PolicyContext;
use forgeguard_authz_core::query::PolicyQuery;
use forgeguard_core::{PrincipalRef, ProjectId};

use crate::route::MatchedRoute;

/// Bridge identity + matched route into a policy query.
///
/// Pure function — no I/O. Constructs:
/// - `PrincipalRef` from `identity.user_id()`
/// - Action from `matched_route.action()`
/// - Resource from `matched_route.resource()`
/// - `PolicyContext` with tenant, groups, IP, and extra claims
pub fn build_query(
    identity: &Identity,
    matched_route: &MatchedRoute,
    _project_id: &ProjectId,
    client_ip: Option<IpAddr>,
) -> PolicyQuery {
    let principal = PrincipalRef::new(identity.user_id().clone());

    let mut context = PolicyContext::new().with_groups(identity.groups().to_vec());

    if let Some(tenant) = identity.tenant_id() {
        context = context.with_tenant(tenant.clone());
    }

    if let Some(ip) = client_ip {
        context = context.with_ip_address(ip);
    }

    if let Some(extra) = identity.extra() {
        context = context.with_attribute("extra_claims", extra.clone());
    }

    let resource = matched_route.resource().cloned();

    PolicyQuery::new(principal, matched_route.action().clone(), resource, context)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{GroupName, ProjectId, QualifiedAction, TenantId, UserId};

    use crate::method::HttpMethod;
    use crate::route::{RouteMapping, RouteMatcher};
    use forgeguard_authn_core::IdentityParams;

    use super::*;

    fn make_identity(tenant: Option<&str>, groups: &[&str]) -> Identity {
        Identity::new(IdentityParams {
            user_id: UserId::new("alice").unwrap(),
            tenant_id: tenant.map(|t| TenantId::new(t).unwrap()),
            groups: groups.iter().map(|g| GroupName::new(*g).unwrap()).collect(),
            expiry: None,
            resolver: "jwt",
            extra: None,
        })
    }

    #[test]
    fn build_query_basic() {
        let routes = vec![RouteMapping::new(
            HttpMethod::Get,
            "/users".to_string(),
            QualifiedAction::parse("todo:list:user").unwrap(),
            None,
            None,
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let matched = matcher.match_request("GET", "/users").unwrap();
        let identity = make_identity(Some("acme-corp"), &["admin"]);
        let project = ProjectId::new("my-app").unwrap();

        let query = build_query(
            &identity,
            &matched,
            &project,
            Some("192.168.1.1".parse().unwrap()),
        );

        assert_eq!(query.action().to_string(), "todo:list:user");
        assert_eq!(query.context().tenant_id().unwrap().as_str(), "acme-corp");
        assert_eq!(query.context().groups().len(), 1);
        assert_eq!(
            query.context().ip_address().unwrap().to_string(),
            "192.168.1.1"
        );
    }

    #[test]
    fn build_query_no_tenant_no_ip() {
        let routes = vec![RouteMapping::new(
            HttpMethod::Get,
            "/items".to_string(),
            QualifiedAction::parse("todo:list:item").unwrap(),
            None,
            None,
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let matched = matcher.match_request("GET", "/items").unwrap();
        let identity = make_identity(None, &[]);
        let project = ProjectId::new("my-app").unwrap();

        let query = build_query(&identity, &matched, &project, None);

        assert!(query.context().tenant_id().is_none());
        assert!(query.context().ip_address().is_none());
        assert!(query.context().groups().is_empty());
    }

    #[test]
    fn build_query_with_extra_claims() {
        let identity = Identity::new(IdentityParams {
            user_id: UserId::new("alice").unwrap(),
            tenant_id: None,
            groups: vec![],
            expiry: None,
            resolver: "jwt",
            extra: Some(serde_json::json!({"role": "superadmin"})),
        });
        let routes = vec![RouteMapping::new(
            HttpMethod::Get,
            "/admin".to_string(),
            QualifiedAction::parse("admin:access:panel").unwrap(),
            None,
            None,
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let matched = matcher.match_request("GET", "/admin").unwrap();
        let project = ProjectId::new("my-app").unwrap();

        let query = build_query(&identity, &matched, &project, None);

        assert_eq!(
            query.context().attributes().get("extra_claims"),
            Some(&serde_json::json!({"role": "superadmin"}))
        );
    }
}
