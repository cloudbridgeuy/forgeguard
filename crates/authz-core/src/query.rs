//! Protocol-agnostic authorization query.

use forgeguard_core::{PrincipalRef, QualifiedAction, ResourceRef};

use crate::context::PolicyContext;

/// A fully-typed authorization query.
///
/// "Can principal P perform action A on resource R given context C?"
///
/// All fields are typed — no raw strings. Constructed from `forgeguard_core`
/// types that carry their own validation proof.
pub struct PolicyQuery {
    principal: PrincipalRef,
    action: QualifiedAction,
    resource: Option<ResourceRef>,
    context: PolicyContext,
}

impl PolicyQuery {
    /// Construct a new policy query.
    pub fn new(
        principal: PrincipalRef,
        action: QualifiedAction,
        resource: Option<ResourceRef>,
        context: PolicyContext,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
        }
    }

    /// Borrow the principal.
    pub fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    /// Borrow the action.
    pub fn action(&self) -> &QualifiedAction {
        &self.action
    }

    /// Borrow the resource, if present.
    pub fn resource(&self) -> Option<&ResourceRef> {
        self.resource.as_ref()
    }

    /// Borrow the context.
    pub fn context(&self) -> &PolicyContext {
        &self.context
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{PrincipalRef, QualifiedAction, ResourceId, ResourceRef, UserId};

    use super::*;

    #[test]
    fn construct_query_without_resource() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:read:list").unwrap();
        let context = PolicyContext::new();

        let query = PolicyQuery::new(principal, action, None, context);

        assert_eq!(PrincipalRef::vp_entity_type(), "iam::user");
        assert_eq!(query.action().to_string(), "todo:read:list");
        assert!(query.resource().is_none());
    }

    #[test]
    fn construct_query_with_resource() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:read:list").unwrap();
        let resource_id = ResourceId::parse("my-list").unwrap();
        let resource = ResourceRef::from_route(&action, resource_id);
        let context = PolicyContext::new();

        let query = PolicyQuery::new(principal, action, Some(resource), context);

        assert!(query.resource().is_some());
    }

    #[test]
    fn construct_query_with_context() {
        use forgeguard_core::{GroupName, TenantId};

        let principal = PrincipalRef::new(UserId::new("bob").unwrap());
        let action = QualifiedAction::parse("admin:write:user").unwrap();
        let context = PolicyContext::new()
            .with_tenant(TenantId::new("acme-corp").unwrap())
            .with_groups(vec![GroupName::new("admin").unwrap()])
            .with_ip_address("192.168.1.1".parse().unwrap())
            .with_attribute("department", serde_json::json!("engineering"));

        let query = PolicyQuery::new(principal, action, None, context);

        assert_eq!(query.context().tenant_id().unwrap().as_str(), "acme-corp");
        assert_eq!(query.context().groups().len(), 1);
        assert_eq!(
            query.context().ip_address().unwrap().to_string(),
            "192.168.1.1"
        );
        assert_eq!(
            query.context().attributes().get("department"),
            Some(&serde_json::json!("engineering"))
        );
    }
}
