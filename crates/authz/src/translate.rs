//! Translation between `forgeguard_authz_core` types and AWS Verified Permissions SDK types.

use aws_sdk_verifiedpermissions::types::{ActionIdentifier, Decision, EntityIdentifier};
use forgeguard_authz_core::{DenyReason, PolicyDecision, PolicyQuery};
use forgeguard_core::{PrincipalRef, ProjectId, TenantId};

use crate::error::{Error, Result};

/// Translated components for an `IsAuthorized` API call.
///
/// We expose the individual fields rather than the SDK's fluent builder
/// so the caller can apply them to the client's `is_authorized()` call.
pub(crate) struct VpRequestComponents {
    /// The Cedar principal entity.
    pub(crate) principal: EntityIdentifier,
    /// The Cedar action entity.
    pub(crate) action: ActionIdentifier,
    /// The Cedar resource entity, if the query includes a resource.
    pub(crate) resource: Option<EntityIdentifier>,
}

/// Build VP request components from a [`PolicyQuery`].
///
/// Maps:
/// - principal -> entity type `"iam::user"` + entity ID from `PrincipalRef::to_fgrn()`
/// - action -> `QualifiedAction::vp_action_type()` + `vp_action_id()`
/// - resource -> `cedar_entity_type()` + `ResourceRef::to_fgrn()` (if present)
pub(crate) fn build_vp_request(
    query: &PolicyQuery,
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<VpRequestComponents> {
    let principal_fgrn = query.principal().to_fgrn(project, tenant);
    let principal = EntityIdentifier::builder()
        .entity_type(PrincipalRef::vp_entity_type())
        .entity_id(principal_fgrn.as_vp_entity_id())
        .build()
        .map_err(|e| Error::VerifiedPermissions(format!("building principal entity: {e}")))?;

    let action = ActionIdentifier::builder()
        .action_type(query.action().vp_action_type())
        .action_id(query.action().vp_action_id())
        .build()
        .map_err(|e| Error::VerifiedPermissions(format!("building action identifier: {e}")))?;

    let resource = match query.resource() {
        Some(r) => {
            let resource_fgrn = r.to_fgrn(project, tenant);
            let entity = EntityIdentifier::builder()
                .entity_type(r.vp_entity_type())
                .entity_id(resource_fgrn.as_vp_entity_id())
                .build()
                .map_err(|e| {
                    Error::VerifiedPermissions(format!("building resource entity: {e}"))
                })?;
            Some(entity)
        }
        None => None,
    };

    Ok(VpRequestComponents {
        principal,
        action,
        resource,
    })
}

/// Translate a VP `Decision` into a [`PolicyDecision`].
///
/// VP ALLOW -> `PolicyDecision::Allow`.
/// VP DENY (or unknown) -> `PolicyDecision::Deny { reason: NoMatchingPolicy }`.
pub(crate) fn translate_vp_decision(decision: &Decision) -> PolicyDecision {
    match decision {
        Decision::Allow => PolicyDecision::Allow,
        _ => PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_authz_core::PolicyContext;
    use forgeguard_core::{QualifiedAction, ResourceId, ResourceRef, UserId};

    use super::*;

    fn test_project() -> ProjectId {
        ProjectId::new("acme-app").unwrap()
    }

    fn test_tenant() -> TenantId {
        TenantId::new("acme-corp").unwrap()
    }

    fn make_query_without_resource() -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:read:list").unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    fn make_query_with_resource() -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:read:list").unwrap();
        let resource_id = ResourceId::parse("list-001").unwrap();
        let resource = ResourceRef::from_route(&action, resource_id);
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, Some(resource), context)
    }

    #[test]
    fn build_request_without_resource() {
        let query = make_query_without_resource();
        let components = build_vp_request(&query, &test_project(), &test_tenant()).unwrap();

        assert_eq!(components.principal.entity_type(), "iam::user");
        assert_eq!(
            components.principal.entity_id(),
            "fgrn:acme-app:acme-corp:iam:user:alice"
        );
        assert_eq!(components.action.action_type(), "todo::action");
        assert_eq!(components.action.action_id(), "read-list");
        assert!(components.resource.is_none());
    }

    #[test]
    fn build_request_with_resource() {
        let query = make_query_with_resource();
        let components = build_vp_request(&query, &test_project(), &test_tenant()).unwrap();

        let resource = components.resource.unwrap();
        assert_eq!(resource.entity_type(), "todo::list");
        assert_eq!(
            resource.entity_id(),
            "fgrn:acme-app:acme-corp:todo:list:list-001"
        );
    }

    #[test]
    fn translate_allow() {
        let decision = translate_vp_decision(&Decision::Allow);
        assert!(decision.is_allowed());
    }

    #[test]
    fn translate_deny() {
        let decision = translate_vp_decision(&Decision::Deny);
        assert!(decision.is_denied());
    }
}
