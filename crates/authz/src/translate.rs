//! Translation between `forgeguard_authz_core` types and AWS Verified Permissions SDK types.

use aws_sdk_verifiedpermissions::types::{
    ActionIdentifier, Decision, EntitiesDefinition, EntityIdentifier, EntityItem,
};
use forgeguard_authz_core::{DenyReason, PolicyDecision, PolicyQuery};
use forgeguard_core::{GroupName, PrincipalRef, ProjectId, TenantId};

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
/// - principal -> entity type `"{vp_ns}::user"` + entity ID from `PrincipalRef::to_fgrn()`
/// - action -> `QualifiedAction::vp_action_type(project)` + `vp_action_id()`
/// - resource -> `ResourceRef::vp_entity_type(project)` + `ResourceRef::to_fgrn()` (if present)
pub(crate) fn build_vp_request(
    query: &PolicyQuery,
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<VpRequestComponents> {
    let principal_fgrn = query.principal().to_fgrn(project, tenant);
    let principal = EntityIdentifier::builder()
        .entity_type(PrincipalRef::vp_entity_type(project))
        .entity_id(principal_fgrn.as_vp_entity_id())
        .build()
        .map_err(|e| Error::VerifiedPermissions(format!("building principal entity: {e}")))?;

    let action = ActionIdentifier::builder()
        .action_type(query.action().vp_action_type(project))
        .action_id(query.action().vp_action_id())
        .build()
        .map_err(|e| Error::VerifiedPermissions(format!("building action identifier: {e}")))?;

    let resource = match query.resource() {
        Some(r) => {
            let entity = EntityIdentifier::builder()
                .entity_type(r.vp_entity_type(project))
                .entity_id(r.id().as_str())
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

/// Build inline VP entities for the `IsAuthorized` request.
///
/// Creates:
/// - A user entity (`{vp_ns}::user`) with `parents` pointing to group entities
/// - One group entity (`{vp_ns}::group`) per group, with no parents or attributes
///
/// VP has no entity store (design decision D5), so we pass entities inline
/// at query time.
pub(crate) fn build_vp_entities(
    principal: &PrincipalRef,
    groups: &[GroupName],
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<EntitiesDefinition> {
    let principal_fgrn = principal.to_fgrn(project, tenant);
    let group_type = PrincipalRef::vp_group_entity_type(project);

    // Build group entity identifiers using group name (not FGRN) to match
    // compiled Cedar policies which are tenant-independent.
    let group_identifiers: Vec<EntityIdentifier> = groups
        .iter()
        .map(|g| {
            EntityIdentifier::builder()
                .entity_type(group_type.as_str())
                .entity_id(g.as_str())
                .build()
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            Error::VerifiedPermissions(format!("building group entity identifier: {e}"))
        })?;

    // Build the user entity with parents pointing to groups.
    let mut user_builder = EntityItem::builder().identifier(
        EntityIdentifier::builder()
            .entity_type(PrincipalRef::vp_entity_type(project))
            .entity_id(principal_fgrn.as_vp_entity_id())
            .build()
            .map_err(|e| {
                Error::VerifiedPermissions(format!("building user entity identifier: {e}"))
            })?,
    );

    for parent in &group_identifiers {
        user_builder = user_builder.parents(parent.clone());
    }

    let user_entity = user_builder.build();

    let mut entities = vec![user_entity];

    // Build group entities (no parents, no attributes).
    for group_id in &group_identifiers {
        let group_entity = EntityItem::builder().identifier(group_id.clone()).build();
        entities.push(group_entity);
    }

    Ok(EntitiesDefinition::EntityList(entities))
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
    use forgeguard_core::{GroupName, QualifiedAction, ResourceId, ResourceRef, UserId};

    use super::*;

    fn test_project() -> ProjectId {
        ProjectId::new("acme-app").unwrap()
    }

    fn test_tenant() -> TenantId {
        TenantId::new("acme-corp").unwrap()
    }

    fn make_query_without_resource() -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:list:read").unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    fn make_query_with_resource() -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:list:read").unwrap();
        let resource_id = ResourceId::parse("list-001").unwrap();
        let resource = ResourceRef::from_route(&action, resource_id);
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, Some(resource), context)
    }

    #[test]
    fn build_request_without_resource() {
        let query = make_query_without_resource();
        let components = build_vp_request(&query, &test_project(), &test_tenant()).unwrap();

        assert_eq!(components.principal.entity_type(), "acme_app::user");
        assert_eq!(
            components.principal.entity_id(),
            "fgrn:acme-app:acme-corp:iam:user:alice"
        );
        assert_eq!(components.action.action_type(), "acme_app::Action");
        assert_eq!(components.action.action_id(), "todo-list-read");
        assert!(components.resource.is_none());
    }

    #[test]
    fn build_request_with_resource() {
        let query = make_query_with_resource();
        let components = build_vp_request(&query, &test_project(), &test_tenant()).unwrap();

        let resource = components.resource.unwrap();
        assert_eq!(resource.entity_type(), "acme_app::todo__list");
        assert_eq!(resource.entity_id(), "list-001");
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

    // -- build_vp_entities ---------------------------------------------------

    #[test]
    fn entities_user_with_no_groups() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let entities = build_vp_entities(&principal, &[], &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                // Only the user entity, no group entities.
                assert_eq!(items.len(), 1);
                let user_item = &items[0];
                let ident = user_item.identifier().expect("identifier set");
                assert_eq!(ident.entity_type(), "acme_app::user");
                assert_eq!(ident.entity_id(), "fgrn:acme-app:acme-corp:iam:user:alice");
                assert!(user_item.parents().is_empty());
            }
            _ => panic!("expected EntityList variant"),
        }
    }

    #[test]
    fn entities_user_with_groups() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let groups = vec![
            GroupName::new("admin").unwrap(),
            GroupName::new("viewer").unwrap(),
        ];
        let entities =
            build_vp_entities(&principal, &groups, &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                // 1 user + 2 group entities.
                assert_eq!(items.len(), 3);

                // User entity has 2 parents.
                let user_item = &items[0];
                assert_eq!(user_item.parents().len(), 2);
                let parent_types: Vec<&str> = user_item
                    .parents()
                    .iter()
                    .map(aws_sdk_verifiedpermissions::types::EntityIdentifier::entity_type)
                    .collect();
                assert!(parent_types.iter().all(|t| *t == "acme_app::group"));

                // Group entities have no parents.
                assert!(items[1].parents().is_empty());
                assert!(items[2].parents().is_empty());
            }
            _ => panic!("expected EntityList variant"),
        }
    }

    #[test]
    fn entities_single_group_has_correct_fgrn() {
        let principal = PrincipalRef::new(UserId::new("bob").unwrap());
        let groups = vec![GroupName::new("editor").unwrap()];
        let entities =
            build_vp_entities(&principal, &groups, &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                assert_eq!(items.len(), 2);

                // Group entity ID matches the group name (not FGRN).
                let group_ident = items[1].identifier().expect("identifier set");
                assert_eq!(group_ident.entity_type(), "acme_app::group");
                assert_eq!(group_ident.entity_id(), "editor");

                // User's parent matches the group entity.
                let user_parent = &items[0].parents()[0];
                assert_eq!(user_parent.entity_id(), "editor");
            }
            _ => panic!("expected EntityList variant"),
        }
    }
}
