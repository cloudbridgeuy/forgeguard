//! Translation between `forgeguard_authz_core` types and AWS Verified Permissions SDK types.

use aws_sdk_verifiedpermissions::types::{
    ActionIdentifier, AttributeValue, Decision, EntitiesDefinition, EntityIdentifier, EntityItem,
};
use forgeguard_authz_core::{DenyReason, PolicyDecision, PolicyQuery};
use forgeguard_core::{GroupName, PrincipalKind, PrincipalRef, ProjectId, ResourceRef, TenantId};

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
/// - principal -> entity type from `PrincipalRef::vp_entity_type()` + entity ID from `PrincipalRef::to_fgrn()`
/// - action -> `QualifiedAction::vp_action_type(project)` + `vp_action_id()`
/// - resource -> `ResourceRef::vp_entity_type(project)` + `ResourceRef::to_fgrn()` (if present)
pub(crate) fn build_vp_request(
    query: &PolicyQuery,
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<VpRequestComponents> {
    let principal_fgrn = query.principal().to_fgrn(project, tenant);
    let principal = EntityIdentifier::builder()
        .entity_type(query.principal().vp_entity_type(project))
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
/// For **User** principals:
/// - A user entity (`{vp_ns}::User`) with `org_id` attribute and `parents` pointing to group entities
/// - One group entity (`{vp_ns}::Group`) per group, with no parents or attributes
///
/// For **Machine** principals:
/// - A single machine entity (`{vp_ns}::Machine`) with an `org_id` string attribute
///   set to the tenant ID value; no group parents.
///
/// When a **resource** is present, a resource entity is added with an `org_id`
/// attribute matching the tenant. This is required for Cedar policies that
/// scope access via `resource.org_id == principal.org_id`.
///
/// VP has no entity store (design decision D5), so we pass entities inline
/// at query time.
pub(crate) fn build_vp_entities(
    principal: &PrincipalRef,
    groups: &[GroupName],
    resource: Option<&ResourceRef>,
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<EntitiesDefinition> {
    let principal_fgrn = principal.to_fgrn(project, tenant);

    let mut entities: Vec<EntityItem> = match principal.kind() {
        PrincipalKind::Machine => {
            // Machine entity: org_id attribute = tenant_id, no group parents.
            let machine_entity = EntityItem::builder()
                .identifier(
                    EntityIdentifier::builder()
                        .entity_type(principal.vp_entity_type(project))
                        .entity_id(principal_fgrn.as_vp_entity_id())
                        .build()
                        .map_err(|e| {
                            Error::VerifiedPermissions(format!(
                                "building machine entity identifier: {e}"
                            ))
                        })?,
                )
                .attributes(
                    "org_id",
                    AttributeValue::String(tenant.as_str().to_string()),
                )
                .build();

            vec![machine_entity]
        }
        PrincipalKind::User => {
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

            // Build the user entity with parents pointing to groups and org_id attribute.
            let mut user_builder = EntityItem::builder()
                .identifier(
                    EntityIdentifier::builder()
                        .entity_type(principal.vp_entity_type(project))
                        .entity_id(principal_fgrn.as_vp_entity_id())
                        .build()
                        .map_err(|e| {
                            Error::VerifiedPermissions(format!(
                                "building user entity identifier: {e}"
                            ))
                        })?,
                )
                .attributes(
                    "org_id",
                    AttributeValue::String(tenant.as_str().to_string()),
                );

            for parent in &group_identifiers {
                user_builder = user_builder.parents(parent.clone());
            }

            let user_entity = user_builder.build();

            // Build group entities (no parents, no attributes) and chain after the user entity.
            let group_entities = group_identifiers
                .iter()
                .map(|id| EntityItem::builder().identifier(id.clone()).build());

            std::iter::once(user_entity).chain(group_entities).collect()
        }
    };

    // Add resource entity with org_id attribute for tenant-scoped policies.
    if let Some(res) = resource {
        let resource_entity = EntityItem::builder()
            .identifier(
                EntityIdentifier::builder()
                    .entity_type(res.vp_entity_type(project))
                    .entity_id(res.id().as_str())
                    .build()
                    .map_err(|e| {
                        Error::VerifiedPermissions(format!(
                            "building resource entity identifier: {e}"
                        ))
                    })?,
            )
            .attributes(
                "org_id",
                AttributeValue::String(tenant.as_str().to_string()),
            )
            .build();
        entities.push(resource_entity);
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

        assert_eq!(components.principal.entity_type(), "acme_app::User");
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

    // -- build_vp_request machine entity type --------------------------------

    #[test]
    fn build_vp_request_machine_entity_type() {
        let principal = PrincipalRef::machine(UserId::new("svc-worker").unwrap());
        let action = QualifiedAction::parse("todo:list:read").unwrap();
        let context = PolicyContext::new();
        let query = PolicyQuery::new(principal, action, None, context);

        let components = build_vp_request(&query, &test_project(), &test_tenant()).unwrap();

        assert_eq!(components.principal.entity_type(), "acme_app::Machine");
    }

    // -- build_vp_entities ---------------------------------------------------

    #[test]
    fn entities_user_with_no_groups() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let entities =
            build_vp_entities(&principal, &[], None, &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                // Only the user entity, no group entities.
                assert_eq!(items.len(), 1);
                let user_item = &items[0];
                let ident = user_item.identifier().expect("identifier set");
                assert_eq!(ident.entity_type(), "acme_app::User");
                assert_eq!(ident.entity_id(), "fgrn:acme-app:acme-corp:iam:user:alice");
                assert!(user_item.parents().is_empty());

                // User entity carries org_id attribute.
                let attrs = user_item.attributes().expect("attributes set");
                let org_id = attrs.get("org_id").expect("org_id attribute present");
                assert_eq!(
                    org_id.as_string().expect("org_id is a String value"),
                    "acme-corp"
                );
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
            build_vp_entities(&principal, &groups, None, &test_project(), &test_tenant()).unwrap();

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
                assert!(parent_types.iter().all(|t| *t == "acme_app::Group"));

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
            build_vp_entities(&principal, &groups, None, &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                assert_eq!(items.len(), 2);

                // Group entity ID matches the group name (not FGRN).
                let group_ident = items[1].identifier().expect("identifier set");
                assert_eq!(group_ident.entity_type(), "acme_app::Group");
                assert_eq!(group_ident.entity_id(), "editor");

                // User's parent matches the group entity.
                let user_parent = &items[0].parents()[0];
                assert_eq!(user_parent.entity_id(), "editor");
            }
            _ => panic!("expected EntityList variant"),
        }
    }

    #[test]
    fn build_vp_entities_machine_has_org_id_attribute() {
        let principal = PrincipalRef::machine(UserId::new("svc-worker").unwrap());
        let entities =
            build_vp_entities(&principal, &[], None, &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                assert_eq!(items.len(), 1);
                let machine = &items[0];
                let ident = machine.identifier().expect("identifier set");
                assert_eq!(ident.entity_type(), "acme_app::Machine");

                let attrs = machine.attributes().expect("attributes set");
                let org_id = attrs.get("org_id").expect("org_id attribute present");
                assert_eq!(
                    org_id.as_string().expect("org_id is a String value"),
                    "acme-corp"
                );
            }
            _ => panic!("expected EntityList variant"),
        }
    }

    #[test]
    fn build_vp_entities_machine_no_group_parents() {
        let principal = PrincipalRef::machine(UserId::new("svc-worker").unwrap());
        // Even if groups are passed they should be ignored for Machine principals.
        let groups = vec![GroupName::new("admin").unwrap()];
        let entities =
            build_vp_entities(&principal, &groups, None, &test_project(), &test_tenant()).unwrap();

        match &entities {
            EntitiesDefinition::EntityList(items) => {
                // Only the machine entity — no group entities.
                assert_eq!(items.len(), 1);
                assert!(items[0].parents().is_empty());
            }
            _ => panic!("expected EntityList variant"),
        }
    }
}
