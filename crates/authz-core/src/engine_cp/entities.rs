//! Local-Cedar port of the VP inline-entity shapes from
//! `crates/authz/src/translate.rs::build_vp_entities`. Same ids, same
//! attrs, same parent wiring — only the target types change
//! (`cedar_policy::Entities` instead of the AWS VP SDK).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use forgeguard_core::{
    GroupName, PrincipalKind, PrincipalRef, ProjectId, QualifiedAction, ResourceOrgSource,
    ResourceRef, TenantId,
};

fn uid(entity_type: &str, id: &str) -> std::result::Result<EntityUid, String> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| format!("bad entity type {entity_type}: {e}"))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

fn org_id_attr(value: &str) -> HashMap<String, RestrictedExpression> {
    HashMap::from([(
        "org_id".to_owned(),
        RestrictedExpression::new_string(value.to_owned()),
    )])
}

pub(crate) fn build_cp_entities(
    principal: &PrincipalRef,
    groups: &[GroupName],
    resource: Option<&ResourceRef>,
    project: &ProjectId,
    tenant: &TenantId,
) -> std::result::Result<Entities, String> {
    let mut entities: Vec<Entity> = Vec::new();
    let principal_fgrn = principal.to_fgrn(project, tenant);
    let principal_uid = uid(
        &principal.vp_entity_type(project),
        principal_fgrn.as_vp_entity_id(),
    )?;

    match principal.kind() {
        PrincipalKind::Machine => {
            entities.push(
                Entity::new(principal_uid, org_id_attr(tenant.as_str()), HashSet::new())
                    .map_err(|e| format!("machine entity: {e}"))?,
            );
        }
        PrincipalKind::User => {
            let group_type = PrincipalRef::vp_group_entity_type(project);
            let mut parents = HashSet::new();
            for group in groups {
                // Bare group name, not FGRN — matches compiled RBAC policies,
                // which are tenant-independent (translate.rs L123-124).
                let group_uid = uid(&group_type, group.as_str())?;
                parents.insert(group_uid.clone());
                entities.push(
                    Entity::new(group_uid, HashMap::new(), HashSet::new())
                        .map_err(|e| format!("group entity: {e}"))?,
                );
            }
            entities.push(
                Entity::new(principal_uid, org_id_attr(tenant.as_str()), parents)
                    .map_err(|e| format!("user entity: {e}"))?,
            );
        }
    }

    if let Some(res) = resource {
        let res_fgrn = res.to_fgrn(project, tenant);
        let org_id = match res.org_source() {
            ResourceOrgSource::OwnId => res.id().as_str(),
            ResourceOrgSource::RequestTenant => tenant.as_str(),
        };
        entities.push(
            Entity::new(
                uid(&res.vp_entity_type(project), res_fgrn.as_vp_entity_id())?,
                org_id_attr(org_id),
                HashSet::new(),
            )
            .map_err(|e| format!("resource entity: {e}"))?,
        );
    }

    Entities::from_entities(entities, None).map_err(|e| format!("entities: {e}"))
}

pub(crate) fn build_cp_request(
    principal: &PrincipalRef,
    action: &QualifiedAction,
    resource: Option<&ResourceRef>,
    project: &ProjectId,
    tenant: &TenantId,
) -> std::result::Result<Request, String> {
    let principal_fgrn = principal.to_fgrn(project, tenant);
    let principal_uid = uid(
        &principal.vp_entity_type(project),
        principal_fgrn.as_vp_entity_id(),
    )?;
    let action_uid = uid(&action.vp_action_type(project), &action.vp_action_id())?;
    // Every cp:* route mapping (`cp_route_actions` in control-plane/src/app.rs)
    // attaches a concrete resource id (`with_default_resource_id("collection")`
    // or `with_org_resource()`), so `resource` is never actually `None` for a
    // real request; translate.rs's VP path likewise omits the resource entity
    // entirely rather than fabricating one when it is absent. Fail closed
    // instead of guessing at an entity shape nothing produces.
    let Some(res) = resource else {
        return Err("cp:* queries always carry a resource".to_owned());
    };
    let res_fgrn = res.to_fgrn(project, tenant);
    let resource_uid = uid(&res.vp_entity_type(project), res_fgrn.as_vp_entity_id())?;
    Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        Context::empty(),
        None,
    )
    .map_err(|e| format!("request: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use forgeguard_core::{
        GroupName, PrincipalRef, ProjectId, QualifiedAction, ResourceId, ResourceRef, TenantId,
        UserId,
    };

    fn fixtures() -> (ProjectId, TenantId) {
        ("forgeguard".parse().unwrap(), "org-1".parse().unwrap())
    }

    #[test]
    fn user_entity_has_group_parents_and_org_id() {
        let (project, tenant) = fixtures();
        let principal = PrincipalRef::new("user-1".parse::<UserId>().unwrap());
        let groups = vec!["member".parse::<GroupName>().unwrap()];
        let entities = build_cp_entities(&principal, &groups, None, &project, &tenant).unwrap();
        let json = entities.to_json_value().unwrap();
        let list = json.as_array().unwrap();
        let user = list
            .iter()
            .find(|e| e["uid"]["type"].as_str().unwrap().ends_with("::User"))
            .unwrap();
        assert_eq!(user["attrs"]["org_id"], "org-1");
        assert_eq!(user["parents"][0]["id"], "member");
        assert!(list
            .iter()
            .any(|e| e["uid"]["type"].as_str().unwrap().ends_with("::Group")
                && e["uid"]["id"] == "member"));
    }

    #[test]
    fn machine_entity_has_org_id_and_no_parents() {
        let (project, tenant) = fixtures();
        let principal = PrincipalRef::machine("proxy-1".parse::<UserId>().unwrap());
        let entities = build_cp_entities(&principal, &[], None, &project, &tenant).unwrap();
        let json = entities.to_json_value().unwrap();
        let machine = json.as_array().unwrap()[0].clone();
        assert!(machine["uid"]["type"]
            .as_str()
            .unwrap()
            .ends_with("::Machine"));
        assert_eq!(machine["attrs"]["org_id"], "org-1");
        assert_eq!(machine["parents"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn resource_org_id_follows_org_source() {
        let (project, tenant) = fixtures();
        let principal = PrincipalRef::new("user-1".parse::<UserId>().unwrap());
        let action = QualifiedAction::parse("cp:organization:read").unwrap();
        // RequestTenant (default): org_id = request tenant
        let res = ResourceRef::from_route(&action, ResourceId::parse("org-1").unwrap());
        let entities = build_cp_entities(&principal, &[], Some(&res), &project, &tenant).unwrap();
        let json = entities.to_json_value().unwrap();
        let resource = json
            .as_array()
            .unwrap()
            .iter()
            .find(|e| {
                e["uid"]["type"]
                    .as_str()
                    .unwrap()
                    .ends_with("::cp__organization")
            })
            .unwrap();
        assert_eq!(resource["attrs"]["org_id"], "org-1");
        // OwnId: org_id = the resource's own id
        let res_own = ResourceRef::from_route(&action, ResourceId::parse("org-2").unwrap())
            .scoped_by_own_id();
        let entities =
            build_cp_entities(&principal, &[], Some(&res_own), &project, &tenant).unwrap();
        let json = entities.to_json_value().unwrap();
        let resource = json
            .as_array()
            .unwrap()
            .iter()
            .find(|e| {
                e["uid"]["type"]
                    .as_str()
                    .unwrap()
                    .ends_with("::cp__organization")
            })
            .unwrap();
        assert_eq!(resource["attrs"]["org_id"], "org-2");
    }

    #[test]
    fn request_uses_vp_action_id() {
        let (project, tenant) = fixtures();
        let principal = PrincipalRef::new("user-1".parse::<UserId>().unwrap());
        let action = QualifiedAction::parse("cp:organization:read").unwrap();
        let resource = ResourceRef::from_route(&action, ResourceId::parse("collection").unwrap());
        let req =
            build_cp_request(&principal, &action, Some(&resource), &project, &tenant).unwrap();
        assert!(format!("{req:?}").contains("cp-organization-read"));
    }
}
