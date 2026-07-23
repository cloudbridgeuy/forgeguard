//! CP `cp:*` conformance: the same questions the VP path answered,
//! evaluated against the embedded engine. Model text mirrors the
//! real forgeguard.toml role model.

use forgeguard_authz_core::{
    compile_cp_model, CpCedarEngine, PolicyContext, PolicyEngine, PolicyQuery, Snapshot,
};
use forgeguard_core::{
    PrincipalRef, ProjectId, QualifiedAction, ResourceId, ResourceRef, TenantId, UserId,
};

const MODEL: &str = include_str!("../../../forgeguard.toml");

#[allow(clippy::unwrap_used, clippy::expect_used)]
fn engine() -> CpCedarEngine {
    let text = compile_cp_model(MODEL).unwrap();
    let snapshot = Snapshot::from_policy_text(&text).unwrap();
    CpCedarEngine::new(snapshot, "forgeguard".parse::<ProjectId>().unwrap())
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
fn query(user: &str, groups: &[&str], action: &str) -> PolicyQuery {
    let action = QualifiedAction::parse(action).unwrap();
    let resource = ResourceRef::from_route(&action, ResourceId::parse("collection").unwrap());
    let ctx = PolicyContext::new()
        .with_tenant("org-1".parse::<TenantId>().unwrap())
        .with_groups(groups.iter().map(|g| g.parse().unwrap()).collect());
    PolicyQuery::new(
        PrincipalRef::new(user.parse::<UserId>().unwrap()),
        action,
        Some(resource),
        ctx,
    )
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn member_can_read_organization() {
    let d = engine()
        .evaluate(&query("u1", &["member"], "cp:organization:read"))
        .await
        .unwrap();
    assert!(d.decision().is_allowed());
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn member_cannot_create_group() {
    let d = engine()
        .evaluate(&query("u1", &["member"], "cp:group:create"))
        .await
        .unwrap();
    assert!(d.is_denied());
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn admin_inherits_member_reads() {
    let d = engine()
        .evaluate(&query("u1", &["admin"], "cp:organization:read"))
        .await
        .unwrap();
    assert!(d.decision().is_allowed());
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn owner_inherits_admin_writes() {
    let d = engine()
        .evaluate(&query("u1", &["owner"], "cp:group:create"))
        .await
        .unwrap();
    assert!(d.decision().is_allowed());
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn no_groups_is_denied() {
    let d = engine()
        .evaluate(&query("u1", &[], "cp:organization:read"))
        .await
        .unwrap();
    assert!(d.is_denied());
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn missing_tenant_is_denied_not_error() {
    let action = QualifiedAction::parse("cp:organization:read").unwrap();
    let resource = ResourceRef::from_route(&action, ResourceId::parse("collection").unwrap());
    let q = PolicyQuery::new(
        PrincipalRef::new("u1".parse::<UserId>().unwrap()),
        action,
        Some(resource),
        PolicyContext::new(), // no tenant, no groups
    );
    let d = engine().evaluate(&q).await.unwrap();
    assert!(d.is_denied());
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn machine_can_read_proxy_config_same_org_only() {
    // Exercise the machine-principal cedar policies from forgeguard.toml:
    // `machine-proxy-config-read` permits Machine principals to read
    // cp-proxy-config-read on their own org's resource.
    let action = QualifiedAction::parse("cp:proxy-config:read").unwrap();
    let same_org = PolicyQuery::new(
        PrincipalRef::machine("proxy-1".parse().unwrap()),
        action.clone(),
        Some(
            ResourceRef::from_route(&action, ResourceId::parse("org-1").unwrap())
                .scoped_by_own_id(),
        ),
        PolicyContext::new().with_tenant("org-1".parse::<TenantId>().unwrap()),
    );
    assert!(engine()
        .evaluate(&same_org)
        .await
        .unwrap()
        .decision()
        .is_allowed());

    let cross_org = PolicyQuery::new(
        PrincipalRef::machine("proxy-1".parse().unwrap()),
        action.clone(),
        Some(
            ResourceRef::from_route(&action, ResourceId::parse("org-2").unwrap())
                .scoped_by_own_id(),
        ),
        PolicyContext::new().with_tenant("org-1".parse::<TenantId>().unwrap()),
    );
    assert!(engine().evaluate(&cross_org).await.unwrap().is_denied());
}
