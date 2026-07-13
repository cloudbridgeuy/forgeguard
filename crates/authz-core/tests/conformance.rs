//! Conformance harness: loads JSON fixtures from `conformance/engine/`,
//! builds a `MemoryStore` from each, and asserts every case's expected
//! decision. See `conformance/engine/README.md` for the fixture format.

use std::collections::HashMap;
use std::path::Path;

use forgeguard_authz_core::{
    AuthzStore, CedarEngine, DecisionQuery, MemoryStore, ModelState, Snapshot, StoreWrite,
};
use forgeguard_core::{
    share, AnchoredResource, Fgrn, NativeId, OrgUnit, Principal, Segment, ShareRequest, Spine, Verb,
};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    name: String,
    #[allow(dead_code)]
    description: String,
    organization: String,
    spine: Vec<SpineNode>,
    principals: Vec<PrincipalFixture>,
    #[serde(default)]
    principal_sets: Vec<PrincipalSetFixture>,
    #[serde(default)]
    grants: Vec<GrantFixture>,
    #[serde(default)]
    promotions: Vec<PromotionFixture>,
    policies: String,
    cases: Vec<CaseFixture>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SpineNode {
    id: String,
    parent: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalFixture {
    id: String,
    kind: String,
    anchor: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalSetFixture {
    id: String,
    anchor: String,
    #[serde(default)]
    members: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantFixture {
    resource_type: String,
    resource_id: String,
    to: String,
    actions: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionFixture {
    resource_type: String,
    resource_id: String,
    anchor: String,
    to: String,
    actions: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseFixture {
    name: String,
    principal: String,
    action: String,
    resource_type: String,
    resource_id: String,
    #[serde(default)]
    chain: Vec<String>,
    expect: String,
}

/// Load every fixture under `conformance/engine/*.json`.
fn load_fixtures() -> Vec<Fixture> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/engine");
    let mut fixtures = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("conformance/engine must exist") {
        let entry = entry.expect("readable dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("readable fixture file");
        let fixture: Fixture =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        fixtures.push(fixture);
    }
    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    fixtures
}

/// Resolve `id` against the given lookup maps in order, falling back to
/// `fallback` if none contain it. Backs the fixture id-resolution helpers
/// below, which each check a different combination of maps.
fn resolve_or(maps: &[&HashMap<String, Fgrn>], id: &str, fallback: impl Fn() -> Fgrn) -> Fgrn {
    maps.iter()
        .find_map(|map| map.get(id).cloned())
        .unwrap_or_else(fallback)
}

/// Build the `MemoryStore` a fixture describes, plus a lookup from fixture
/// id to the corresponding `Fgrn` for principals and resources.
async fn build_store(
    fixture: &Fixture,
) -> (MemoryStore, HashMap<String, Fgrn>, HashMap<String, Fgrn>) {
    let org = Segment::try_new(&fixture.organization).expect("valid organization segment");
    let nid = |s: &str| NativeId::try_new(s).expect("valid native id");
    let org_unit_or = |map: &HashMap<String, Fgrn>, id: &str| {
        resolve_or(&[map], id, || Fgrn::org_unit(&org, &nid(id)))
    };
    let principal_or = |map: &HashMap<String, Fgrn>, id: &str| {
        resolve_or(&[map], id, || Fgrn::principal(&org, &nid(id)))
    };
    // A promotion anchor may be an org unit or a principal — check org
    // units first (spine ids are known upfront), then principals, falling
    // back to a bare org-unit FGRN.
    let anchor_or =
        |org_units: &HashMap<String, Fgrn>, principals: &HashMap<String, Fgrn>, id: &str| {
            resolve_or(&[org_units, principals], id, || {
                Fgrn::org_unit(&org, &nid(id))
            })
        };
    // Grantees may be a principal or a principal set — check the principal
    // map first, then sets, falling back to a bare principal FGRN.
    let grantee_or =
        |principals: &HashMap<String, Fgrn>, sets: &HashMap<String, Fgrn>, id: &str| {
            resolve_or(&[principals, sets], id, || Fgrn::principal(&org, &nid(id)))
        };

    let mut org_units = Vec::new();
    let mut org_unit_fgrns = HashMap::new();
    for node in &fixture.spine {
        let fgrn = Fgrn::org_unit(&org, &nid(&node.id));
        let parent = node
            .parent
            .as_ref()
            .map(|p| org_unit_or(&org_unit_fgrns, p));
        org_units.push(OrgUnit::try_new(fgrn.clone(), parent).expect("valid org unit"));
        org_unit_fgrns.insert(node.id.clone(), fgrn);
    }
    let spine = Spine::try_new(org_units).expect("valid spine");

    let store = MemoryStore::new(ModelState::new(spine));

    let mut principal_fgrns = HashMap::new();
    for p in &fixture.principals {
        let fgrn = Fgrn::principal(&org, &nid(&p.id));
        let kind = p.kind.parse().expect("valid principal kind");
        let anchor = org_unit_or(&org_unit_fgrns, &p.anchor);
        let principal = Principal::try_new(fgrn.clone(), kind, anchor).expect("valid principal");
        store
            .apply(StoreWrite::PutPrincipal(principal))
            .await
            .expect("PutPrincipal applies");
        principal_fgrns.insert(p.id.clone(), fgrn);
    }

    let mut set_fgrns = HashMap::new();
    for set in &fixture.principal_sets {
        let fgrn = Fgrn::principal_set(&org, &nid(&set.id));
        let anchor = org_unit_or(&org_unit_fgrns, &set.anchor);
        let mut principal_set = forgeguard_core::PrincipalSet::try_new(fgrn.clone(), anchor)
            .expect("valid principal set");
        for member in &set.members {
            let member_fgrn = principal_or(&principal_fgrns, member);
            principal_set
                .add_member(member_fgrn)
                .expect("valid set member");
        }
        store
            .apply(StoreWrite::PutPrincipalSet(principal_set))
            .await
            .expect("PutPrincipalSet applies");
        set_fgrns.insert(set.id.clone(), fgrn);
    }

    let mut resource_fgrns = HashMap::new();
    for promo in &fixture.promotions {
        let anchor = anchor_or(&org_unit_fgrns, &principal_fgrns, &promo.anchor);
        let to = grantee_or(&principal_fgrns, &set_fgrns, &promo.to);
        let actions = promo
            .actions
            .iter()
            .map(|a| Verb::try_new(a.clone()).expect("valid verb"))
            .collect();
        let (promoted, grant) = share(ShareRequest {
            resource: AnchoredResource::try_new(
                Segment::try_new(&promo.resource_type).expect("valid resource type"),
                anchor,
            )
            .expect("valid anchored resource"),
            native_id: nid(&promo.resource_id),
            to,
            actions,
        })
        .expect("valid share");
        resource_fgrns.insert(
            format!("{}/{}", promo.resource_type, promo.resource_id),
            promoted.fgrn().clone(),
        );
        store
            .apply(StoreWrite::PutPromotion(promoted))
            .await
            .expect("PutPromotion applies");
        store
            .apply(StoreWrite::PutGrant(grant))
            .await
            .expect("PutGrant applies");
    }

    for grant in &fixture.grants {
        let resource = resource_fgrns
            .get(&format!("{}/{}", grant.resource_type, grant.resource_id))
            .cloned()
            .unwrap_or_else(|| {
                Fgrn::resource(
                    &org,
                    &Segment::try_new(&grant.resource_type).expect("valid resource type"),
                    &nid(&grant.resource_id),
                )
            });
        let to = grantee_or(&principal_fgrns, &set_fgrns, &grant.to);
        let actions = grant
            .actions
            .iter()
            .map(|a| Verb::try_new(a.clone()).expect("valid verb"))
            .collect();
        let g = forgeguard_core::Grant::try_new(resource, actions, to).expect("valid grant");
        store
            .apply(StoreWrite::PutGrant(g))
            .await
            .expect("PutGrant applies");
    }

    (store, principal_fgrns, resource_fgrns)
}

#[tokio::test]
async fn conformance() {
    let fixtures = load_fixtures();
    assert!(!fixtures.is_empty(), "expected at least one fixture");

    for fixture in &fixtures {
        let (store, principal_fgrns, resource_fgrns) = build_store(fixture).await;
        let engine = CedarEngine::new(
            Snapshot::from_policy_text(&fixture.policies).expect("valid snapshot policy text"),
        );

        for case in &fixture.cases {
            let resolve_principal = |id: &str, context: &str| -> Fgrn {
                principal_fgrns
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| panic!("unknown principal in {context}: {id}"))
            };
            let principal = resolve_principal(&case.principal, "case");
            let resource_key = format!("{}/{}", case.resource_type, case.resource_id);
            let resource = resource_fgrns
                .get(&resource_key)
                .unwrap_or_else(|| panic!("unknown resource in case: {resource_key}"));
            let action = Verb::try_new(case.action.clone()).expect("valid verb");

            let mut query = DecisionQuery::new(principal.clone(), action, resource.clone());
            if !case.chain.is_empty() {
                assert_eq!(
                    case.chain.first().map(String::as_str),
                    Some(case.principal.as_str()),
                    "{}/{}: chain[0] must equal the case principal",
                    fixture.name,
                    case.name
                );
                let links = case
                    .chain
                    .iter()
                    .map(|id| resolve_principal(id, "chain"))
                    .collect();
                let chain = forgeguard_core::DelegationChain::try_new(links)
                    .expect("valid delegation chain");
                query = query
                    .with_chain(chain)
                    .expect("chain actor matches principal");
            }

            let record = engine
                .decide(&store, &query)
                .await
                .unwrap_or_else(|e| panic!("{}/{}: {e}", fixture.name, case.name));

            let verdict = if record.is_allow() { "allow" } else { "deny" };
            println!("[{}] {} -> {verdict}", fixture.name, case.name);

            assert_eq!(
                verdict, case.expect,
                "{}/{}: expected {}, got {verdict}",
                fixture.name, case.name, case.expect
            );
        }
    }
}
