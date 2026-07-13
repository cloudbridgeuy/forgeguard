//! Resource promotion (Brief v1.4 §"Anchoring and cardinality"): a resource
//! is promoted into the graph the moment someone shares it — sharing is the
//! minting event. [`share`] is the only constructor of [`PromotedResource`],
//! so a resource FGRN cannot exist without its first grant.

use crate::anchored_resource::AnchoredResource;
use crate::error::Result;
use crate::fgrn::Fgrn;
use crate::grant::Grant;
use crate::native_id::NativeId;
use crate::verb::Verb;

/// A resource that has been promoted into the graph. The FGRN incorporates
/// the application's native identifier
/// (`fgrn:{org}:resource:{type}/{native_id}`), so promotion is a single
/// ForgeGuard-side write with no app-side column or migration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PromotedResource {
    fgrn: Fgrn,
    anchor: Fgrn,
}

impl PromotedResource {
    /// The minted resource FGRN.
    pub fn fgrn(&self) -> &Fgrn {
        &self.fgrn
    }

    /// The spine node the resource remains anchored to.
    pub fn anchor(&self) -> &Fgrn {
        &self.anchor
    }
}

/// Inputs for one share. Params struct — pub fields are the documented
/// carve-out (see .claude/context/params-struct-rule.md).
pub struct ShareRequest {
    /// The unpromoted resource being shared.
    pub resource: AnchoredResource,
    /// The application's native identifier for the resource row.
    pub native_id: NativeId,
    /// The grantee — a principal or principal-set.
    pub to: Fgrn,
    /// The verbs the share carries. Must be non-empty.
    pub actions: Vec<Verb>,
}

/// Promote a resource by sharing it. Mints the resource FGRN from the
/// anchor's organization + the resource type + the native id, and builds
/// the first grant edge in the same step. All grant validation (empty
/// actions, grantee kind, cross-org) comes from [`Grant::try_new`].
pub fn share(request: ShareRequest) -> Result<(PromotedResource, Grant)> {
    let minted = Fgrn::resource(
        request.resource.anchor().organization(),
        request.resource.resource_type(),
        &request.native_id,
    );
    let grant = Grant::try_new(minted.clone(), request.actions, request.to)?;
    Ok((
        PromotedResource {
            fgrn: minted,
            anchor: request.resource.anchor().clone(),
        },
        grant,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::segment::Segment;

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn principal(id: &str) -> Fgrn {
        Fgrn::principal(&org(), &NativeId::try_new(id).unwrap())
    }

    fn anchored_doc() -> AnchoredResource {
        AnchoredResource::try_new(
            Segment::try_new("document").unwrap(),
            principal("usr_owner"),
        )
        .unwrap()
    }

    fn verb(s: &str) -> Verb {
        Verb::try_new(s).unwrap()
    }

    #[test]
    fn share_mints_fgrn_with_native_id() {
        let request = ShareRequest {
            resource: anchored_doc(),
            native_id: NativeId::try_new("doc_123").unwrap(),
            to: principal("usr_reader"),
            actions: vec![verb("read")],
        };
        let (promoted, grant) = share(request).unwrap();
        assert_eq!(
            promoted.fgrn().to_string(),
            "fgrn:acme:resource:document/doc_123"
        );
        assert_eq!(promoted.anchor(), &principal("usr_owner"));
        assert_eq!(grant.resource(), promoted.fgrn());
        assert_eq!(grant.to(), &principal("usr_reader"));
    }

    #[test]
    fn share_org_comes_from_anchor() {
        let globex = Segment::try_new("globex").unwrap();
        let anchor = Fgrn::principal(&globex, &NativeId::try_new("usr_owner").unwrap());
        let resource =
            AnchoredResource::try_new(Segment::try_new("document").unwrap(), anchor).unwrap();
        let request = ShareRequest {
            resource,
            native_id: NativeId::try_new("doc_1").unwrap(),
            to: Fgrn::principal(&globex, &NativeId::try_new("usr_reader").unwrap()),
            actions: vec![verb("read")],
        };
        let (promoted, _grant) = share(request).unwrap();
        assert_eq!(promoted.fgrn().organization(), &globex);
    }

    #[test]
    fn share_with_empty_actions_mints_nothing() {
        let request = ShareRequest {
            resource: anchored_doc(),
            native_id: NativeId::try_new("doc_123").unwrap(),
            to: principal("usr_reader"),
            actions: vec![],
        };
        let err = share(request).unwrap_err();
        assert!(err
            .to_string()
            .contains("grant must carry at least one action"));
    }

    #[test]
    fn share_to_cross_org_grantee_mints_nothing() {
        let globex = Segment::try_new("globex").unwrap();
        let request = ShareRequest {
            resource: anchored_doc(),
            native_id: NativeId::try_new("doc_123").unwrap(),
            to: Fgrn::principal(&globex, &NativeId::try_new("usr_x").unwrap()),
            actions: vec![verb("read")],
        };
        let err = share(request).unwrap_err();
        assert!(err
            .to_string()
            .contains("grantee must belong to the same organization"));
    }

    #[test]
    fn share_to_org_unit_grantee_mints_nothing() {
        let request = ShareRequest {
            resource: anchored_doc(),
            native_id: NativeId::try_new("doc_123").unwrap(),
            to: Fgrn::org_unit(&org(), &NativeId::try_new("ou_1").unwrap()),
            actions: vec![verb("read")],
        };
        let err = share(request).unwrap_err();
        assert!(err
            .to_string()
            .contains("grantee must be a principal or principal-set"));
    }
}
