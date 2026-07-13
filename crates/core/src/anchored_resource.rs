//! An unpromoted application resource's reference into the spine
//! (Brief v1.4 §"Anchoring and cardinality"): the resource itself lives in
//! the application's database; ForgeGuard sees only its type name and the
//! FGRN of the node it anchors to. Promotion (which mints a resource FGRN)
//! is a separate, later concern.

use crate::error::{Error, Result};
use crate::fgrn::{Fgrn, FgrnKind};
use crate::segment::Segment;

/// A reference to an application resource by type + anchor. The anchor must
/// be a spine citizen: an org unit, a principal, or a principal-set.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AnchoredResource {
    resource_type: Segment,
    anchor: Fgrn,
}

impl AnchoredResource {
    pub fn try_new(resource_type: Segment, anchor: Fgrn) -> Result<AnchoredResource> {
        match anchor.kind() {
            FgrnKind::OrgUnit | FgrnKind::Principal | FgrnKind::PrincipalSet => {}
            FgrnKind::Resource => {
                return Err(Error::Spine {
                    fgrn: anchor.to_string(),
                    reason: "resource anchor must be an org unit, principal, or principal-set",
                });
            }
        }
        Ok(AnchoredResource {
            resource_type,
            anchor,
        })
    }

    pub fn resource_type(&self) -> &Segment {
        &self.resource_type
    }

    pub fn anchor(&self) -> &Fgrn {
        &self.anchor
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::native_id::NativeId;

    #[test]
    fn happy_path_org_unit_anchor() {
        let org = Segment::try_new("acme").unwrap();
        let id = NativeId::try_new("ou_1").unwrap();
        let anchor = Fgrn::org_unit(&org, &id);
        let resource_type = Segment::try_new("document").unwrap();
        let res = AnchoredResource::try_new(resource_type.clone(), anchor.clone()).unwrap();
        assert_eq!(res.resource_type(), &resource_type);
        assert_eq!(res.anchor(), &anchor);
    }

    #[test]
    fn happy_path_principal_anchor() {
        let org = Segment::try_new("acme").unwrap();
        let id = NativeId::try_new("user_1").unwrap();
        let anchor = Fgrn::principal(&org, &id);
        let resource_type = Segment::try_new("document").unwrap();
        let res = AnchoredResource::try_new(resource_type.clone(), anchor.clone()).unwrap();
        assert_eq!(res.resource_type(), &resource_type);
        assert_eq!(res.anchor(), &anchor);
    }

    #[test]
    fn happy_path_principal_set_anchor() {
        let org = Segment::try_new("acme").unwrap();
        let id = NativeId::try_new("set_1").unwrap();
        let anchor = Fgrn::principal_set(&org, &id);
        let resource_type = Segment::try_new("document").unwrap();
        let res = AnchoredResource::try_new(resource_type.clone(), anchor.clone()).unwrap();
        assert_eq!(res.resource_type(), &resource_type);
        assert_eq!(res.anchor(), &anchor);
    }

    #[test]
    fn resource_anchor_is_rejected() {
        let org = Segment::try_new("acme").unwrap();
        let resource_type = Segment::try_new("document").unwrap();
        let id = NativeId::try_new("doc_1").unwrap();
        let anchor = Fgrn::resource(&org, &resource_type, &id);
        let err = AnchoredResource::try_new(resource_type, anchor.clone()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "spine violation: resource anchor must be an org unit, principal, or principal-set: {}",
                anchor
            )
        );
    }
}
