//! The organizational spine (Brief v1.4): org units whose hierarchy
//! edges form an enforced single-rooted tree. Grant edges (lateral
//! access) are a separate concept and never live here.
//!
//! Re-parenting changes an edge, never an FGRN — identity does not
//! encode position.

use std::collections::HashMap;

use crate::{Error, Fgrn, FgrnKind, Result, Segment};

// ---------------------------------------------------------------------------
// OrgUnit
// ---------------------------------------------------------------------------

/// A single node of the spine and its parent edge.
///
/// `parent = None` means this unit claims to be the root; whether the
/// claim holds (exactly one root) is decided by [`Spine::try_new`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OrgUnit {
    fgrn: Fgrn,
    parent: Option<Fgrn>,
}

impl OrgUnit {
    /// Validate and construct an `OrgUnit`. Does not check that the
    /// parent exists elsewhere in a spine — that is `Spine::try_new`'s job.
    pub fn try_new(fgrn: Fgrn, parent: Option<Fgrn>) -> Result<OrgUnit> {
        if fgrn.kind() != FgrnKind::OrgUnit {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "org unit fgrn must have kind orgunit",
            });
        }

        if let Some(parent) = &parent {
            if parent.kind() != FgrnKind::OrgUnit {
                return Err(Error::Spine {
                    fgrn: parent.to_string(),
                    reason: "parent fgrn must have kind orgunit",
                });
            }
            if parent == &fgrn {
                return Err(Error::Spine {
                    fgrn: fgrn.to_string(),
                    reason: "org unit cannot be its own parent",
                });
            }
            if parent.organization() != fgrn.organization() {
                return Err(Error::Spine {
                    fgrn: parent.to_string(),
                    reason: "parent must belong to the same organization",
                });
            }
        }

        Ok(OrgUnit { fgrn, parent })
    }

    /// Borrow this unit's FGRN.
    pub fn fgrn(&self) -> &Fgrn {
        &self.fgrn
    }

    /// Borrow this unit's parent FGRN, if any.
    pub fn parent(&self) -> Option<&Fgrn> {
        self.parent.as_ref()
    }

    /// Consume this unit into its (fgrn, parent) parts.
    fn into_parts(self) -> (Fgrn, Option<Fgrn>) {
        (self.fgrn, self.parent)
    }
}

// ---------------------------------------------------------------------------
// Spine
// ---------------------------------------------------------------------------

/// A validated single-rooted tree of org units.
///
/// Parse Don't Validate: holding a `Spine` proves single root, existing
/// parents, acyclicity, and one organization. `add`/`reparent` preserve
/// those invariants by checking before applying.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Spine {
    units: HashMap<Fgrn, Option<Fgrn>>,
    root: Fgrn,
    organization: Segment,
}

impl Spine {
    /// Validate a set of org units and construct a `Spine`.
    pub fn try_new(units: Vec<OrgUnit>) -> Result<Spine> {
        let Some(first) = units.first() else {
            return Err(Error::Spine {
                fgrn: "(empty)".to_string(),
                reason: "spine must contain at least one org unit",
            });
        };
        let organization = first.fgrn().organization().clone();

        let mut map: HashMap<Fgrn, Option<Fgrn>> = HashMap::with_capacity(units.len());
        let mut root: Option<Fgrn> = None;

        for unit in units {
            let (fgrn, parent) = unit.into_parts();
            if map.contains_key(&fgrn) {
                return Err(Error::Spine {
                    fgrn: fgrn.to_string(),
                    reason: "duplicate org unit",
                });
            }
            if fgrn.organization() != &organization {
                return Err(Error::Spine {
                    fgrn: fgrn.to_string(),
                    reason: "all org units must belong to one organization",
                });
            }
            if parent.is_none() {
                if root.is_some() {
                    return Err(Error::Spine {
                        fgrn: fgrn.to_string(),
                        reason: "spine must have exactly one root",
                    });
                }
                root = Some(fgrn.clone());
            }
            map.insert(fgrn, parent);
        }

        let Some(root) = root else {
            return Err(Error::Spine {
                fgrn: "(none)".to_string(),
                reason: "spine must have exactly one root",
            });
        };

        for parent in map.values().flatten() {
            if !map.contains_key(parent) {
                return Err(Error::Spine {
                    fgrn: parent.to_string(),
                    reason: "unknown parent",
                });
            }
        }

        for node in map.keys() {
            let mut current = node;
            let mut steps = 0usize;
            while let Some(Some(parent)) = map.get(current) {
                steps += 1;
                if steps > map.len() {
                    return Err(Error::Spine {
                        fgrn: node.to_string(),
                        reason: "cycle detected",
                    });
                }
                current = parent;
            }
        }

        Ok(Spine {
            units: map,
            root,
            organization,
        })
    }

    /// The organization this spine belongs to.
    pub fn organization(&self) -> &Segment {
        &self.organization
    }

    /// The root org unit's FGRN.
    pub fn root(&self) -> &Fgrn {
        &self.root
    }

    /// The number of org units in the spine.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Always false — a spine always contains at least a root.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Whether `fgrn` is a node in this spine.
    pub fn contains(&self, fgrn: &Fgrn) -> bool {
        self.units.contains_key(fgrn)
    }

    /// `Ok(None)` iff `fgrn` is the root. `Err` if `fgrn` is not in the spine.
    pub fn parent(&self, fgrn: &Fgrn) -> Result<Option<&Fgrn>> {
        self.units
            .get(fgrn)
            .map(|parent| parent.as_ref())
            .ok_or_else(|| Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "unknown org unit",
            })
    }

    /// Root-first path: `[root, ..., fgrn]`. `Err` if `fgrn` is not in the spine.
    pub fn path(&self, fgrn: &Fgrn) -> Result<Vec<&Fgrn>> {
        let mut path = vec![
            self.units
                .get_key_value(fgrn)
                .ok_or_else(|| Error::Spine {
                    fgrn: fgrn.to_string(),
                    reason: "unknown org unit",
                })?
                .0,
        ];

        let mut current = fgrn;
        while let Some(Some(parent)) = self.units.get(current) {
            let (key, _) = self
                .units
                .get_key_value(parent)
                .unwrap_or_else(|| unreachable!("a held Spine proves every parent exists"));
            path.push(key);
            current = parent;
        }

        path.reverse();
        Ok(path)
    }

    /// Is `node` in the subtree rooted at `ancestor` (inclusive)?
    pub fn is_at_or_below(&self, node: &Fgrn, ancestor: &Fgrn) -> Result<bool> {
        let path = self.path(node)?;
        if !self.contains(ancestor) {
            return Err(Error::Spine {
                fgrn: ancestor.to_string(),
                reason: "unknown org unit",
            });
        }
        Ok(path.contains(&ancestor))
    }

    /// Add a new org unit. The unit's parent must be `Some` and already
    /// present in the spine; a second root is unrepresentable this way.
    pub fn add(&mut self, unit: OrgUnit) -> Result<()> {
        let (fgrn, parent) = unit.into_parts();
        let Some(parent) = parent else {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "spine already has a root",
            });
        };
        if !self.units.contains_key(&parent) {
            return Err(Error::Spine {
                fgrn: parent.to_string(),
                reason: "unknown parent",
            });
        }
        if self.units.contains_key(&fgrn) {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "duplicate org unit",
            });
        }
        if fgrn.organization() != &self.organization {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "all org units must belong to one organization",
            });
        }

        self.units.insert(fgrn, Some(parent));
        Ok(())
    }

    /// Move `node`'s parent edge to `new_parent`. The FGRN never changes.
    pub fn reparent(&mut self, node: &Fgrn, new_parent: &Fgrn) -> Result<()> {
        if !self.units.contains_key(node) {
            return Err(Error::Spine {
                fgrn: node.to_string(),
                reason: "unknown org unit",
            });
        }
        if node == &self.root {
            return Err(Error::Spine {
                fgrn: node.to_string(),
                reason: "cannot reparent the root",
            });
        }
        if !self.units.contains_key(new_parent) {
            return Err(Error::Spine {
                fgrn: new_parent.to_string(),
                reason: "unknown parent",
            });
        }
        if self.is_at_or_below(new_parent, node)? {
            return Err(Error::Spine {
                fgrn: node.to_string(),
                reason: "reparent would create a cycle",
            });
        }

        if let Some(entry) = self.units.get_mut(node) {
            *entry = Some(new_parent.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::NativeId;

    fn ou(org: &str, id: &str) -> Fgrn {
        Fgrn::org_unit(
            &Segment::try_new(org).unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    fn principal(org: &str, id: &str) -> Fgrn {
        Fgrn::principal(
            &Segment::try_new(org).unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    #[test]
    fn try_new_accepts_root() {
        let unit = OrgUnit::try_new(ou("acme", "root"), None).unwrap();
        assert_eq!(unit.fgrn(), &ou("acme", "root"));
        assert_eq!(unit.parent(), None);
    }

    #[test]
    fn try_new_accepts_child() {
        let unit = OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "root"))).unwrap();
        assert_eq!(unit.parent(), Some(&ou("acme", "root")));
    }

    #[test]
    fn try_new_rejects_non_orgunit_fgrn() {
        let err = OrgUnit::try_new(principal("acme", "usr_1"), None).unwrap_err();
        assert!(err
            .to_string()
            .contains("org unit fgrn must have kind orgunit"));
    }

    #[test]
    fn try_new_rejects_non_orgunit_parent() {
        let err =
            OrgUnit::try_new(ou("acme", "finance"), Some(principal("acme", "usr_1"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent fgrn must have kind orgunit"));
    }

    #[test]
    fn try_new_rejects_self_parent() {
        let err = OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "finance"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("org unit cannot be its own parent"));
    }

    #[test]
    fn try_new_rejects_cross_org_parent() {
        let err = OrgUnit::try_new(ou("acme", "finance"), Some(ou("globex", "root"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent must belong to the same organization"));
    }

    // -- Spine ---------------------------------------------------------------

    // fixture tree:  root ── finance ── accounting
    //                    └── engineering
    fn fixture() -> Spine {
        Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "root"))).unwrap(),
            OrgUnit::try_new(ou("acme", "accounting"), Some(ou("acme", "finance"))).unwrap(),
            OrgUnit::try_new(ou("acme", "engineering"), Some(ou("acme", "root"))).unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn spine_try_new_happy_path() {
        let spine = fixture();
        assert_eq!(spine.root(), &ou("acme", "root"));
        assert_eq!(spine.len(), 4);
        assert!(!spine.is_empty());
        assert_eq!(spine.organization().as_str(), "acme");
        assert!(spine.contains(&ou("acme", "accounting")));
        assert!(!spine.contains(&ou("acme", "marketing")));
    }

    #[test]
    fn spine_try_new_rejects_empty() {
        let err = Spine::try_new(vec![]).unwrap_err();
        assert!(err
            .to_string()
            .contains("spine must contain at least one org unit"));
    }

    #[test]
    fn spine_try_new_rejects_duplicate() {
        let err = Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("duplicate org unit"));
    }

    #[test]
    fn spine_try_new_rejects_mixed_organizations() {
        let err = Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("globex", "root"), None).unwrap(),
        ])
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("all org units must belong to one organization"));
    }

    #[test]
    fn spine_try_new_rejects_zero_roots() {
        let err = Spine::try_new(vec![OrgUnit::try_new(
            ou("acme", "finance"),
            Some(ou("acme", "root")),
        )
        .unwrap()])
        .unwrap_err();
        assert!(err.to_string().contains("spine must have exactly one root"));
    }

    #[test]
    fn spine_try_new_rejects_two_roots() {
        let err = Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("acme", "root2"), None).unwrap(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("spine must have exactly one root"));
    }

    #[test]
    fn spine_try_new_rejects_unknown_parent() {
        let err = Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "ghost"))).unwrap(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("unknown parent"));
    }

    #[test]
    fn spine_try_new_rejects_cycle() {
        // A root satisfies the single-root check on its own; the a<->b
        // cycle is disjoint from it and both parents exist, so only the
        // cycle-detection pass catches it.
        let err = Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("acme", "a"), Some(ou("acme", "b"))).unwrap(),
            OrgUnit::try_new(ou("acme", "b"), Some(ou("acme", "a"))).unwrap(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("cycle detected"));
    }

    #[test]
    fn spine_parent() {
        let spine = fixture();
        assert_eq!(spine.parent(&ou("acme", "root")).unwrap(), None);
        assert_eq!(
            spine.parent(&ou("acme", "accounting")).unwrap(),
            Some(&ou("acme", "finance"))
        );
        assert!(spine.parent(&ou("acme", "ghost")).is_err());
    }

    #[test]
    fn spine_path() {
        let spine = fixture();
        assert_eq!(
            spine.path(&ou("acme", "accounting")).unwrap(),
            vec![
                &ou("acme", "root"),
                &ou("acme", "finance"),
                &ou("acme", "accounting")
            ]
        );
        assert_eq!(
            spine.path(&ou("acme", "root")).unwrap(),
            vec![&ou("acme", "root")]
        );
    }

    #[test]
    fn spine_is_at_or_below() {
        let spine = fixture();
        assert!(spine
            .is_at_or_below(&ou("acme", "accounting"), &ou("acme", "finance"))
            .unwrap());
        assert!(spine
            .is_at_or_below(&ou("acme", "accounting"), &ou("acme", "root"))
            .unwrap());
        assert!(!spine
            .is_at_or_below(&ou("acme", "finance"), &ou("acme", "engineering"))
            .unwrap());
        assert!(spine
            .is_at_or_below(&ou("acme", "finance"), &ou("acme", "finance"))
            .unwrap());
    }

    #[test]
    fn spine_add() {
        let mut spine = fixture();
        spine
            .add(OrgUnit::try_new(ou("acme", "backend"), Some(ou("acme", "engineering"))).unwrap())
            .unwrap();
        assert_eq!(
            spine.path(&ou("acme", "backend")).unwrap(),
            vec![
                &ou("acme", "root"),
                &ou("acme", "engineering"),
                &ou("acme", "backend")
            ]
        );

        let err = spine
            .add(OrgUnit::try_new(ou("acme", "root2"), None).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("spine already has a root"));

        let err = spine
            .add(OrgUnit::try_new(ou("acme", "orphan"), Some(ou("acme", "ghost"))).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("unknown parent"));

        let err = spine
            .add(OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "root"))).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("duplicate org unit"));

        // A cross-organization unit is already rejected at `OrgUnit::try_new`
        // (its parent must share its organization), so it never reaches
        // `Spine::add`'s own organization guard directly — construction
        // itself surfaces the same reason.
        let err = OrgUnit::try_new(ou("globex", "outsider"), Some(ou("acme", "root"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent must belong to the same organization"));
    }

    #[test]
    fn spine_reparent() {
        let mut spine = fixture();
        spine
            .reparent(&ou("acme", "finance"), &ou("acme", "engineering"))
            .unwrap();
        assert_eq!(
            spine.path(&ou("acme", "accounting")).unwrap(),
            vec![
                &ou("acme", "root"),
                &ou("acme", "engineering"),
                &ou("acme", "finance"),
                &ou("acme", "accounting")
            ]
        );

        let err = spine
            .reparent(&ou("acme", "root"), &ou("acme", "finance"))
            .unwrap_err();
        assert!(err.to_string().contains("cannot reparent the root"));

        let mut spine = fixture();
        let err = spine
            .reparent(&ou("acme", "finance"), &ou("acme", "accounting"))
            .unwrap_err();
        assert!(err.to_string().contains("reparent would create a cycle"));

        let err = spine
            .reparent(&ou("acme", "finance"), &ou("acme", "finance"))
            .unwrap_err();
        assert!(err.to_string().contains("reparent would create a cycle"));

        let err = spine
            .reparent(&ou("acme", "ghost"), &ou("acme", "root"))
            .unwrap_err();
        assert!(err.to_string().contains("unknown org unit"));

        let err = spine
            .reparent(&ou("acme", "finance"), &ou("acme", "ghost"))
            .unwrap_err();
        assert!(err.to_string().contains("unknown parent"));
    }
}
