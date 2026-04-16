//! Cedar IDENT types: validated identifiers for Cedar policy language.
//!
//! These types encode Cedar IDENT validity in the type system, eliminating
//! raw string manipulation at call sites.

use std::fmt;

use crate::{Error, Namespace, ProjectId, Result};

// ---------------------------------------------------------------------------
// CedarIdent
// ---------------------------------------------------------------------------

/// A validated Cedar IDENT: `[_a-zA-Z][_a-zA-Z0-9]*`.
///
/// Constructed via [`CedarIdent::new`] (fallible, for arbitrary input) or
/// [`crate::Segment::to_cedar_ident`] (infallible, since every valid `Segment`
/// produces a valid IDENT after replacing `-` with `_`).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CedarIdent(String);

impl CedarIdent {
    /// Create a new `CedarIdent` after validating the input matches
    /// `[_a-zA-Z][_a-zA-Z0-9]*`.
    pub fn new(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::Parse {
                field: "cedar_ident",
                value: s.to_string(),
                reason: "cannot be empty",
            });
        }

        let first = s.as_bytes()[0];
        if first != b'_' && !first.is_ascii_alphabetic() {
            return Err(Error::Parse {
                field: "cedar_ident",
                value: s.to_string(),
                reason: "must start with an underscore or ASCII letter",
            });
        }

        if !s.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric()) {
            return Err(Error::Parse {
                field: "cedar_ident",
                value: s.to_string(),
                reason: "must contain only underscores, ASCII letters, and digits",
            });
        }

        Ok(Self(s.to_string()))
    }

    /// Internal constructor from a value already known to be valid.
    /// Used by `Segment::to_cedar_ident()` where validity is guaranteed.
    pub(crate) fn from_valid(s: String) -> Self {
        Self(s)
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CedarIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// CedarEntityType
// ---------------------------------------------------------------------------

/// A Cedar entity type encoding `{namespace}__{entity}`.
///
/// Uses `__` (double underscore) as the namespace separator, which is
/// unambiguous because `Segment` forbids underscores (so `_` only comes
/// from `-` replacement).
///
/// IAM entities (`user`, `group`) use bare names without a namespace prefix.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CedarEntityType(String);

impl CedarEntityType {
    /// Construct from namespace and entity segments.
    ///
    /// Result: `"{namespace_ident}__{entity_ident}"`.
    pub fn new(namespace: &Namespace, entity: &crate::Entity) -> Self {
        let ns_ident = namespace.as_segment().to_cedar_ident();
        let entity_ident = entity.as_segment().to_cedar_ident();
        Self(format!("{}__{}", ns_ident.as_str(), entity_ident.as_str()))
    }

    /// Construct from raw [`crate::Segment`] values (e.g., from [`crate::CedarEntityRef`]).
    ///
    /// Result: `"{namespace_ident}__{entity_ident}"`.
    pub fn new_from_segments(namespace: &crate::Segment, entity: &crate::Segment) -> Self {
        let ns_ident = namespace.to_cedar_ident();
        let entity_ident = entity.to_cedar_ident();
        Self(format!("{}__{}", ns_ident.as_str(), entity_ident.as_str()))
    }

    /// The `user` entity type (no namespace prefix).
    pub fn user() -> Self {
        Self("user".to_string())
    }

    /// The `group` entity type (no namespace prefix).
    pub fn group() -> Self {
        Self("group".to_string())
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CedarEntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// CedarNamespace
// ---------------------------------------------------------------------------

/// A VP namespace derived from a [`ProjectId`].
///
/// Wraps a [`CedarIdent`] produced by converting the project's `Segment`
/// to a Cedar-safe identifier (replacing `-` with `_`).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CedarNamespace(CedarIdent);

impl CedarNamespace {
    /// Derive a VP namespace from a project ID.
    pub fn from_project(project: &ProjectId) -> Self {
        Self(project.as_segment().to_cedar_ident())
    }

    /// Borrow the inner `CedarIdent`.
    pub fn as_ident(&self) -> &CedarIdent {
        &self.0
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for CedarNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- CedarIdent ----------------------------------------------------------

    #[test]
    fn cedar_ident_valid_lowercase() {
        assert!(CedarIdent::new("acme_corp").is_ok());
    }

    #[test]
    fn cedar_ident_valid_uppercase() {
        assert!(CedarIdent::new("AcmeCorp").is_ok());
    }

    #[test]
    fn cedar_ident_valid_underscore_start() {
        assert!(CedarIdent::new("_private").is_ok());
    }

    #[test]
    fn cedar_ident_valid_with_digits() {
        assert!(CedarIdent::new("item123").is_ok());
    }

    #[test]
    fn cedar_ident_rejects_empty() {
        assert!(CedarIdent::new("").is_err());
    }

    #[test]
    fn cedar_ident_rejects_leading_digit() {
        assert!(CedarIdent::new("123abc").is_err());
    }

    #[test]
    fn cedar_ident_rejects_hyphens() {
        assert!(CedarIdent::new("acme-corp").is_err());
    }

    #[test]
    fn cedar_ident_rejects_spaces() {
        assert!(CedarIdent::new("acme corp").is_err());
    }

    #[test]
    fn cedar_ident_as_str() {
        let ident = CedarIdent::new("acme_corp").unwrap();
        assert_eq!(ident.as_str(), "acme_corp");
    }

    #[test]
    fn cedar_ident_display() {
        let ident = CedarIdent::new("todo_list").unwrap();
        assert_eq!(ident.to_string(), "todo_list");
    }

    // -- CedarEntityType -----------------------------------------------------

    #[test]
    fn cedar_entity_type_from_namespace_entity() {
        let ns = Namespace::parse("todo").unwrap();
        let entity = crate::Entity::parse("list").unwrap();
        let cet = CedarEntityType::new(&ns, &entity);
        assert_eq!(cet.as_str(), "todo__list");
    }

    #[test]
    fn cedar_entity_type_with_hyphens() {
        let ns = Namespace::parse("ci").unwrap();
        let entity = crate::Entity::parse("pipeline-run").unwrap();
        let cet = CedarEntityType::new(&ns, &entity);
        assert_eq!(cet.as_str(), "ci__pipeline_run");
    }

    #[test]
    fn cedar_entity_type_user() {
        assert_eq!(CedarEntityType::user().as_str(), "user");
    }

    #[test]
    fn cedar_entity_type_group() {
        assert_eq!(CedarEntityType::group().as_str(), "group");
    }

    #[test]
    fn cedar_entity_type_display() {
        let ns = Namespace::parse("todo").unwrap();
        let entity = crate::Entity::parse("list").unwrap();
        let cet = CedarEntityType::new(&ns, &entity);
        assert_eq!(cet.to_string(), "todo__list");
    }

    // -- CedarNamespace ------------------------------------------------------

    #[test]
    fn cedar_namespace_from_project() {
        let project = ProjectId::new("todo-app").unwrap();
        let ns = CedarNamespace::from_project(&project);
        assert_eq!(ns.as_str(), "todo_app");
    }

    #[test]
    fn cedar_namespace_no_hyphens() {
        let project = ProjectId::new("myapp").unwrap();
        let ns = CedarNamespace::from_project(&project);
        assert_eq!(ns.as_str(), "myapp");
    }

    #[test]
    fn cedar_namespace_display() {
        let project = ProjectId::new("todo-app").unwrap();
        let ns = CedarNamespace::from_project(&project);
        assert_eq!(ns.to_string(), "todo_app");
    }
}
