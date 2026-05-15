//! Raw and validated attribute-map types for the user schema.

use std::collections::BTreeMap;

/// Raw wire-form attribute map — keys and values as received from the client,
/// before any schema validation.
pub type RawAttrMap = BTreeMap<String, String>;

/// Schema-validated attribute map.
///
/// A `UserAttributes` instance is proof that every key was either `email`,
/// `email_verified`, or matched an entry in the org's `UserSchema`, and that
/// every value satisfied that entry's constraints. The only constructor lives
/// in [`super::validation::validate_attributes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAttributes(BTreeMap<String, String>);

impl UserAttributes {
    /// Module-private constructor used by `validate_attributes`.
    pub(super) fn from_validated(inner: BTreeMap<String, String>) -> Self {
        Self(inner)
    }

    /// Borrow the underlying map.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Consume `self` and yield the underlying map.
    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }
}
