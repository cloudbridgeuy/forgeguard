use forgeguard_authn_core::UserSchema;

use crate::etag::Etag;

/// Per-org `UserSchema` coupled with its content-addressed etag.
///
/// Holding an `EtagedUserSchema` is proof that `schema` and `etag` are
/// consistent — the etag was computed from the schema at write time and
/// cannot drift.
#[derive(Debug, Clone)]
pub(crate) struct EtagedUserSchema {
    schema: UserSchema,
    etag: Etag,
}

impl EtagedUserSchema {
    pub(crate) fn compute(schema: UserSchema) -> Self {
        let etag = super::compute_etag_json(&schema);
        Self { schema, etag }
    }

    pub(crate) fn from_stored(schema: UserSchema, etag: Etag) -> Self {
        Self { schema, etag }
    }

    pub(crate) fn schema(&self) -> &UserSchema {
        &self.schema
    }

    pub(crate) fn etag(&self) -> &Etag {
        &self.etag
    }
}
