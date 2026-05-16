//! User-schema HTTP handlers.
//!
//! - [`pure`] — functional core: wire DTOs, payload parser, 422 shaper. No I/O.
//! - [`get`] — imperative shell for `GET /user-schema`.
//! - [`put`] — imperative shell for `PUT /user-schema`.

pub(crate) mod get;
pub(crate) mod pure;
pub(crate) mod put;

pub(crate) use get::get_user_schema_handler;
pub(crate) use put::put_user_schema_handler;
