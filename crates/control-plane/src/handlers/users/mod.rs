//! `POST /api/v1/organizations/{org_id}/users` — inline saga handler.
//!
//! ## Module structure
//!
//! - `pure` — functional core: request DTO, response DTOs for the 7 saga
//!   paths, validation-error shaping. No I/O.
//! - `create` — imperative shell: the `create_handler` Axum entry point and
//!   the `run_saga` driver that walks the S1 → S2 → S3 / C2 stages.

pub(crate) mod create;
pub(crate) mod pure;

pub(crate) use create::create_handler;
