//! `GET /api/v1/organizations/{org_id}/user-schema`
//!
//! Imperative shell: load the org, state-gate on `Deleted`, fetch the stored
//! schema row, and shape the response. Pure helpers (DTOs, error mapping) live
//! in [`super::pure`].

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authn_core::UserSchema;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, OrganizationId};

use super::pure::{etag_header, UserSchemaResource};
use crate::store::OrgStore;

/// `GET /api/v1/organizations/{org_id}/user-schema`
///
/// Returns the org's declared user attribute schema. State-gated per R9.2:
/// every status accepts GET except `Deleted` (→ 404).
///
/// When no schema row has been written for the org, returns `200 OK` with an
/// empty schema body (`{"standard": {}, "custom": {}}`) and **no** `ETag`
/// header. The presence of the `ETag` header is the operator-visible signal
/// that a schema has been explicitly set.
#[tracing::instrument(
    name = "get_user_schema",
    skip_all,
    fields(org_id = %raw_org_id),
)]
pub(crate) async fn get_user_schema_handler(
    ForgeGuardIdentity(_identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<dyn OrgStore>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    let record = match store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return crate::handlers::not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "get user_schema: org lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if record.org().status() == OrgStatus::Deleted {
        return crate::handlers::not_found();
    }

    match store.get_user_schema(&org_id).await {
        Ok(Some(eg)) => (
            StatusCode::OK,
            etag_header(eg.etag()),
            Json(UserSchemaResource::new(eg.schema().clone())),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::OK,
            HeaderMap::new(),
            Json(UserSchemaResource::new(UserSchema::default())),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "get user_schema failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
