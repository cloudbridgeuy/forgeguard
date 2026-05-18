//! `POST /api/v1/organizations/{org_id}/users` — saga driver.
//!
//! Imperative shell: walks S1 (validation) → S2 (Cognito AdminCreateUser) →
//! S3 (DDB PutMembership) with C2 (Cognito AdminDeleteUser) compensation on a
//! transient S3 failure. Returns one of seven response shapes per plan §9.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authn_core::saga::{SagaStage, SagaStatus, SagaTicket, SagaTicketParams, TicketId};
use forgeguard_authn_core::user_pool::{CreateUserParams, PoolId, UserPoolError};
use forgeguard_authn_core::user_schema::CreateUserCommand;
use forgeguard_authn_core::{validate_attributes, MembershipRow, MembershipRowParams, UserSchema};
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, OrganizationId, UserId};

use super::pure::{
    self, AttributeAlreadyExistsBody, CompensationFailedBody, CreateUserPayload, CreatedUserBody,
    InFlightSagaBody, ParkedSagaBody, UpstreamErrorBody, UsernameExistsBody,
};
use crate::handlers::AppState;
use crate::metrics;
use crate::store::{OrgRecord, OrgStore, PutMembershipRowParams, SagaStageUpdate, SagaTicketStore};
use crate::user_pool::UserPoolClient;
use crate::vp_client::VpClient;

/// `POST /api/v1/organizations/{org_id}/users`
///
/// Inline 3-stage saga (S1/S2/S3) with C2 compensation on transient S3 failure.
/// See plan §9 for the 7 response paths.
#[tracing::instrument(
    name = "create_user",
    skip_all,
    fields(org_id = %raw_org_id),
)]
pub(crate) async fn create_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
    Json(body): Json<CreateUserPayload>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    let store = &state.store;
    let user_pool = &state.user_pool;
    let saga_tickets = &state.saga_tickets;

    let record = match store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return crate::handlers::not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "create user: org lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match record.org().status() {
        OrgStatus::Active => {}
        OrgStatus::Deleted => return crate::handlers::not_found(),
        status => return state_conflict(status),
    }

    let pool_id = match resolve_pool_id(&record) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let schema = match fetch_schema(store.as_ref(), &org_id, &raw_org_id).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // "anonymous" is a valid non-empty UserId literal; the error branch is
    // unreachable. `unwrap_or_else(|_| unreachable!(...))` is the project
    // idiom for infallible-at-the-call-site Results in non-test code.
    let created_by = identity
        .as_ref()
        .map(|i| i.user_id().clone())
        .unwrap_or_else(|| {
            UserId::new("anonymous")
                .unwrap_or_else(|_| unreachable!("'anonymous' is a valid UserId literal"))
        });

    run_saga(SagaCtx {
        store: store.as_ref(),
        user_pool: user_pool.as_ref(),
        saga_tickets: saga_tickets.as_ref(),
        org_id: &org_id,
        raw_org_id: &raw_org_id,
        pool_id,
        schema: &schema,
        created_by: &created_by,
        body,
    })
    .await
}

/// Bundle of borrowed inputs threaded through the saga driver.
struct SagaCtx<'a> {
    store: &'a dyn OrgStore,
    user_pool: &'a dyn UserPoolClient,
    saga_tickets: &'a dyn SagaTicketStore,
    org_id: &'a OrganizationId,
    raw_org_id: &'a str,
    pool_id: PoolId,
    schema: &'a UserSchema,
    created_by: &'a UserId,
    body: CreateUserPayload,
}

async fn run_saga(ctx: SagaCtx<'_>) -> Response {
    let SagaCtx {
        store,
        user_pool,
        saga_tickets,
        org_id,
        raw_org_id,
        pool_id,
        schema,
        created_by,
        body,
    } = ctx;

    // -----------------------------------------------------------------------
    // Stage S1 — pure validation (no ticket written yet)
    // -----------------------------------------------------------------------
    // Wire-to-domain conversion (pure): parses raw group names into typed
    // `GroupName`. Surfaces 422 on the first malformed entry.
    let command: CreateUserCommand = match pure::payload_to_command(body) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let validated_attrs = match validate_attributes(schema, &command.attributes) {
        Ok(v) => v,
        Err(errors) => return pure::shape_422_validation(&errors),
    };

    // Declaration check is I/O (store lookup) and stays in the imperative shell.
    for group in &command.groups {
        match store.is_declared_group(org_id, group.as_str()).await {
            Ok(true) => {}
            Ok(false) => return pure::shape_422_undeclared_group(group.as_str()),
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, group = %group, error = %e, "create user: declared-group check failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    let typed_groups = command.groups;

    // -----------------------------------------------------------------------
    // Path 5 — in-flight idempotency check
    // -----------------------------------------------------------------------
    match saga_tickets
        .find_in_flight_saga_by_email(org_id, &command.email)
        .await
    {
        Ok(Some(existing_ticket_id)) => {
            return (
                StatusCode::CONFLICT,
                Json(InFlightSagaBody {
                    error: "in_flight_saga",
                    existing_ticket_id,
                    message: "a user creation is already in progress for this email",
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, email = %command.email, error = %e, "create user: in-flight lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // -----------------------------------------------------------------------
    // Persist the InFlight/S1 ticket
    // -----------------------------------------------------------------------
    let now = chrono::Utc::now();
    let ticket_id = TicketId::generate();
    let ticket = SagaTicket::new(SagaTicketParams {
        ticket_id: ticket_id.clone(),
        org_id: org_id.clone(),
        email: command.email.clone(),
        groups: typed_groups.clone(),
        attributes: validated_attrs.as_map().clone(),
        created_at: now,
        created_by: created_by.clone(),
    });

    if let Err(e) = saga_tickets.put_saga_ticket(ticket).await {
        tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: put_saga_ticket failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // S1 -> S2 — about to call Cognito.
    if let Err(e) = saga_tickets
        .advance_saga_stage(
            &ticket_id,
            SagaStage::S1,
            SagaStage::S2,
            SagaStageUpdate::default(),
        )
        .await
    {
        tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: advance S1->S2 failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // -----------------------------------------------------------------------
    // Stage S2 — AdminCreateUser
    // -----------------------------------------------------------------------
    let create_params = CreateUserParams {
        pool_id: pool_id.clone(),
        email: command.email.clone(),
        attributes: validated_attrs.as_map().clone(),
    };
    let sub = match user_pool.admin_create_user(create_params).await {
        Ok(sub) => sub,
        Err(UserPoolError::UsernameExists) => {
            mark_ticket_failed(saga_tickets, &ticket_id, SagaStage::S2, "username_exists").await;
            return (
                StatusCode::CONFLICT,
                Json(UsernameExistsBody {
                    error: "username_exists",
                    message: "a user with this email already exists",
                }),
            )
                .into_response();
        }
        Err(UserPoolError::AttributeAlreadyExists { ref name }) => {
            let reason = format!("attribute_already_exists:{name}");
            mark_ticket_failed(saga_tickets, &ticket_id, SagaStage::S2, &reason).await;
            return (
                StatusCode::CONFLICT,
                Json(AttributeAlreadyExistsBody {
                    error: "attribute_already_exists",
                    message: "a Cognito attribute on this request already exists",
                }),
            )
                .into_response();
        }
        Err(UserPoolError::Transient { source }) => {
            let reason = format!("s2_transient:{source}");
            tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %source, "create user: S2 transient failure");
            mark_ticket_failed(saga_tickets, &ticket_id, SagaStage::S2, &reason).await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(UpstreamErrorBody {
                    ticket_id,
                    error: "upstream_error",
                    message: "Cognito returned a transient error; the client may retry",
                }),
            )
                .into_response();
        }
        Err(err) => {
            let reason = format!("s2_permanent:{err}");
            tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %err, "create user: S2 permanent failure");
            mark_ticket_failed(saga_tickets, &ticket_id, SagaStage::S2, &reason).await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(UpstreamErrorBody {
                    ticket_id,
                    error: "upstream_error",
                    message: "Cognito returned a permanent error",
                }),
            )
                .into_response();
        }
    };

    // S2 -> S3 — record the sub on the ticket.
    if let Err(e) = saga_tickets
        .advance_saga_stage(
            &ticket_id,
            SagaStage::S2,
            SagaStage::S3,
            SagaStageUpdate {
                sub: Some(sub.clone()),
                ..SagaStageUpdate::default()
            },
        )
        .await
    {
        tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: advance S2->S3 failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // -----------------------------------------------------------------------
    // Stage S3 — PutMembership
    // -----------------------------------------------------------------------
    let row = MembershipRow::new(MembershipRowParams {
        sub: sub.clone(),
        org_id: org_id.clone(),
        groups: typed_groups.clone(),
        email: command.email.clone(),
        created_at: now,
        created_by: created_by.clone(),
    });

    match store
        .put_membership_row(PutMembershipRowParams { row: &row })
        .await
    {
        Ok(()) => {
            if let Err(e) = saga_tickets
                .advance_saga_stage(
                    &ticket_id,
                    SagaStage::S3,
                    SagaStage::Done,
                    SagaStageUpdate {
                        status: Some(SagaStatus::Succeeded),
                        ..SagaStageUpdate::default()
                    },
                )
                .await
            {
                tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: advance S3->Done failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            (
                StatusCode::CREATED,
                Json(CreatedUserBody {
                    sub,
                    attributes: validated_attrs.as_map().clone(),
                    groups: typed_groups.iter().map(|g| g.as_str().to_owned()).collect(),
                    ticket_id,
                }),
            )
                .into_response()
        }
        Err(s3_err) => {
            tracing::warn!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %s3_err, "create user: S3 transient failure, compensating");
            // S3 -> Compensating
            if let Err(e) = saga_tickets
                .advance_saga_stage(
                    &ticket_id,
                    SagaStage::S3,
                    SagaStage::Compensating,
                    SagaStageUpdate {
                        failure_reason: Some(s3_err.to_string()),
                        ..SagaStageUpdate::default()
                    },
                )
                .await
            {
                tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: advance S3->Compensating failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            // C2 — AdminDeleteUser
            match user_pool.admin_delete_user(&pool_id, &sub).await {
                Ok(()) => {
                    // Compensating -> Failed; saga rolled back cleanly.
                    if let Err(e) = saga_tickets
                        .advance_saga_stage(
                            &ticket_id,
                            SagaStage::Compensating,
                            SagaStage::Failed,
                            SagaStageUpdate {
                                status: Some(SagaStatus::Failed),
                                ..SagaStageUpdate::default()
                            },
                        )
                        .await
                    {
                        tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: advance Compensating->Failed failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    (
                        StatusCode::ACCEPTED,
                        Json(ParkedSagaBody {
                            ticket_id,
                            status: "in_progress",
                            sub: None,
                            message: "user creation is being processed asynchronously",
                        }),
                    )
                        .into_response()
                }
                Err(c2_err) => {
                    tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %c2_err, "create user: C2 failed, manual reconciliation required");
                    let reason = format!("c2_failed:{c2_err}");
                    if let Err(e) = saga_tickets
                        .advance_saga_stage(
                            &ticket_id,
                            SagaStage::Compensating,
                            SagaStage::CompensationFailed,
                            SagaStageUpdate {
                                status: Some(SagaStatus::CompensationFailed),
                                failure_reason: Some(reason),
                                ..SagaStageUpdate::default()
                            },
                        )
                        .await
                    {
                        tracing::error!(org_id = %raw_org_id, ticket_id = %ticket_id, error = %e, "create user: advance Compensating->CompensationFailed failed");
                    }
                    metrics::record_saga_compensation_failed();
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(CompensationFailedBody {
                            ticket_id,
                            status: "failed",
                            reason: "compensation failed — Cognito user may exist without a membership row",
                        }),
                    )
                        .into_response()
                }
            }
        }
    }
}

/// Resolve the org's Cognito pool id, surfacing a 500 if the Active org is
/// missing the configuration field (saga invariant violation — parallels
/// `shape_active_state_error` in the groups handler).
#[allow(clippy::result_large_err)] // `Response` *is* the error payload here
fn resolve_pool_id(record: &OrgRecord) -> Result<PoolId, Response> {
    let raw = record
        .config()
        .and_then(crate::config::OrgConfig::cognito_user_pool_id)
        .ok_or_else(|| {
            tracing::error!(
                org_id = %record.org().org_id(),
                "active org has no cognito_user_pool_id; saga invariant violated",
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    PoolId::try_new(raw).map_err(|e| {
        tracing::error!(
            org_id = %record.org().org_id(),
            error = %e,
            "active org has invalid cognito_user_pool_id",
        );
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })
}

/// Fetch the org's `UserSchema`, defaulting to an empty schema if no row exists.
///
/// An Active org without a schema is a valid configuration — it means no
/// custom or required attributes are declared, so only the always-accepted
/// `email`/`email_verified` invariants pass S1.
#[allow(clippy::result_large_err)] // `Response` *is* the error payload here
async fn fetch_schema(
    store: &dyn OrgStore,
    org_id: &OrganizationId,
    raw_org_id: &str,
) -> Result<UserSchema, Response> {
    match store.get_user_schema(org_id).await {
        Ok(Some(eg)) => Ok(eg.schema().clone()),
        Ok(None) => Ok(UserSchema::default()),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "create user: schema lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Move a non-terminal ticket to `Failed` with the given prior stage.
/// Used by the S2 failure paths (UsernameExists, AttributeAlreadyExists,
/// Permanent error).
async fn mark_ticket_failed(
    saga_tickets: &dyn SagaTicketStore,
    ticket_id: &TicketId,
    from: SagaStage,
    reason: &str,
) {
    if let Err(e) = saga_tickets
        .advance_saga_stage(
            ticket_id,
            from,
            SagaStage::Failed,
            SagaStageUpdate {
                status: Some(SagaStatus::Failed),
                failure_reason: Some(reason.to_owned()),
                ..SagaStageUpdate::default()
            },
        )
        .await
    {
        tracing::error!(ticket_id = %ticket_id, error = %e, "create user: advance to Failed failed");
    }
}

/// 409 response for non-`Active`, non-`Deleted` org statuses (Draft,
/// Provisioning, etc.). Mirrors `state_conflict` in `user_schema::put` but
/// with a distinct error code so clients can branch on it.
fn state_conflict(status: OrgStatus) -> Response {
    use serde::Serialize;
    #[derive(Serialize)]
    struct Body {
        error: &'static str,
        reason: String,
    }
    (
        StatusCode::CONFLICT,
        Json(Body {
            error: "org_state_conflict",
            reason: status.to_string(),
        }),
    )
        .into_response()
}
