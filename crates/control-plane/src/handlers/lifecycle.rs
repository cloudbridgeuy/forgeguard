//! Lifecycle verb handlers (#113 V2): `activate`/`suspend`/`restore`.
//!
//! Authorization is enforced by the `forgeguard_layer` middleware via the
//! `cp-organization-activate`/`-suspend`/`-restore` action mappings in
//! `app.rs` + `forgeguard.toml`, so no explicit authz code lives here.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authz_core::EventKind;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, OrganizationId};

use crate::handlers::{actor_for, not_found, revision_header_map, AppState};
use crate::store::OrgRecord;
use crate::vp_client::VpClient;

/// A lifecycle verb driving [`OrgStatus`] through the event log.
#[derive(Debug, Clone, Copy)]
pub(crate) enum LifecycleVerb {
    Activate,
    Suspend,
    Restore,
}

impl LifecycleVerb {
    /// The status this verb transitions an org *to*.
    fn target(self) -> OrgStatus {
        match self {
            Self::Activate | Self::Restore => OrgStatus::Active,
            Self::Suspend => OrgStatus::Suspended,
        }
    }

    /// The event kind appended for this verb.
    fn kind(self) -> EventKind {
        match self {
            Self::Activate => EventKind::OrgActivated,
            Self::Suspend => EventKind::OrgSuspended,
            Self::Restore => EventKind::OrgRestored,
        }
    }

    /// The statuses this verb is valid to transition from.
    fn valid_from(self, from: OrgStatus) -> bool {
        match self {
            Self::Activate => matches!(from, OrgStatus::Draft),
            Self::Suspend => matches!(from, OrgStatus::Active),
            Self::Restore => matches!(from, OrgStatus::Suspended),
        }
    }
}

/// Shared flow for all three lifecycle verbs: parse org id (404) -> `store.get`
/// (missing/`Deleted` -> 404) -> no-op if already at `target` (200, no event)
/// -> `valid_from` gate (409 `invalid_transition`) -> append the lifecycle
/// event via [`crate::model_event_store::ModelEventStore::transition_org`],
/// mapping a lost revision race to 409 `transition_conflict`.
async fn transition_handler<V: VpClient + 'static>(
    verb: LifecycleVerb,
    identity: Option<forgeguard_authn_core::Identity>,
    raw_org_id: String,
    state: AppState<V>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    let record = match state.store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "lifecycle transition: get failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if record.org().status() == OrgStatus::Deleted {
        return not_found();
    }

    let from = record.org().status();
    let target = verb.target();

    if from == target {
        let revision = match current_revision(&state, &raw_org_id).await {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        return (
            StatusCode::OK,
            revision_header_map(revision.value()),
            Json(serde_json::json!({
                "organization": record.org(),
                "revision": revision.value(),
            })),
        )
            .into_response();
    }

    if !verb.valid_from(from) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "invalid_transition",
                "from": from.to_string(),
                "to": target.to_string(),
            })),
        )
            .into_response();
    }

    let expected_revision = match current_revision(&state, &raw_org_id).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let now = chrono::Utc::now();
    let org = match record.org().clone().transition_to(target, now) {
        Ok(org) => org,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "lifecycle transition: transition_to failed");
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "invalid_transition",
                    "from": from.to_string(),
                    "to": target.to_string(),
                })),
            )
                .into_response();
        }
    };
    let org_snapshot = org.clone();
    let updated_record = OrgRecord::new(org, record.configured().cloned());
    let actor = actor_for(&raw_org_id, identity.as_ref());

    match state
        .model_events
        .transition_org(updated_record, verb.kind(), actor, expected_revision)
        .await
    {
        Ok(revision) => (
            StatusCode::OK,
            revision_header_map(revision.value()),
            Json(serde_json::json!({
                "organization": org_snapshot,
                "revision": revision.value(),
            })),
        )
            .into_response(),
        Err(crate::error::Error::RevisionMismatch { current }) => (
            StatusCode::CONFLICT,
            revision_header_map(current),
            Json(serde_json::json!({
                "error": "transition_conflict",
                "current_revision": current,
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "lifecycle transition: append failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Fetch the event log's current revision for `raw_org_id`, mapping a store
/// error to a `500` response for the caller to return directly.
async fn current_revision<V: VpClient + 'static>(
    state: &AppState<V>,
    raw_org_id: &str,
) -> Result<forgeguard_authz_core::Revision, Response> {
    state
        .model_events
        .latest_revision(raw_org_id)
        .await
        .map_err(|e| {
            tracing::error!(org_id = %raw_org_id, error = %e, "lifecycle transition: latest_revision failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}

/// `POST /api/v1/organizations/{org_id}/activate` — `Draft` -> `Active`.
#[tracing::instrument(name = "activate_org", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn activate_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
) -> Response {
    transition_handler(LifecycleVerb::Activate, identity, raw_org_id, state).await
}

/// `POST /api/v1/organizations/{org_id}/suspend` — `Active` -> `Suspended`.
#[tracing::instrument(name = "suspend_org", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn suspend_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
) -> Response {
    transition_handler(LifecycleVerb::Suspend, identity, raw_org_id, state).await
}

/// `POST /api/v1/organizations/{org_id}/restore` — `Suspended` -> `Active`.
#[tracing::instrument(name = "restore_org", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn restore_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
) -> Response {
    transition_handler(LifecycleVerb::Restore, identity, raw_org_id, state).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ALL_VERBS: [LifecycleVerb; 3] = [
        LifecycleVerb::Activate,
        LifecycleVerb::Suspend,
        LifecycleVerb::Restore,
    ];
    const ALL_STATUSES: [OrgStatus; 5] = [
        OrgStatus::Draft,
        OrgStatus::Active,
        OrgStatus::Suspended,
        OrgStatus::Deleting,
        OrgStatus::Deleted,
    ];

    #[test]
    fn target_matches_verb() {
        assert!(matches!(
            LifecycleVerb::Activate.target(),
            OrgStatus::Active
        ));
        assert!(matches!(
            LifecycleVerb::Suspend.target(),
            OrgStatus::Suspended
        ));
        assert!(matches!(LifecycleVerb::Restore.target(), OrgStatus::Active));
    }

    #[test]
    fn kind_matches_verb() {
        assert_eq!(LifecycleVerb::Activate.kind(), EventKind::OrgActivated);
        assert_eq!(LifecycleVerb::Suspend.kind(), EventKind::OrgSuspended);
        assert_eq!(LifecycleVerb::Restore.kind(), EventKind::OrgRestored);
    }

    #[test]
    fn valid_from_cross_product() {
        for verb in ALL_VERBS {
            for status in ALL_STATUSES {
                let expected = matches!(
                    (verb, status),
                    (LifecycleVerb::Activate, OrgStatus::Draft)
                        | (LifecycleVerb::Suspend, OrgStatus::Active)
                        | (LifecycleVerb::Restore, OrgStatus::Suspended)
                );
                assert_eq!(
                    verb.valid_from(status),
                    expected,
                    "verb={verb:?} status={status:?}"
                );
            }
        }
    }
}
