//! `DynamoModelEventStore`'s group-write methods (#113 V4, Task 3) — split
//! out of `mod.rs` to keep that file under the 1000-line cap. A child module
//! of `model_event_store`, so it can reach `DynamoModelEventStore`'s private
//! fields/methods the same way `mod.rs`'s own impl blocks do.

use aws_sdk_dynamodb::types::AttributeValue;
use forgeguard_authz_core::{
    decide_upsert, group_deleted_payload, group_put_payload, Actor, EventKind, RbacEntry, Revision,
    UpsertDecision,
};
use forgeguard_core::OrganizationId;

use crate::dynamo_store::{map_sdk_error, pk, sk};
use crate::error::{Error, Result};
use crate::event_log::{DynamoEventLog, StateDelete, StateGuard, StatePut};
use crate::handlers::groups::codec::{from_group_item, group_pk, group_sk, to_group_item};
use crate::store::groups::EtagedGroup;

use super::support::{build_model_event, BuildModelEventParams};
use super::{DynamoModelEventStore, GroupWriteOutcome, ModelEventStore};

impl DynamoModelEventStore {
    /// Consistent-read fetch of the `GROUP#{name}` item, shared by
    /// `put_group_impl`/`delete_group_impl`.
    async fn get_group_item(
        &self,
        org_id_typed: &OrganizationId,
        name: &str,
    ) -> Result<Option<std::collections::HashMap<String, AttributeValue>>> {
        Ok(self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(group_pk(org_id_typed)))
            .key(sk(), AttributeValue::S(group_sk(name)))
            .consistent_read(true)
            .send()
            .await
            .map_err(map_sdk_error)?
            .item)
    }

    /// [`super::ModelEventStore::put_group`]'s body — see that trait method's
    /// doc for the D5/D6 contract.
    ///
    /// No HTTP route reaches this yet — wired in Task 4, hence `dead_code`,
    /// same precedent as `put_promotion`.
    #[allow(dead_code)]
    pub(super) async fn put_group_impl(
        &self,
        org_id: &str,
        entry: RbacEntry,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<GroupWriteOutcome> {
        let org_id_typed = OrganizationId::new(org_id)
            .map_err(|e| Error::Store(format!("invalid org_id '{org_id}': {e}")))?;
        let name = entry.name.clone();

        let existing_item = self.get_group_item(&org_id_typed, &name).await?;
        let existing_value = existing_item
            .as_ref()
            .map(from_group_item)
            .transpose()?
            .map(|(existing_entry, _etag)| serde_json::to_value(&existing_entry))
            .transpose()
            .map_err(|e| Error::Store(format!("serialize existing group entry: {e}")))?;

        let new_value = serde_json::to_value(&entry)
            .map_err(|e| Error::Store(format!("serialize group entry: {e}")))?;

        match decide_upsert(existing_value.as_ref(), &new_value) {
            UpsertDecision::NoOp => {
                let current = self.latest_revision(org_id).await?;
                Ok(GroupWriteOutcome::NoOp { current })
            }
            UpsertDecision::Changed { payload } => {
                let etaged = EtagedGroup::compute(entry)?;
                let mut attributes =
                    to_group_item(&org_id_typed, etaged.entry(), etaged.etag().as_str())?;
                attributes.remove(pk());
                attributes.remove(sk());

                let (signing_key, key_id) = self.ensure_signing_key(org_id).await?;
                let occurred_at = chrono::Utc::now().to_rfc3339();
                let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);

                let org_id_owned = org_id.to_string();
                let event_payload = group_put_payload(&name, &payload);
                let build = move |revision: Revision| {
                    build_model_event(BuildModelEventParams {
                        org_id: &org_id_owned,
                        kind: EventKind::GroupPut,
                        actor: actor.clone(),
                        payload: event_payload.clone(),
                        signing_key: &signing_key,
                        key_id: &key_id,
                        occurred_at: &occurred_at,
                        revision,
                    })
                };

                let state = StatePut {
                    pk: group_pk(&org_id_typed),
                    sk: group_sk(&name),
                    attributes,
                    guard: StateGuard::None,
                };

                let revision = log.append(expected_revision, build, state).await?;
                Ok(GroupWriteOutcome::Applied { revision })
            }
        }
    }

    /// [`super::ModelEventStore::delete_group`]'s body — see that trait
    /// method's doc for the D5/D6 contract.
    ///
    /// No HTTP route reaches this yet — wired in Task 4, hence `dead_code`,
    /// same precedent as `put_promotion`.
    #[allow(dead_code)]
    pub(super) async fn delete_group_impl(
        &self,
        org_id: &str,
        name: &str,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<GroupWriteOutcome> {
        let org_id_typed = OrganizationId::new(org_id)
            .map_err(|e| Error::Store(format!("invalid org_id '{org_id}': {e}")))?;

        let existing_item = self.get_group_item(&org_id_typed, name).await?;
        if existing_item.is_none() {
            let current = self.latest_revision(org_id).await?;
            return Ok(GroupWriteOutcome::NoOp { current });
        }

        let (signing_key, key_id) = self.ensure_signing_key(org_id).await?;
        let occurred_at = chrono::Utc::now().to_rfc3339();
        let log = DynamoEventLog::new(self.client.clone(), self.table_name.clone(), org_id);

        let org_id_owned = org_id.to_string();
        let event_payload = group_deleted_payload(name);
        let build = move |revision: Revision| {
            build_model_event(BuildModelEventParams {
                org_id: &org_id_owned,
                kind: EventKind::GroupDeleted,
                actor: actor.clone(),
                payload: event_payload.clone(),
                signing_key: &signing_key,
                key_id: &key_id,
                occurred_at: &occurred_at,
                revision,
            })
        };

        let state = StateDelete {
            pk: group_pk(&org_id_typed),
            sk: group_sk(name),
        };

        match log
            .append_with_delete(expected_revision, build, state)
            .await?
        {
            Some(revision) => Ok(GroupWriteOutcome::Applied { revision }),
            // Lost the race — a concurrent delete already won (D6/D7:
            // idempotent no-op, nothing appended).
            None => {
                let current = self.latest_revision(org_id).await?;
                Ok(GroupWriteOutcome::NoOp { current })
            }
        }
    }
}
