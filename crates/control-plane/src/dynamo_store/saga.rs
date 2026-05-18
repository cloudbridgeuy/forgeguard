//! DynamoDB-backed `SagaTicketStore` for the V3 POST /users saga.
//!
//! Backed by the dedicated `forgeguard-{env}-sagas` table (see
//! `infra/control-plane/lib/sagas-stack.ts`). Item layout follows plan §7:
//!
//! - `PK` = `ORG#{org_id}`
//! - `SK` = `SAGA#USER_CREATE#{ticket_id}`
//! - `gsi_pk` / `gsi_sk` — sparse `gsi_in_flight` index, present only while
//!   the saga is non-terminal. Terminal `advance_saga_stage` calls REMOVE
//!   both attributes so the email becomes available for a fresh saga.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::Utc;
use forgeguard_authn_core::saga::{
    SagaStage, SagaStatus, SagaTicket, SagaTicketFromStorage, TicketId,
};
use forgeguard_core::{GroupName, OrganizationId, UserId};

use crate::dynamo_store::{get_s, get_s_opt, map_sdk_error, parse_datetime, pk, sk, ORG_PREFIX};
use crate::error::{Error, Result};
use crate::store::saga::{SagaStageUpdate, SagaTicketStore};

const SK_SAGA_PREFIX: &str = "SAGA#USER_CREATE#";
const GSI_NAME: &str = "gsi_in_flight";

fn saga_pk(org_id: &OrganizationId) -> String {
    format!("{ORG_PREFIX}{org_id}")
}

fn saga_sk(ticket_id: &TicketId) -> String {
    format!("{SK_SAGA_PREFIX}{ticket_id}")
}

fn gsi_pk_value(org_id: &OrganizationId, email: &str) -> String {
    format!("{ORG_PREFIX}{org_id}#EMAIL#{email}")
}

fn gsi_sk_value(ticket_id: &TicketId) -> String {
    format!("TICKET#{ticket_id}")
}

/// Serialize a fresh in-flight ticket into a DynamoDB item map.
///
/// Always writes `gsi_pk`/`gsi_sk` — the caller (`put_saga_ticket`) is the
/// only writer of new rows and rows start non-terminal. Terminal transitions
/// later REMOVE these attributes via `advance_saga_stage`.
pub(crate) fn to_saga_item(ticket: &SagaTicket) -> HashMap<String, AttributeValue> {
    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert(pk().to_owned(), AttributeValue::S(saga_pk(ticket.org_id())));
    item.insert(
        sk().to_owned(),
        AttributeValue::S(saga_sk(ticket.ticket_id())),
    );
    item.insert(
        "ticket_id".to_owned(),
        AttributeValue::S(ticket.ticket_id().to_string()),
    );
    item.insert(
        "org_id".to_owned(),
        AttributeValue::S(ticket.org_id().to_string()),
    );
    item.insert(
        "status".to_owned(),
        AttributeValue::S(ticket.status().to_string()),
    );
    item.insert(
        "current_stage".to_owned(),
        AttributeValue::S(ticket.current_stage().to_string()),
    );
    item.insert(
        "email".to_owned(),
        AttributeValue::S(ticket.email().to_owned()),
    );
    let groups: Vec<AttributeValue> = ticket
        .groups()
        .iter()
        .map(|g| AttributeValue::S(g.to_string()))
        .collect();
    item.insert("groups".to_owned(), AttributeValue::L(groups));
    let attrs: HashMap<String, AttributeValue> = ticket
        .attributes()
        .iter()
        .map(|(k, v)| (k.clone(), AttributeValue::S(v.clone())))
        .collect();
    item.insert("attributes".to_owned(), AttributeValue::M(attrs));
    item.insert(
        "created_at".to_owned(),
        AttributeValue::S(ticket.created_at().to_rfc3339()),
    );
    item.insert(
        "updated_at".to_owned(),
        AttributeValue::S(ticket.updated_at().to_rfc3339()),
    );
    if let Some(sub) = ticket.sub() {
        item.insert("sub".to_owned(), AttributeValue::S(sub.to_string()));
    }
    if let Some(reason) = ticket.failure_reason() {
        item.insert(
            "failure_reason".to_owned(),
            AttributeValue::S(reason.to_owned()),
        );
    }
    item.insert(
        "created_by".to_owned(),
        AttributeValue::S(ticket.created_by().to_string()),
    );
    // Sparse GSI keys — present only while non-terminal. Fresh tickets always
    // start at S1/InFlight, so we unconditionally write them here.
    item.insert(
        "gsi_pk".to_owned(),
        AttributeValue::S(gsi_pk_value(ticket.org_id(), ticket.email())),
    );
    item.insert(
        "gsi_sk".to_owned(),
        AttributeValue::S(gsi_sk_value(ticket.ticket_id())),
    );
    item
}

/// Parse a stored DDB item back into a `SagaTicket`. Raw `AttributeValue` maps
/// never leak past this function (Parse Don't Validate).
pub(crate) fn from_saga_item(item: &HashMap<String, AttributeValue>) -> Result<SagaTicket> {
    let ticket_id = TicketId::try_new(get_s(item, "ticket_id")?)
        .map_err(|e| Error::Store(format!("invalid ticket_id in saga row: {e}")))?;
    let org_id = OrganizationId::new(&get_s(item, "org_id")?)
        .map_err(|e| Error::Store(format!("invalid org_id in saga row: {e}")))?;
    let email = get_s(item, "email")?;
    let status = parse_status(&get_s(item, "status")?)?;
    let current_stage = parse_stage(&get_s(item, "current_stage")?)?;
    let groups = parse_groups(item)?;
    let attributes = parse_attributes(item)?;
    let created_at = parse_datetime(item, "created_at")?;
    let updated_at = parse_datetime(item, "updated_at")?;
    let sub = get_s_opt(item, "sub")
        .map(|raw| {
            UserId::new(&raw).map_err(|e| Error::Store(format!("invalid sub in saga row: {e}")))
        })
        .transpose()?;
    let failure_reason = get_s_opt(item, "failure_reason");
    let created_by = UserId::new(&get_s(item, "created_by")?)
        .map_err(|e| Error::Store(format!("invalid created_by in saga row: {e}")))?;

    Ok(SagaTicket::from(SagaTicketFromStorage {
        ticket_id,
        org_id,
        email,
        status,
        current_stage,
        groups,
        attributes,
        created_at,
        updated_at,
        sub,
        failure_reason,
        created_by,
    }))
}

fn parse_status(raw: &str) -> Result<SagaStatus> {
    match raw {
        "in_flight" => Ok(SagaStatus::InFlight),
        "succeeded" => Ok(SagaStatus::Succeeded),
        "failed" => Ok(SagaStatus::Failed),
        "compensation_failed" => Ok(SagaStatus::CompensationFailed),
        other => Err(Error::Store(format!("invalid saga status: {other}"))),
    }
}

fn parse_stage(raw: &str) -> Result<SagaStage> {
    match raw {
        "S1" => Ok(SagaStage::S1),
        "S2" => Ok(SagaStage::S2),
        "S3" => Ok(SagaStage::S3),
        "done" => Ok(SagaStage::Done),
        "compensating" => Ok(SagaStage::Compensating),
        "failed" => Ok(SagaStage::Failed),
        "compensation_failed" => Ok(SagaStage::CompensationFailed),
        other => Err(Error::Store(format!("invalid saga stage: {other}"))),
    }
}

fn parse_groups(item: &HashMap<String, AttributeValue>) -> Result<Vec<GroupName>> {
    let Some(av) = item.get("groups") else {
        return Err(Error::Store("missing 'groups' attribute".to_owned()));
    };
    let list = av
        .as_l()
        .map_err(|_| Error::Store("'groups' attribute is not a List".to_owned()))?;
    list.iter()
        .map(|v| {
            let s = v
                .as_s()
                .map_err(|_| Error::Store("'groups' entry is not a String".to_owned()))?;
            GroupName::new(s).map_err(|e| Error::Store(format!("invalid group name: {e}")))
        })
        .collect()
}

fn parse_attributes(
    item: &HashMap<String, AttributeValue>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let Some(av) = item.get("attributes") else {
        return Ok(std::collections::BTreeMap::new());
    };
    let map = av
        .as_m()
        .map_err(|_| Error::Store("'attributes' is not a Map".to_owned()))?;
    map.iter()
        .map(|(k, v)| {
            let s = v
                .as_s()
                .map_err(|_| Error::Store(format!("attribute '{k}' is not a String")))?;
            Ok((k.clone(), s.clone()))
        })
        .collect()
}

/// Production `SagaTicketStore` backed by the `forgeguard-{env}-sagas` table.
#[derive(Debug, Clone)]
pub(crate) struct DynamoSagaTicketStore {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoSagaTicketStore {
    pub(crate) fn new(client: aws_sdk_dynamodb::Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

#[async_trait]
impl SagaTicketStore for DynamoSagaTicketStore {
    async fn get_saga_ticket(&self, ticket_id: &TicketId) -> Result<Option<SagaTicket>> {
        // The PK is org-scoped, but `get_saga_ticket` only carries the
        // ticket id. The only known caller (the resume worker in #103) will
        // scan a stream record that includes both keys — for the V3 inline
        // saga driver, `get_saga_ticket` is only used by tests. We fall back
        // to a Scan-and-filter by SK so the contract holds.
        let mut exclusive_start_key = None;
        let target_sk = saga_sk(ticket_id);
        loop {
            let mut req = self
                .client
                .scan()
                .table_name(&self.table_name)
                .filter_expression("#sk = :sk_val")
                .expression_attribute_names("#sk", sk())
                .expression_attribute_values(":sk_val", AttributeValue::S(target_sk.clone()));

            if let Some(key) = exclusive_start_key {
                req = req.set_exclusive_start_key(Some(key));
            }

            let result = req.send().await.map_err(map_sdk_error)?;
            if let Some(items) = result.items {
                if let Some(item) = items.into_iter().next() {
                    return from_saga_item(&item).map(Some);
                }
            }

            match result.last_evaluated_key {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
                _ => return Ok(None),
            }
        }
    }

    async fn put_saga_ticket(&self, ticket: SagaTicket) -> Result<()> {
        let ticket_id = ticket.ticket_id().clone();
        let item = to_saga_item(&ticket);
        match self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(#sk)")
            .expression_attribute_names("#sk", sk())
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(sdk_err) => {
                let is_ccfe = matches!(
                    sdk_err,
                    aws_sdk_dynamodb::error::SdkError::ServiceError(ref e)
                        if e.err().is_conditional_check_failed_exception()
                );
                if is_ccfe {
                    Err(Error::Conflict(format!(
                        "saga ticket '{ticket_id}' already exists"
                    )))
                } else {
                    Err(map_sdk_error(sdk_err))
                }
            }
        }
    }

    async fn find_in_flight_saga_by_email(
        &self,
        org_id: &OrganizationId,
        email: &str,
    ) -> Result<Option<TicketId>> {
        let gsi_pk = gsi_pk_value(org_id, email);
        let result = self
            .client
            .query()
            .table_name(&self.table_name)
            .index_name(GSI_NAME)
            .key_condition_expression("#gsi_pk = :gsi_pk_val")
            .expression_attribute_names("#gsi_pk", "gsi_pk")
            .expression_attribute_values(":gsi_pk_val", AttributeValue::S(gsi_pk))
            .limit(1)
            .send()
            .await
            .map_err(map_sdk_error)?;

        let Some(items) = result.items else {
            return Ok(None);
        };
        let Some(item) = items.into_iter().next() else {
            return Ok(None);
        };
        let raw = get_s(&item, "ticket_id")?;
        TicketId::try_new(raw)
            .map(Some)
            .map_err(|e| Error::Store(format!("invalid ticket_id in gsi_in_flight row: {e}")))
    }

    async fn advance_saga_stage(
        &self,
        ticket_id: &TicketId,
        expected_prev: SagaStage,
        next: SagaStage,
        update_fields: SagaStageUpdate,
    ) -> Result<()> {
        // Locate the row first so the conditional UpdateItem has the full key.
        // The inline runner is the only writer during the request lifetime, so
        // a single Scan here is acceptable; the alternative (carrying org_id
        // through every call) would leak DDB layout into the trait.
        let current = self
            .get_saga_ticket(ticket_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("saga ticket '{ticket_id}' not found")))?;

        let parts = build_advance_update(expected_prev, next, &update_fields);

        let mut req = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key(pk(), AttributeValue::S(saga_pk(current.org_id())))
            .key(sk(), AttributeValue::S(saga_sk(ticket_id)))
            .update_expression(parts.update_expression)
            .condition_expression(parts.condition_expression);
        for (k, v) in parts.names {
            req = req.expression_attribute_names(k, v);
        }
        for (k, v) in parts.values {
            req = req.expression_attribute_values(k, v);
        }

        match req.send().await {
            Ok(_) => Ok(()),
            Err(sdk_err) => {
                let is_ccfe = matches!(
                    sdk_err,
                    aws_sdk_dynamodb::error::SdkError::ServiceError(ref service_err)
                        if service_err.err().is_conditional_check_failed_exception()
                );
                if is_ccfe {
                    Err(Error::Conflict(format!(
                        "saga ticket '{ticket_id}' stage mismatch: expected {expected_prev}"
                    )))
                } else {
                    Err(map_sdk_error(sdk_err))
                }
            }
        }
    }
}

/// Bundled parts of an `UpdateItem` call for `advance_saga_stage`.
struct AdvanceParts {
    update_expression: String,
    condition_expression: String,
    names: Vec<(&'static str, &'static str)>,
    values: Vec<(&'static str, AttributeValue)>,
}

/// Build the `UpdateItem` parts for a single stage transition.
///
/// Always updates `current_stage` and `updated_at`. Optionally sets `sub`,
/// `status`, and `failure_reason` from `update_fields`. Terminal transitions
/// (`next.is_terminal()`) add `REMOVE gsi_pk, gsi_sk` so the sparse
/// `gsi_in_flight` index entry disappears immediately.
fn build_advance_update(
    expected_prev: SagaStage,
    next: SagaStage,
    update_fields: &SagaStageUpdate,
) -> AdvanceParts {
    let mut sets: Vec<&'static str> = vec!["#current_stage = :next_stage", "#updated_at = :now"];
    let mut names: Vec<(&'static str, &'static str)> = vec![
        ("#current_stage", "current_stage"),
        ("#updated_at", "updated_at"),
    ];
    let mut values: Vec<(&'static str, AttributeValue)> = vec![
        (":next_stage", AttributeValue::S(next.to_string())),
        (":now", AttributeValue::S(Utc::now().to_rfc3339())),
        (
            ":expected_prev",
            AttributeValue::S(expected_prev.to_string()),
        ),
    ];

    if let Some(sub) = &update_fields.sub {
        sets.push("#sub = :sub_val");
        names.push(("#sub", "sub"));
        values.push((":sub_val", AttributeValue::S(sub.to_string())));
    }
    if let Some(status) = update_fields.status {
        sets.push("#status = :status_val");
        names.push(("#status", "status"));
        values.push((":status_val", AttributeValue::S(status.to_string())));
    }
    if let Some(reason) = &update_fields.failure_reason {
        sets.push("#failure_reason = :failure_reason_val");
        names.push(("#failure_reason", "failure_reason"));
        values.push((":failure_reason_val", AttributeValue::S(reason.clone())));
    }

    let mut expression = format!("SET {}", sets.join(", "));
    if next.is_terminal() {
        expression.push_str(" REMOVE #gsi_pk, #gsi_sk");
        names.push(("#gsi_pk", "gsi_pk"));
        names.push(("#gsi_sk", "gsi_sk"));
    }

    AdvanceParts {
        update_expression: expression,
        condition_expression: "#current_stage = :expected_prev".to_owned(),
        names,
        values,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};
    use forgeguard_authn_core::saga::{SagaTicket, SagaTicketParams};
    use forgeguard_core::{GroupName, OrganizationId, UserId};

    use super::*;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ticket() -> SagaTicket {
        let mut attrs = BTreeMap::new();
        attrs.insert("custom:role".to_owned(), "engineer".to_owned());
        SagaTicket::new(SagaTicketParams {
            ticket_id: TicketId::generate(),
            org_id: OrganizationId::new("acme").unwrap(),
            email: "alice@example.com".to_owned(),
            groups: vec![GroupName::new("admin").unwrap()],
            attributes: attrs,
            created_at: ts(),
            created_by: UserId::new("admin-sub").unwrap(),
        })
    }

    #[test]
    fn to_item_writes_required_keys_and_gsi() {
        let t = ticket();
        let item = to_saga_item(&t);

        assert_eq!(
            item.get(pk()).and_then(|v| v.as_s().ok()),
            Some(&"ORG#acme".to_owned())
        );
        assert!(item
            .get(sk())
            .and_then(|v| v.as_s().ok())
            .unwrap()
            .starts_with("SAGA#USER_CREATE#"));
        assert_eq!(
            item.get("status").and_then(|v| v.as_s().ok()),
            Some(&"in_flight".to_owned())
        );
        assert_eq!(
            item.get("current_stage").and_then(|v| v.as_s().ok()),
            Some(&"S1".to_owned())
        );
        assert!(item.contains_key("gsi_pk"));
        assert!(item.contains_key("gsi_sk"));
        assert_eq!(
            item.get("gsi_pk").and_then(|v| v.as_s().ok()),
            Some(&"ORG#acme#EMAIL#alice@example.com".to_owned())
        );
    }

    #[test]
    fn to_item_writes_groups_as_list_even_when_empty() {
        let mut t = ticket();
        // Rebuild with empty groups (the constructor takes a Vec).
        t = SagaTicket::new(SagaTicketParams {
            ticket_id: t.ticket_id().clone(),
            org_id: t.org_id().clone(),
            email: t.email().to_owned(),
            groups: vec![],
            attributes: t.attributes().clone(),
            created_at: t.created_at(),
            created_by: t.created_by().clone(),
        });
        let item = to_saga_item(&t);
        let list = item.get("groups").unwrap().as_l().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn to_item_then_from_item_roundtrips() {
        let original = ticket();
        let item = to_saga_item(&original);
        let parsed = from_saga_item(&item).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn advance_to_s2_only_updates_stage_and_timestamp() {
        let parts = build_advance_update(SagaStage::S1, SagaStage::S2, &SagaStageUpdate::default());
        assert!(parts.update_expression.starts_with("SET "));
        assert!(parts
            .update_expression
            .contains("#current_stage = :next_stage"));
        assert!(parts.update_expression.contains("#updated_at = :now"));
        assert!(!parts.update_expression.contains("REMOVE"));
        assert_eq!(
            parts.condition_expression,
            "#current_stage = :expected_prev"
        );
    }

    #[test]
    fn advance_to_s3_writes_sub() {
        let parts = build_advance_update(
            SagaStage::S2,
            SagaStage::S3,
            &SagaStageUpdate {
                sub: Some(UserId::new("cognito-sub").unwrap()),
                ..SagaStageUpdate::default()
            },
        );
        assert!(parts.update_expression.contains("#sub = :sub_val"));
        assert!(!parts.update_expression.contains("REMOVE"));
    }

    #[test]
    fn advance_to_done_removes_gsi_attrs_and_sets_status() {
        let parts = build_advance_update(
            SagaStage::S3,
            SagaStage::Done,
            &SagaStageUpdate {
                status: Some(SagaStatus::Succeeded),
                ..SagaStageUpdate::default()
            },
        );
        assert!(parts.update_expression.contains("REMOVE #gsi_pk, #gsi_sk"));
        assert!(parts.update_expression.contains("#status = :status_val"));
        assert!(parts
            .names
            .iter()
            .any(|(placeholder, _)| *placeholder == "#gsi_pk"));
        assert!(parts
            .names
            .iter()
            .any(|(placeholder, _)| *placeholder == "#gsi_sk"));
    }

    #[test]
    fn advance_to_compensation_failed_removes_gsi_attrs_and_records_reason() {
        let parts = build_advance_update(
            SagaStage::Compensating,
            SagaStage::CompensationFailed,
            &SagaStageUpdate {
                status: Some(SagaStatus::CompensationFailed),
                failure_reason: Some("c2 timed out".to_owned()),
                ..SagaStageUpdate::default()
            },
        );
        assert!(parts.update_expression.contains("REMOVE #gsi_pk, #gsi_sk"));
        assert!(parts
            .update_expression
            .contains("#failure_reason = :failure_reason_val"));
        assert!(parts
            .values
            .iter()
            .any(|(placeholder, v)| *placeholder == ":failure_reason_val"
                && v.as_s().map(std::string::String::as_str) == Ok("c2 timed out")));
    }

    #[test]
    fn parse_status_rejects_garbage() {
        assert!(parse_status("nope").is_err());
    }

    #[test]
    fn parse_stage_rejects_garbage() {
        assert!(parse_stage("S99").is_err());
    }
}
