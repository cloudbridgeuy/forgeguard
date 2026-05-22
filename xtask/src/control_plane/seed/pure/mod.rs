//! Pure functional core for the seed command.
//!
//! Every helper here is deterministic — no `await`, no `Utc::now()` (callers
//! pass `now`), no AWS calls, no filesystem.
//!
//! ## V5 invariant
//! `seed_org_to_status_attr` returns `"draft"` unconditionally. Active-org
//! provisioning lives in the saga ticket (separate from #102) — the seed
//! never produces an Active row.

use std::collections::BTreeMap;

use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use forgeguard_authn_core::{
    AttrType, CustomAttrName, CustomAttrSpec, RawAttrMap, StandardAttrName, StandardAttrSpec,
    UserSchema,
};
use forgeguard_authz_core::rbac::{validate_group_name, CYCLE_PREFIX};
use forgeguard_authz_core::{resolve_inherits, RbacEntry};

use crate::control_plane::schema::orgs_schema;
use crate::control_plane::seed_core::{SeedGroup, SeedOrg, SeedUser, SeedUserSchema};

/// Group sort-key prefix in DynamoDB. Mirrors the V2 codepath in
/// `crates/control-plane/src/handlers/groups/codec.rs::SK_GROUP_PREFIX`.
const SK_GROUP_PREFIX: &str = "GROUP#";

pub(crate) fn seed_org_to_status_attr() -> &'static str {
    "draft"
}

/// Default proxy `OrgConfig` JSON for a seeded org.
///
/// Matches the shape `forgeguard_control_plane::config::OrgConfig` deserialises;
/// `vp_store_id` and `cognito_user_pool_id` are deliberately absent because
/// every seeded org is Draft.
pub(crate) fn seed_org_to_org_config_json(_org_id: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "2026-04-07",
        "project_id": "seed-test",
        "upstream_url": "http://localhost:8080",
        "default_policy": "deny",
        "namespace": "app",
        "tenant": {
            "enabled": true,
            "principal_attribute": "tenant_id",
            "resource_attribute": "tenant_id",
        },
    })
}

/// Build the full DynamoDB attribute list for a seeded org row.
///
/// PK / SK come from `orgs_schema()` so this stays the single source of truth
/// for key shape — no parallel string template to drift against the schema.
pub(crate) fn seed_org_to_dynamodb_attrs(
    org: &SeedOrg,
    now: DateTime<Utc>,
) -> Result<Vec<(String, AttributeValue)>, String> {
    let schema = orgs_schema();
    let org_type = schema
        .item_types
        .get("org")
        .ok_or_else(|| "orgs_schema missing 'org' item type".to_owned())?;
    let pk_value = org_type.pk.replace("{org_id}", org.org_id());
    let sk_value = org_type.sk.clone();
    let now_rfc = now.to_rfc3339();
    let config_json = serde_json::to_string(&seed_org_to_org_config_json(org.org_id()))
        .map_err(|e| format!("serialize org config: {e}"))?;
    let etag = format!("\"{:016x}\"", 0u64);

    Ok(vec![
        (schema.partition_key.clone(), AttributeValue::S(pk_value)),
        (schema.sort_key.clone(), AttributeValue::S(sk_value)),
        ("name".to_owned(), AttributeValue::S(org.name().to_owned())),
        (
            "status".to_owned(),
            AttributeValue::S(seed_org_to_status_attr().to_owned()),
        ),
        ("created_at".to_owned(), AttributeValue::S(now_rfc.clone())),
        ("updated_at".to_owned(), AttributeValue::S(now_rfc)),
        ("config".to_owned(), AttributeValue::S(config_json)),
        ("etag".to_owned(), AttributeValue::S(etag)),
    ])
}

/// Errors surfaced when converting `[SeedGroup]` into validated `[RbacEntry]`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SeedGroupConversionError {
    #[error("group '{group}' inherits unknown role '{parent}'")]
    DanglingInherit { group: String, parent: String },
    #[error("group inheritance cycle: {0}")]
    Cycle(String),
    #[error("group '{group}' has invalid name: {reason}")]
    InvalidName { group: String, reason: String },
}

/// Mechanically copy `SeedGroup` rows into the canonical `RbacEntry` shape.
pub(crate) fn seed_groups_to_rbac_entries(groups: &[SeedGroup]) -> Vec<RbacEntry> {
    groups
        .iter()
        .map(|g| RbacEntry {
            name: g.name().to_owned(),
            description: g.description().map(str::to_owned),
            inherits: g.inherits().to_vec(),
            allow: g.allow().to_vec(),
            tenant_scoped: g.tenant_scoped(),
        })
        .collect()
}

/// Validate name regex + inheritance graph for every entry. Translates the
/// `String` errors from `resolve_inherits` into a typed ADT so the orchestrator
/// can pattern-match without parsing prose.
pub(crate) fn validate_seed_groups(entries: &[RbacEntry]) -> Result<(), SeedGroupConversionError> {
    for entry in entries {
        validate_group_name(&entry.name).map_err(|e| SeedGroupConversionError::InvalidName {
            group: entry.name.clone(),
            reason: e.to_string(),
        })?;
    }
    for entry in entries {
        resolve_inherits(entries, &entry.name)
            .map_err(|msg| classify_resolve_err(&entry.name, &msg))?;
    }
    Ok(())
}

fn classify_resolve_err(group: &str, msg: &str) -> SeedGroupConversionError {
    if msg.starts_with(CYCLE_PREFIX) {
        SeedGroupConversionError::Cycle(msg.to_owned())
    } else if let Some(parent) = parse_dangling_parent(msg) {
        SeedGroupConversionError::DanglingInherit {
            group: group.to_owned(),
            parent,
        }
    } else {
        SeedGroupConversionError::DanglingInherit {
            group: group.to_owned(),
            parent: msg.to_owned(),
        }
    }
}

fn parse_dangling_parent(msg: &str) -> Option<String> {
    let start = msg.find('\'')? + 1;
    let rest = &msg[start..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_owned())
}

/// Build the DynamoDB attribute list for a seeded group row.
///
/// Mirrors the V2 codec in `crates/control-plane/src/handlers/groups/codec.rs`:
/// `{PK = ORG#<org_id>, SK = GROUP#<name>, config = <RbacEntry as JSON>, etag}`.
/// Timestamps are intentionally absent — the V2 codec does not store them on
/// group rows, so the seed must not either or `from_group_item` would reject
/// the row.
pub(crate) fn seed_group_to_dynamodb_attrs(
    org_id: &str,
    entry: &RbacEntry,
    etag: &str,
    _now: DateTime<Utc>,
) -> Result<Vec<(String, AttributeValue)>, String> {
    let schema = orgs_schema();
    let config_json =
        serde_json::to_string(entry).map_err(|e| format!("serialize group entry: {e}"))?;

    Ok(vec![
        (
            schema.partition_key.clone(),
            AttributeValue::S(format!("ORG#{org_id}")),
        ),
        (
            schema.sort_key.clone(),
            AttributeValue::S(format!("{SK_GROUP_PREFIX}{}", entry.name)),
        ),
        ("config".to_owned(), AttributeValue::S(config_json)),
        ("etag".to_owned(), AttributeValue::S(etag.to_owned())),
    ])
}

/// Compute a deterministic ETag for an `RbacEntry`.
///
/// Same recipe as `crates/control-plane/src/handlers/groups/pure.rs::compute_group_etag`:
/// `xxh64` of the canonical-JSON bytes, formatted as `"<16-hex>"`. Seeded rows
/// must round-trip cleanly through a CP `If-Match` check after seed.
pub(crate) fn compute_group_etag(entry: &RbacEntry) -> Result<String, String> {
    let json = serde_json::to_string(entry).map_err(|e| format!("etag serial: {e}"))?;
    let hash = xxhash_rust::xxh64::xxh64(json.as_bytes(), 0);
    Ok(format!("\"{hash:016x}\""))
}

/// Errors surfaced when converting a `SeedUserSchema` into the domain
/// `UserSchema`. The TOML keys are raw strings, so a malformed `seed.toml`
/// schema is caught here — before any AWS call — same as `validate_seed_groups`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SeedSchemaConversionError {
    #[error("standard attribute '{name}' is not a recognised Cognito attribute: {reason}")]
    InvalidStandardAttr { name: String, reason: String },
    #[error("custom attribute '{name}' has an invalid name: {reason}")]
    InvalidCustomAttr { name: String, reason: String },
}

/// Convert a `SeedUserSchema` (TOML repr) into the domain `UserSchema`.
///
/// Standard keys must name one of the 15 recognised Cognito standard
/// attributes; custom keys must satisfy `CustomAttrName`. `seed.toml` carries
/// only a `required` flag per attribute, so custom attrs map to an unbounded
/// `AttrType::String` (no `min_length` / `max_length`).
pub(crate) fn seed_user_schema_to_domain(
    s: &SeedUserSchema,
) -> Result<UserSchema, SeedSchemaConversionError> {
    let mut standard = BTreeMap::new();
    for (name, spec) in s.standard() {
        let attr = name.parse::<StandardAttrName>().map_err(|e| {
            SeedSchemaConversionError::InvalidStandardAttr {
                name: name.clone(),
                reason: e.to_string(),
            }
        })?;
        standard.insert(
            attr,
            StandardAttrSpec {
                required: spec.required(),
            },
        );
    }

    let mut custom = BTreeMap::new();
    for (name, spec) in s.custom() {
        let attr = CustomAttrName::try_new(name.clone()).map_err(|e| {
            SeedSchemaConversionError::InvalidCustomAttr {
                name: name.clone(),
                reason: e.to_string(),
            }
        })?;
        custom.insert(
            attr,
            CustomAttrSpec {
                ty: AttrType::String {
                    min_length: None,
                    max_length: None,
                    required: spec.required(),
                },
            },
        );
    }

    Ok(UserSchema::new(standard, custom))
}

/// Clone a seeded user's declared attributes into the owned `RawAttrMap`
/// that `validate_attributes` and the downstream Cognito call both consume.
/// Thin, but names the TOML→domain boundary explicitly so the
/// `seed/users.rs` call site reads clearly.
pub(crate) fn seed_user_attrs_to_domain(user: &SeedUser) -> RawAttrMap {
    user.attributes().clone()
}

/// A non-empty, validated set of seeded org IDs. Used by the teardown shell to
/// scope its Cognito / VP cleanup to the orgs the seed actually owns.
#[derive(Debug, Clone)]
pub(crate) struct SeededOrgScope {
    org_ids: Vec<String>,
}

impl SeededOrgScope {
    pub(crate) fn new(org_ids: Vec<String>) -> Result<Self, String> {
        if org_ids.is_empty() {
            return Err("SeededOrgScope must contain at least one org_id".to_owned());
        }
        Ok(Self { org_ids })
    }

    pub(crate) fn org_ids(&self) -> &[String] {
        &self.org_ids
    }
}

/// Match the V5 seeded-username pattern: `{org_id}-*` for any org in `scope`.
///
/// Intentionally narrow — does **not** recognise the V0 shape (`acme-admin`
/// without the `org-` prefix). Operators clean those up by hand.
pub(crate) fn is_seeded_username(username: &str, scope: &SeededOrgScope) -> bool {
    scope
        .org_ids()
        .iter()
        .any(|org_id| username.starts_with(&format!("{org_id}-")))
}

/// Membership-row partition key for a Cognito sub.
pub(crate) fn membership_pk_for_user(sub: &str) -> String {
    format!("USER#{sub}")
}

/// Decode the canonical policy name from a VP `description` field that uses
/// the shared `[name] description` encoding produced by
/// `forgeguard_control_plane::vp_client::encode_name_in_description`.
///
/// Returns `None` when the description is missing or does not start with the
/// `[name]` prefix. Mirrored here (instead of imported) because the CP crate
/// is an I/O crate and xtask only consumes pure leaves.
pub(crate) fn decode_policy_name(description: Option<&str>) -> Option<String> {
    let desc = description?;
    let rest = desc.strip_prefix('[')?;
    let end = rest.find(']')?;
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

/// Return `true` when `description` identifies a V0 `cp-rbac-{org}-{role}`
/// policy that belongs to one of the orgs in `scope`.
///
/// Conservative: requires the description's encoded name to start with
/// `cp-rbac-` AND the org-id segment to be in `scope`, AND a non-empty role
/// suffix. Hand-authored policies and ambiguous names are left untouched.
pub(crate) fn is_seeded_cp_rbac_policy(description: Option<&str>, scope: &SeededOrgScope) -> bool {
    let Some(name) = decode_policy_name(description) else {
        return false;
    };
    let Some(rest) = name.strip_prefix("cp-rbac-") else {
        return false;
    };
    scope.org_ids().iter().any(|org_id| {
        rest.strip_prefix(&format!("{org_id}-"))
            .is_some_and(|role| !role.is_empty())
    })
}

#[cfg(test)]
mod tests;
