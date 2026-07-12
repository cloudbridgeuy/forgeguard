#![allow(clippy::unwrap_used)]

use forgeguard_authn_core::{validate_attributes, FieldErrorKind, RawAttrMap};

use super::*;
use crate::control_plane::seed_core::SeedOrg;

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-05-07T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn parse_seed_org(toml_str: &str) -> SeedOrg {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        organization: Vec<SeedOrg>,
    }
    let mut w: Wrapper = toml::from_str(toml_str).unwrap();
    w.organization.remove(0)
}

#[test]
fn seed_org_to_status_attr_is_draft() {
    assert_eq!(seed_org_to_status_attr(), "draft");
}

#[test]
fn seed_org_to_org_config_json_round_trips_through_serde() {
    let v = seed_org_to_org_config_json("org-acme");
    assert_eq!(v["version"], "2026-04-07");
    assert_eq!(v["project_id"], "seed-test");
    assert_eq!(v["default_policy"], "deny");
    assert_eq!(v["tenant"]["principal_attribute"], "tenant_id");
    assert!(v.get("vp_store_id").is_none());
}

#[test]
fn seed_org_to_dynamodb_attrs_byte_stable() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id = "org-acme"
name = "Acme Corp"
cognito_user_pool_id = "us-east-2_acme"
"#,
    );
    let attrs = seed_org_to_dynamodb_attrs(&org, fixed_now()).unwrap();
    let by_key: std::collections::HashMap<_, _> = attrs.into_iter().collect();
    assert_eq!(by_key["PK"].as_s().unwrap(), "ORG#org-acme");
    assert_eq!(by_key["SK"].as_s().unwrap(), "META");
    assert_eq!(by_key["status"].as_s().unwrap(), "draft");
    assert_eq!(
        by_key["created_at"].as_s().unwrap(),
        "2026-05-07T12:00:00+00:00"
    );
    assert_eq!(by_key["etag"].as_s().unwrap(), "\"0000000000000000\"");
}

fn group_fixture() -> Vec<RbacEntry> {
    seed_groups_to_rbac_entries(
        parse_seed_org(
            r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[[organization.group]]
name = "member"
allow = ["cp-organization-read"]

[[organization.group]]
name = "admin"
inherits = ["member"]
allow = ["cp-organization-update"]
"#,
        )
        .groups(),
    )
}

#[test]
fn seed_groups_to_rbac_entries_preserves_field_order_and_defaults() {
    let entries = group_fixture();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "member");
    assert_eq!(entries[0].allow, ["cp-organization-read"]);
    assert!(entries[0].inherits.is_empty());
    assert!(entries[0].tenant_scoped, "default propagates");
    assert_eq!(entries[1].inherits, ["member"]);
}

#[test]
fn validate_seed_groups_happy_path() {
    let entries = group_fixture();
    validate_seed_groups(&entries).unwrap();
}

#[test]
fn validate_seed_groups_dangling_inherit() {
    let entries = vec![RbacEntry {
        name: "broken".to_owned(),
        description: None,
        inherits: vec!["nonexistent".to_owned()],
        allow: vec!["x".to_owned()],
        tenant_scoped: true,
    }];
    let err = validate_seed_groups(&entries).unwrap_err();
    match err {
        SeedGroupConversionError::DanglingInherit { group, parent } => {
            assert_eq!(group, "broken");
            assert_eq!(parent, "nonexistent");
        }
        other => panic!("expected DanglingInherit, got {other:?}"),
    }
}

#[test]
fn validate_seed_groups_cycle() {
    let entries = vec![
        RbacEntry {
            name: "a".to_owned(),
            description: None,
            inherits: vec!["b".to_owned()],
            allow: vec!["x".to_owned()],
            tenant_scoped: true,
        },
        RbacEntry {
            name: "b".to_owned(),
            description: None,
            inherits: vec!["a".to_owned()],
            allow: vec!["y".to_owned()],
            tenant_scoped: true,
        },
    ];
    let err = validate_seed_groups(&entries).unwrap_err();
    assert!(
        matches!(err, SeedGroupConversionError::Cycle(_)),
        "expected Cycle, got {err:?}"
    );
}

#[test]
fn validate_seed_groups_invalid_name() {
    let entries = vec![RbacEntry {
        name: "Bad-Name".to_owned(),
        description: None,
        inherits: vec![],
        allow: vec!["x".to_owned()],
        tenant_scoped: true,
    }];
    let err = validate_seed_groups(&entries).unwrap_err();
    match err {
        SeedGroupConversionError::InvalidName { group, .. } => {
            assert_eq!(group, "Bad-Name");
        }
        other => panic!("expected InvalidName, got {other:?}"),
    }
}

#[test]
fn seed_group_to_dynamodb_attrs_uses_v2_shape() {
    let entry = RbacEntry {
        name: "admin".to_owned(),
        description: Some("Admin role".to_owned()),
        inherits: vec!["member".to_owned()],
        allow: vec!["cp-organization-update".to_owned()],
        tenant_scoped: true,
    };
    let etag = compute_group_etag(&entry).unwrap();
    let attrs = seed_group_to_dynamodb_attrs("org-acme", &entry, &etag, fixed_now()).unwrap();
    let by_key: std::collections::HashMap<_, _> = attrs.into_iter().collect();
    assert_eq!(by_key["PK"].as_s().unwrap(), "ORG#org-acme");
    assert_eq!(by_key["SK"].as_s().unwrap(), "GROUP#admin");
    assert_eq!(by_key["etag"].as_s().unwrap(), &etag);

    let recovered: RbacEntry = serde_json::from_str(by_key["config"].as_s().unwrap()).unwrap();
    assert_eq!(recovered.name, entry.name);
    assert_eq!(recovered.allow, entry.allow);
    assert_eq!(recovered.inherits, entry.inherits);
}

#[test]
fn compute_group_etag_format_and_determinism() {
    let entry = RbacEntry {
        name: "member".to_owned(),
        description: None,
        inherits: vec![],
        allow: vec!["cp-organization-read".to_owned()],
        tenant_scoped: true,
    };
    let etag1 = compute_group_etag(&entry).unwrap();
    let etag2 = compute_group_etag(&entry).unwrap();
    assert_eq!(etag1, etag2);
    assert_eq!(etag1.len(), 18, "etag={etag1:?}");
    assert!(etag1.starts_with('"') && etag1.ends_with('"'));
}

#[test]
fn compute_group_etag_golden_value_matches_cp_recipe() {
    // Golden cross-crate anchor: the CP-side `compute_group_etag` in
    // `crates/control-plane/src/handlers/groups/pure.rs` uses the same
    // serde_json + xxh64 recipe. If field order or seed convention drifts,
    // this assertion catches it before seeded rows fail an `If-Match` round-trip.
    let entry = RbacEntry {
        name: "member".to_owned(),
        description: None,
        inherits: vec![],
        allow: vec!["cp-organization-read".to_owned()],
        tenant_scoped: true,
    };
    let etag = compute_group_etag(&entry).unwrap();
    let json = serde_json::to_string(&entry).unwrap();
    let expected = format!("\"{:016x}\"", xxhash_rust::xxh64::xxh64(json.as_bytes(), 0));
    assert_eq!(etag, expected);
}

fn scope() -> SeededOrgScope {
    SeededOrgScope::new(vec!["org-acme".to_owned(), "org-globex".to_owned()]).unwrap()
}

#[test]
fn is_seeded_username_matches_org_prefix() {
    assert!(is_seeded_username("org-acme-admin", &scope()));
    assert!(is_seeded_username("org-globex-member", &scope()));
}

#[test]
fn is_seeded_username_rejects_v0_shape() {
    assert!(!is_seeded_username("acme-admin", &scope()));
}

#[test]
fn is_seeded_username_rejects_unrelated_orgs() {
    assert!(!is_seeded_username("org-other-admin", &scope()));
}

#[test]
fn membership_pk_for_user_format() {
    assert_eq!(membership_pk_for_user("abc-123"), "USER#abc-123");
}

#[test]
fn seeded_org_scope_rejects_empty() {
    let err = SeededOrgScope::new(vec![]).unwrap_err();
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn seeded_org_scope_accepts_single_org() {
    let s = SeededOrgScope::new(vec!["org-acme".to_owned()]).unwrap();
    assert_eq!(s.org_ids(), &["org-acme"]);
}

#[test]
fn seeded_org_scope_accepts_two_orgs() {
    let s = scope();
    assert_eq!(s.org_ids(), &["org-acme", "org-globex"]);
}

#[test]
fn decode_policy_name_round_trips_encoded_description() {
    assert_eq!(
        decode_policy_name(Some("[cp-rbac-org-acme-admin] Admin role")).as_deref(),
        Some("cp-rbac-org-acme-admin")
    );
    assert_eq!(
        decode_policy_name(Some("[cp-rbac-org-acme-admin]")).as_deref(),
        Some("cp-rbac-org-acme-admin")
    );
}

#[test]
fn decode_policy_name_rejects_raw_or_missing_prefix() {
    assert!(decode_policy_name(None).is_none());
    assert!(decode_policy_name(Some("cp-rbac-admin")).is_none());
    assert!(decode_policy_name(Some("[]")).is_none());
}

#[test]
fn is_seeded_cp_rbac_policy_matches_org_in_scope() {
    assert!(is_seeded_cp_rbac_policy(
        Some("[cp-rbac-org-acme-admin] Admin role"),
        &scope()
    ));
    assert!(is_seeded_cp_rbac_policy(
        Some("[cp-rbac-org-globex-member]"),
        &scope()
    ));
}

#[test]
fn is_seeded_cp_rbac_policy_rejects_unknown_org() {
    assert!(!is_seeded_cp_rbac_policy(
        Some("[cp-rbac-org-other-admin]"),
        &scope()
    ));
}

#[test]
fn is_seeded_cp_rbac_policy_rejects_non_rbac_prefix() {
    assert!(!is_seeded_cp_rbac_policy(
        Some("[cp-organization-read]"),
        &scope()
    ));
}

#[test]
fn is_seeded_cp_rbac_policy_rejects_missing_description() {
    assert!(!is_seeded_cp_rbac_policy(None, &scope()));
}

#[test]
fn is_seeded_cp_rbac_policy_rejects_empty_role_suffix() {
    assert!(!is_seeded_cp_rbac_policy(
        Some("[cp-rbac-org-acme-]"),
        &scope()
    ));
    assert!(!is_seeded_cp_rbac_policy(
        Some("[cp-rbac-org-acme]"),
        &scope()
    ));
}

#[test]
fn is_seeded_cp_rbac_policy_rejects_unencoded_name() {
    assert!(!is_seeded_cp_rbac_policy(
        Some("cp-rbac-org-acme-admin"),
        &scope()
    ));
}

// -- user schema row + etag ------------------------------------------------

fn user_schema_fixture() -> UserSchema {
    let mut standard = std::collections::BTreeMap::new();
    standard.insert(StandardAttrName::Name, StandardAttrSpec { required: true });
    UserSchema::new(standard, std::collections::BTreeMap::new())
}

#[test]
fn user_schema_to_dynamodb_attrs_uses_v2_shape() {
    let schema = user_schema_fixture();
    let etag = compute_user_schema_etag(&schema).unwrap();
    let attrs = user_schema_to_dynamodb_attrs("org-acme", &schema, &etag).unwrap();
    let by_key: std::collections::HashMap<_, _> = attrs.into_iter().collect();
    assert_eq!(by_key["PK"].as_s().unwrap(), "ORG#org-acme");
    assert_eq!(by_key["SK"].as_s().unwrap(), "USER_SCHEMA");
    assert_eq!(by_key["etag"].as_s().unwrap(), &etag);

    let recovered: UserSchema = serde_json::from_str(by_key["schema"].as_s().unwrap()).unwrap();
    assert_eq!(recovered, schema);
}

#[test]
fn compute_user_schema_etag_format_and_determinism() {
    let schema = user_schema_fixture();
    let etag1 = compute_user_schema_etag(&schema).unwrap();
    let etag2 = compute_user_schema_etag(&schema).unwrap();
    assert_eq!(etag1, etag2);
    assert_eq!(etag1.len(), 18, "etag={etag1:?}");
    assert!(etag1.starts_with('"') && etag1.ends_with('"'));
}

#[test]
fn compute_user_schema_etag_matches_cp_recipe() {
    // Cross-crate anchor: CP's `store::compute_etag_json` uses serde_json +
    // xxh64. If field order or seed convention drifts, this catches it before
    // a seeded row fails an `If-Match` round-trip from the CP handler.
    let schema = user_schema_fixture();
    let etag = compute_user_schema_etag(&schema).unwrap();
    let json = serde_json::to_string(&schema).unwrap();
    let expected = format!("\"{:016x}\"", xxhash_rust::xxh64::xxh64(json.as_bytes(), 0));
    assert_eq!(etag, expected);
}

// -- user schema + attr adapters -----------------------------------------

#[test]
fn seed_user_schema_to_domain_happy_path() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }
"#,
    );
    let schema = seed_user_schema_to_domain(org.user_schema()).unwrap();
    assert_eq!(schema.standard().len(), 1);
    assert!(schema.standard()[&StandardAttrName::Name].required);
    assert!(schema.custom().is_empty());
}

#[test]
fn seed_user_schema_to_domain_rejects_unknown_standard_attr() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
bogus_attr = { required = true }
"#,
    );
    let err = seed_user_schema_to_domain(org.user_schema()).unwrap_err();
    assert!(
        matches!(err, SeedSchemaConversionError::InvalidStandardAttr { .. }),
        "got: {err:?}"
    );
}

#[test]
fn seed_user_schema_to_domain_rejects_invalid_custom_attr() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.custom]
"Bad Name" = { required = false }
"#,
    );
    let err = seed_user_schema_to_domain(org.user_schema()).unwrap_err();
    assert!(
        matches!(err, SeedSchemaConversionError::InvalidCustomAttr { .. }),
        "got: {err:?}"
    );
}

#[test]
fn validate_attributes_missing_required_name_errors() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }
"#,
    );
    let schema = seed_user_schema_to_domain(org.user_schema()).unwrap();
    let err = validate_attributes(&schema, &RawAttrMap::new()).unwrap_err();
    assert!(err
        .errors
        .iter()
        .any(|e| matches!(e.reason, FieldErrorKind::MissingRequired) && e.field == "name"));
}

#[test]
fn membership_row_to_dynamo_attrs_matches_cp_layout() {
    use forgeguard_authn_core::membership::MembershipRowParams;
    use forgeguard_authn_core::MembershipRow;
    use forgeguard_core::{GroupName, OrganizationId, UserId};

    let row = MembershipRow::new(MembershipRowParams {
        sub: UserId::new("abc-123").unwrap(),
        org_id: OrganizationId::new("org-acme").unwrap(),
        groups: vec![GroupName::new("admin").unwrap()],
        email: "a@acme.test".to_owned(),
        created_at: fixed_now(),
        created_by: UserId::new("xtask-seed").unwrap(),
    });
    let by_key: std::collections::HashMap<_, _> =
        membership_row_to_dynamo_attrs(&row).into_iter().collect();
    assert_eq!(by_key["PK"].as_s().unwrap(), "USER#abc-123");
    assert_eq!(by_key["SK"].as_s().unwrap(), "ORG#org-acme");
    assert_eq!(by_key["user_id"].as_s().unwrap(), "abc-123");
    assert_eq!(by_key["org_id"].as_s().unwrap(), "org-acme");
    assert_eq!(by_key["email"].as_s().unwrap(), "a@acme.test");
    assert_eq!(by_key["created_by"].as_s().unwrap(), "xtask-seed");
    let groups = by_key["groups"].as_l().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].as_s().unwrap(), "admin");
    let joined = by_key["joined_at"].as_s().unwrap();
    assert!(joined.starts_with("2026-05-07T12:00:00"));
}

#[test]
fn membership_row_to_dynamo_attrs_emits_groups_list_even_when_empty() {
    use forgeguard_authn_core::membership::MembershipRowParams;
    use forgeguard_authn_core::MembershipRow;
    use forgeguard_core::{OrganizationId, UserId};

    let row = MembershipRow::new(MembershipRowParams {
        sub: UserId::new("xyz").unwrap(),
        org_id: OrganizationId::new("org-acme").unwrap(),
        groups: vec![],
        email: "x@acme.test".to_owned(),
        created_at: fixed_now(),
        created_by: UserId::new("xtask-seed").unwrap(),
    });
    let by_key: std::collections::HashMap<_, _> =
        membership_row_to_dynamo_attrs(&row).into_iter().collect();
    let groups = by_key["groups"].as_l().unwrap();
    assert!(groups.is_empty());
}

#[test]
fn validate_attributes_unknown_attr_errors() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id = "org-acme"
name = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }

[[organization.user]]
email = "a@acme.test"
attributes = { name = "Alice", undeclared = "x" }
"#,
    );
    let schema = seed_user_schema_to_domain(org.user_schema()).unwrap();
    let attrs = seed_user_attrs_to_domain(&org.users()[0]);
    let err = validate_attributes(&schema, &attrs).unwrap_err();
    assert!(err
        .errors
        .iter()
        .any(|e| matches!(e.reason, FieldErrorKind::Unknown) && e.field == "undeclared"));
}

// -- preflight_validate (Phase 0) ------------------------------------------

#[test]
fn preflight_validate_happy_path() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }

[[organization.user]]
email      = "admin@acme.test"
groups     = ["admin"]
attributes = { name = "Acme Admin" }

[[organization.group]]
name  = "member"
allow = ["cp-organization-read"]

[[organization.group]]
name     = "admin"
inherits = ["member"]
allow    = ["cp-organization-update"]
"#,
    );
    let schemas = preflight_validate(std::slice::from_ref(&org)).unwrap();
    assert_eq!(schemas.len(), 1);
    assert!(schemas[0].standard().contains_key(&StandardAttrName::Name));
}

#[test]
fn preflight_validate_rejects_invalid_org_id() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "Bad ID"
name                 = "Acme"
cognito_user_pool_id = "us-east-2_acme"
"#,
    );
    let err = preflight_validate(std::slice::from_ref(&org)).unwrap_err();
    assert!(
        matches!(err, PreflightError::InvalidOrgId { ref org, .. } if org == "Bad ID"),
        "got: {err:?}"
    );
}

#[test]
fn preflight_validate_rejects_invalid_pool_id() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme"
cognito_user_pool_id = ""
"#,
    );
    let err = preflight_validate(std::slice::from_ref(&org)).unwrap_err();
    assert!(
        matches!(err, PreflightError::InvalidPoolId { ref org, .. } if org == "org-acme"),
        "got: {err:?}"
    );
}

#[test]
fn preflight_validate_rejects_malformed_schema() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
bogus_attr = { required = true }
"#,
    );
    let err = preflight_validate(std::slice::from_ref(&org)).unwrap_err();
    assert!(matches!(err, PreflightError::Schema { .. }), "got: {err:?}");
}

#[test]
fn preflight_validate_rejects_missing_required_attr() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }

[[organization.user]]
email      = "missing@acme.test"
groups     = ["admin"]
attributes = { }
"#,
    );
    let err = preflight_validate(std::slice::from_ref(&org)).unwrap_err();
    match err {
        PreflightError::Attrs { user, .. } => assert_eq!(user, "missing@acme.test"),
        other => panic!("expected Attrs, got {other:?}"),
    }
}

#[test]
fn preflight_validate_rejects_invalid_membership_group_name() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }

[[organization.user]]
email      = "admin@acme.test"
groups     = ["Bad Group"]
attributes = { name = "Acme Admin" }
"#,
    );
    let err = preflight_validate(std::slice::from_ref(&org)).unwrap_err();
    match err {
        PreflightError::InvalidGroupName { group, .. } => assert_eq!(group, "Bad Group"),
        other => panic!("expected InvalidGroupName, got {other:?}"),
    }
}

#[test]
fn preflight_validate_rejects_dangling_inherit() {
    let org = parse_seed_org(
        r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }

[[organization.group]]
name     = "admin"
inherits = ["nonexistent"]
allow    = ["cp-organization-update"]
"#,
    );
    let err = preflight_validate(std::slice::from_ref(&org)).unwrap_err();
    match err {
        PreflightError::Groups {
            source: SeedGroupConversionError::DanglingInherit { parent, .. },
            ..
        } => assert_eq!(parent, "nonexistent"),
        other => panic!("expected Groups::DanglingInherit, got {other:?}"),
    }
}
