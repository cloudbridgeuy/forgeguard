#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

// -----------------------------------------------------------------------
// compile_rbac_to_cedar tests
// -----------------------------------------------------------------------

#[test]
fn compile_basic_rbac_with_default_tenant_scoping() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "editor".into(),
        description: None,
        inherits: vec![],
        allow: vec![
            "todo:list:create".to_string(),
            "todo:list:update".to_string(),
        ],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs").unwrap();

    let expected = "\
permit(
  principal in TestNs::Group::\"editor\",
  action in [TestNs::Action::\"todo:list:create\", TestNs::Action::\"todo:list:update\"],
  resource
) when { principal.tenant_id == resource.tenant_id };";
    assert_eq!(result, expected);
}

#[test]
fn compile_rbac_with_custom_tenant_attributes() {
    let tenant = TenantConfig {
        enabled: true,
        principal_attribute: "org_id".to_string(),
        resource_attribute: "org_id".to_string(),
    };
    let entry = RbacEntry {
        name: "admin".into(),
        description: None,
        inherits: vec![],
        allow: vec!["shopping:list:create".to_string()],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs").unwrap();

    assert!(result.contains("principal.org_id == resource.org_id"));
}

#[test]
fn compile_rbac_tenant_scoped_false_no_when_clause() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "global-reader".into(),
        description: None,
        inherits: vec![],
        allow: vec!["todo:list:list".to_string()],
        tenant_scoped: false,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs").unwrap();

    let expected = "\
permit(
  principal in TestNs::Group::\"global-reader\",
  action in [TestNs::Action::\"todo:list:list\"],
  resource
);";
    assert_eq!(result, expected);
    assert!(!result.contains("when"));
}

#[test]
fn compile_rbac_tenant_globally_disabled_no_when_clause() {
    let tenant = TenantConfig {
        enabled: false,
        principal_attribute: "tenant_id".to_string(),
        resource_attribute: "tenant_id".to_string(),
    };
    let entry = RbacEntry {
        name: "viewer".into(),
        description: None,
        inherits: vec![],
        allow: vec!["todo:list:read".to_string()],
        tenant_scoped: true, // per-policy wants scoping, but global is off
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs").unwrap();

    assert!(!result.contains("when"));
    assert!(result.ends_with(");"));
}

#[test]
fn compile_rbac_single_action_uses_in_syntax() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "viewer".into(),
        description: None,
        inherits: vec![],
        allow: vec!["todo:list:read".to_string()],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs").unwrap();

    assert!(result.contains("action in [TestNs::Action::\"todo:list:read\"]"));
}

#[test]
fn compile_rbac_empty_allow_list_returns_error() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "empty-role".into(),
        description: None,
        inherits: vec![],
        allow: vec![],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("empty allow list"), "unexpected error: {err}");
}

#[test]
fn compile_rbac_many_actions() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "admin".into(),
        description: None,
        inherits: vec![],
        allow: vec![
            "todo:list:create".to_string(),
            "todo:list:update".to_string(),
            "todo:list:delete".to_string(),
            "todo:list:share".to_string(),
        ],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs").unwrap();

    assert!(result.contains("TestNs::Action::\"todo:list:create\""));
    assert!(result.contains("TestNs::Action::\"todo:list:update\""));
    assert!(result.contains("TestNs::Action::\"todo:list:delete\""));
    assert!(result.contains("TestNs::Action::\"todo:list:share\""));
}

// -----------------------------------------------------------------------
// resolve_inherits tests
// -----------------------------------------------------------------------

fn rbac_entry(name: &str, allow: &[&str], inherits: &[&str]) -> RbacEntry {
    RbacEntry {
        name: name.to_string(),
        description: None,
        inherits: inherits
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        allow: allow.iter().map(std::string::ToString::to_string).collect(),
        tenant_scoped: true,
    }
}

#[test]
fn resolve_no_inheritance() {
    let entries = vec![rbac_entry("viewer", &["read"], &[])];
    let actions = resolve_inherits(&entries, "viewer").unwrap();
    assert_eq!(actions, vec!["read"]);
}

#[test]
fn resolve_simple_inheritance() {
    let entries = vec![
        rbac_entry("viewer", &["read"], &[]),
        rbac_entry("editor", &["write"], &["viewer"]),
    ];
    let actions = resolve_inherits(&entries, "editor").unwrap();
    assert_eq!(actions, vec!["write", "read"]);
}

#[test]
fn resolve_transitive_inheritance() {
    let entries = vec![
        rbac_entry("viewer", &["read"], &[]),
        rbac_entry("editor", &["write"], &["viewer"]),
        rbac_entry("admin", &["delete"], &["editor"]),
    ];
    let actions = resolve_inherits(&entries, "admin").unwrap();
    assert_eq!(actions, vec!["delete", "write", "read"]);
}

#[test]
fn resolve_cycle_detection() {
    let entries = vec![
        rbac_entry("a", &["x"], &["b"]),
        rbac_entry("b", &["y"], &["a"]),
    ];
    let result = resolve_inherits(&entries, "a");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("cycle"), "unexpected error: {err}");
}

#[test]
fn resolve_self_reference() {
    let entries = vec![rbac_entry("a", &["x"], &["a"])];
    let result = resolve_inherits(&entries, "a");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("cycle"), "unexpected error: {err}");
}

#[test]
fn resolve_inherits_from_nonexistent_role() {
    let entries = vec![rbac_entry("a", &["x"], &["nonexistent"])];
    let result = resolve_inherits(&entries, "a");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("not found"), "unexpected error: {err}");
}

#[test]
fn resolve_diamond_inheritance_dedup() {
    // A inherits B and C, both inherit D
    let entries = vec![
        rbac_entry("d", &["read"], &[]),
        rbac_entry("b", &["write"], &["d"]),
        rbac_entry("c", &["exec"], &["d"]),
        rbac_entry("a", &["admin"], &["b", "c"]),
    ];
    let actions = resolve_inherits(&entries, "a").unwrap();

    // "read" from D should appear only once
    let read_count = actions.iter().filter(|a| *a == "read").count();
    assert_eq!(read_count, 1, "diamond should deduplicate actions");

    // All actions should be present
    assert!(actions.contains(&"admin".to_string()));
    assert!(actions.contains(&"write".to_string()));
    assert!(actions.contains(&"exec".to_string()));
    assert!(actions.contains(&"read".to_string()));
}

#[test]
fn resolve_target_not_found() {
    let entries = vec![rbac_entry("viewer", &["read"], &[])];
    let result = resolve_inherits(&entries, "nonexistent");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("not found"), "unexpected error: {err}");
}

#[test]
fn resolve_multi_parent_inherits() {
    let entries = vec![
        rbac_entry("viewer", &["todo:list:list", "todo:list:read"], &[]),
        rbac_entry(
            "shopper",
            &["shopping:list:list", "shopping:list:read"],
            &[],
        ),
        rbac_entry("admin", &["todo:list:delete"], &["viewer", "shopper"]),
    ];
    let actions = resolve_inherits(&entries, "admin").unwrap();
    assert_eq!(
        actions,
        vec![
            "todo:list:delete",
            "todo:list:list",
            "todo:list:read",
            "shopping:list:list",
            "shopping:list:read",
        ]
    );
}

// -----------------------------------------------------------------------
// validate_cedar_ident tests
// -----------------------------------------------------------------------

#[test]
fn compile_rbac_role_name_with_quotes_returns_error() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "role\"injection".into(),
        description: None,
        inherits: vec![],
        allow: vec!["todo:list:read".to_string()],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("invalid characters"),
        "unexpected error: {err}"
    );
}

#[test]
fn compile_rbac_action_with_newline_returns_error() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "viewer".into(),
        description: None,
        inherits: vec![],
        allow: vec!["todo:list\n:read".to_string()],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("invalid characters"),
        "unexpected error: {err}"
    );
}

#[test]
fn compile_rbac_empty_name_returns_error() {
    let tenant = TenantConfig::default();
    let entry = RbacEntry {
        name: "".into(),
        description: None,
        inherits: vec![],
        allow: vec!["todo:list:read".to_string()],
        tenant_scoped: true,
    };
    let result = compile_rbac_to_cedar(&entry, &tenant, "TestNs");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("must not be empty"), "unexpected error: {err}");
}

// -----------------------------------------------------------------------
// Golden test: forgeguard.toml canonical roles
// -----------------------------------------------------------------------

/// Byte-identical parity guard: compile each of the three canonical
/// ForgeGuard RBAC roles and assert the output matches the expected Cedar
/// policy string char-for-char. This guards against silent regressions in
/// the compiler logic.
#[test]
fn compile_forgeguard_rbac_golden_byte_identical() {
    let tenant = TenantConfig {
        enabled: true,
        principal_attribute: "org_id".to_string(),
        resource_attribute: "org_id".to_string(),
    };
    let namespace = "forgeguard";

    // --- member ---
    let member = RbacEntry {
        name: "member".into(),
        description: Some("Read-only org access".into()),
        inherits: vec![],
        allow: vec![
            "cp-organization-read".to_string(),
            "cp-key-read".to_string(),
            "cp-config-read".to_string(),
        ],
        tenant_scoped: true,
    };
    let expected_member = "\
permit(
  principal in forgeguard::Group::\"member\",
  action in [forgeguard::Action::\"cp-organization-read\", forgeguard::Action::\"cp-key-read\", forgeguard::Action::\"cp-config-read\"],
  resource
) when { principal.org_id == resource.org_id };";
    assert_eq!(
        compile_rbac_to_cedar(&member, &tenant, namespace).unwrap(),
        expected_member,
        "member role output mismatch"
    );

    // --- admin ---
    let admin = RbacEntry {
        name: "admin".into(),
        description: Some("Org management without deletion or owner promotion".into()),
        inherits: vec!["member".to_string()],
        allow: vec![
            "cp-organization-create".to_string(),
            "cp-organization-update".to_string(),
            "cp-member-invite".to_string(),
            "cp-member-remove".to_string(),
            "cp-member-change-role".to_string(),
            "cp-config-write".to_string(),
            "cp-key-generate".to_string(),
            "cp-key-revoke".to_string(),
            "cp-key-rotate".to_string(),
        ],
        tenant_scoped: true,
    };
    let expected_admin = "\
permit(
  principal in forgeguard::Group::\"admin\",
  action in [forgeguard::Action::\"cp-organization-create\", forgeguard::Action::\"cp-organization-update\", forgeguard::Action::\"cp-member-invite\", forgeguard::Action::\"cp-member-remove\", forgeguard::Action::\"cp-member-change-role\", forgeguard::Action::\"cp-config-write\", forgeguard::Action::\"cp-key-generate\", forgeguard::Action::\"cp-key-revoke\", forgeguard::Action::\"cp-key-rotate\"],
  resource
) when { principal.org_id == resource.org_id };";
    assert_eq!(
        compile_rbac_to_cedar(&admin, &tenant, namespace).unwrap(),
        expected_admin,
        "admin role output mismatch"
    );

    // --- owner ---
    let owner = RbacEntry {
        name: "owner".into(),
        description: Some("Full org access including deletion and owner promotion".into()),
        inherits: vec!["admin".to_string()],
        allow: vec![
            "cp-organization-delete".to_string(),
            "cp-member-promote-owner".to_string(),
        ],
        tenant_scoped: true,
    };
    let expected_owner = "\
permit(
  principal in forgeguard::Group::\"owner\",
  action in [forgeguard::Action::\"cp-organization-delete\", forgeguard::Action::\"cp-member-promote-owner\"],
  resource
) when { principal.org_id == resource.org_id };";
    assert_eq!(
        compile_rbac_to_cedar(&owner, &tenant, namespace).unwrap(),
        expected_owner,
        "owner role output mismatch"
    );
}
