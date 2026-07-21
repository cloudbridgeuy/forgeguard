use std::sync::LazyLock;

use regex::Regex;

use super::{resolve_inherits, RbacEntry, CYCLE_PREFIX};

/// Stable parsed form of a group write request.
///
/// Constructed only via [`validate_rbac_entry`]. Holding one is proof that
/// every field-level validator passed for the post-write state of the
/// group set.
#[derive(Debug, Clone)]
pub struct ValidatedRbacEntry(RbacEntry);

impl ValidatedRbacEntry {
    pub fn into_inner(self) -> RbacEntry {
        self.0
    }
    pub fn entry(&self) -> &RbacEntry {
        &self.0
    }
}

/// Errors produced by group write validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupValidationError {
    #[error("name {name:?} must match [a-z][a-z0-9_-]*")]
    BadNameRegex { name: String },
    #[error("action id {action:?} must match [a-z][a-z0-9_-]* (hyphenated form, e.g. cp-organization-read)")]
    BadActionId { action: String },
    #[error("action {action:?} must match <namespace>:<entity>:<verb>")]
    BadActionFormat { action: String },
    #[error("allow list must not be empty")]
    EmptyAllow,
    #[error("inherit cycle detected: {0}")]
    InheritCycle(String),
    #[error("inherits references unknown group {0:?}")]
    UnknownInherit(String),
    #[error("description longer than 1024 chars")]
    DescriptionTooLong,
    #[error("path name {path_name:?} does not match body name {body_name:?}")]
    NameMismatch {
        path_name: String,
        body_name: String,
    },
}

/// Compiled group-name regex — initialised once, never fails.
static GROUP_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z][a-z0-9_-]*$").unwrap_or_else(|_| unreachable!("hard-coded regex"))
});

/// Compiled action-format regex — initialised once, never fails.
static ACTION_FORMAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$")
        .unwrap_or_else(|_| unreachable!("hard-coded regex"))
});

/// Validate that a group name matches `[a-z][a-z0-9_-]*`.
pub fn validate_group_name(name: &str) -> Result<(), GroupValidationError> {
    if GROUP_NAME_RE.is_match(name) {
        Ok(())
    } else {
        Err(GroupValidationError::BadNameRegex {
            name: name.to_owned(),
        })
    }
}

/// Validate that an action matches `<namespace>:<entity>:<verb>` — exactly
/// three colon-separated segments, each matching `[a-z][a-z0-9_-]*`.
/// Validate a hyphenated Cedar action id (`cp-organization-read`) — the form
/// `forgeguard.toml`'s `allow` lists use. Reuses the group-name character set.
pub fn validate_action_id(action: &str) -> Result<(), GroupValidationError> {
    if GROUP_NAME_RE.is_match(action) {
        Ok(())
    } else {
        Err(GroupValidationError::BadActionId {
            action: action.to_owned(),
        })
    }
}

pub fn validate_action_format(action: &str) -> Result<(), GroupValidationError> {
    if ACTION_FORMAT_RE.is_match(action) {
        Ok(())
    } else {
        Err(GroupValidationError::BadActionFormat {
            action: action.to_owned(),
        })
    }
}

/// Pre-flight: validate a single new/updated entry against the post-write
/// state of all entries in the org. The handler is responsible for building
/// `all_after` from the existing list plus the proposed entry.
pub fn validate_rbac_entry(
    proposed: RbacEntry,
    all_after: &[RbacEntry],
) -> Result<ValidatedRbacEntry, GroupValidationError> {
    validate_group_name(&proposed.name)?;
    if proposed.allow.is_empty() {
        return Err(GroupValidationError::EmptyAllow);
    }
    if proposed
        .description
        .as_deref()
        .is_some_and(|d| d.len() > 1024)
    {
        return Err(GroupValidationError::DescriptionTooLong);
    }
    for action in &proposed.allow {
        validate_action_format(action)?;
    }
    // Use the existing pure resolver; it surfaces both cycle and unknown-inherit.
    let _ = resolve_inherits(all_after, &proposed.name).map_err(map_resolve_err)?;
    Ok(ValidatedRbacEntry(proposed))
}

fn map_resolve_err(s: String) -> GroupValidationError {
    if s.starts_with(CYCLE_PREFIX) {
        GroupValidationError::InheritCycle(s)
    } else {
        // resolve_inherits returns "RBAC role 'X' not found ..." for missing inherits
        GroupValidationError::UnknownInherit(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // validate_group_name
    // -------------------------------------------------------------------

    #[test]
    fn group_name_accepts_valid_names() {
        for name in &["member", "admin", "owner-extra", "a", "a_b", "a-b-c"] {
            assert!(
                validate_group_name(name).is_ok(),
                "expected {name:?} to be valid"
            );
        }
    }

    #[test]
    fn group_name_rejects_invalid_names() {
        for name in &[
            "",      // empty
            "Admin", // uppercase
            "1abc",  // digit lead
            "-abc",  // hyphen lead
            "_abc",  // underscore lead
            "a b",   // space
            "a:b",   // colon
            "a/b",   // slash
        ] {
            assert!(
                validate_group_name(name).is_err(),
                "expected {name:?} to be invalid"
            );
        }
    }

    // -------------------------------------------------------------------
    // validate_action_format
    // -------------------------------------------------------------------

    #[test]
    fn action_format_accepts_valid_actions() {
        for action in &["cp:proxy-config:read", "todo:list:create", "a:b:c"] {
            assert!(
                validate_action_format(action).is_ok(),
                "expected {action:?} to be valid"
            );
        }
    }

    #[test]
    fn action_format_rejects_invalid_actions() {
        for action in &[
            "",                    // empty
            "cp:read",             // two segments
            "cp::read",            // empty middle segment
            "cp:proxy:read:extra", // four segments
            " cp:proxy:read",      // leading whitespace
            "CP:proxy:read",       // uppercase namespace
        ] {
            assert!(
                validate_action_format(action).is_err(),
                "expected {action:?} to be invalid"
            );
        }
    }

    // -------------------------------------------------------------------
    // validate_rbac_entry
    // -------------------------------------------------------------------

    fn make_entry(
        name: &str,
        allow: Vec<&str>,
        inherits: Vec<&str>,
        description: Option<&str>,
    ) -> RbacEntry {
        RbacEntry {
            name: name.to_owned(),
            description: description.map(str::to_owned),
            inherits: inherits.into_iter().map(str::to_owned).collect(),
            allow: allow.into_iter().map(str::to_owned).collect(),
            tenant_scoped: true,
        }
    }

    #[test]
    fn validate_rbac_entry_happy_path() {
        let member = make_entry("member", vec!["cp:x:read"], vec![], None);
        let admin = make_entry("admin", vec!["cp:x:read"], vec!["member"], None);
        let all_after = vec![member.clone(), admin.clone()];
        let result = validate_rbac_entry(admin, &all_after);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rbac_entry_empty_allow() {
        let entry = make_entry("admin", vec![], vec![], None);
        let result = validate_rbac_entry(entry.clone(), &[entry]);
        assert_eq!(result.unwrap_err(), GroupValidationError::EmptyAllow);
    }

    #[test]
    fn validate_rbac_entry_bad_name() {
        let entry = make_entry("Admin", vec!["cp:x:read"], vec![], None);
        let all_after = vec![entry.clone()];
        let err = validate_rbac_entry(entry, &all_after).unwrap_err();
        assert!(
            matches!(err, GroupValidationError::BadNameRegex { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rbac_entry_bad_action_format() {
        let entry = make_entry("admin", vec!["not-valid"], vec![], None);
        let all_after = vec![entry.clone()];
        let err = validate_rbac_entry(entry, &all_after).unwrap_err();
        assert!(
            matches!(err, GroupValidationError::BadActionFormat { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rbac_entry_description_too_long() {
        let long_desc = "x".repeat(1025);
        let entry = make_entry("admin", vec!["cp:x:read"], vec![], Some(long_desc.as_str()));
        let all_after = vec![entry.clone()];
        let err = validate_rbac_entry(entry, &all_after).unwrap_err();
        assert_eq!(err, GroupValidationError::DescriptionTooLong);
    }

    #[test]
    fn validate_rbac_entry_self_inherit_cycle() {
        // A role that inherits itself should produce InheritCycle.
        let entry = make_entry("admin", vec!["cp:x:read"], vec!["admin"], None);
        let all_after = vec![entry.clone()];
        let err = validate_rbac_entry(entry, &all_after).unwrap_err();
        assert!(
            matches!(err, GroupValidationError::InheritCycle(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rbac_entry_transitive_cycle() {
        // a -> b -> a
        let a = make_entry("a", vec!["cp:x:read"], vec!["b"], None);
        let b = make_entry("b", vec!["cp:y:write"], vec!["a"], None);
        let all_after = vec![a.clone(), b];
        let err = validate_rbac_entry(a, &all_after).unwrap_err();
        assert!(
            matches!(err, GroupValidationError::InheritCycle(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rbac_entry_unknown_inherit() {
        let entry = make_entry("admin", vec!["cp:x:read"], vec!["nonexistent"], None);
        let all_after = vec![entry.clone()];
        let err = validate_rbac_entry(entry, &all_after).unwrap_err();
        assert!(
            matches!(err, GroupValidationError::UnknownInherit(_)),
            "got {err:?}"
        );
    }
}
