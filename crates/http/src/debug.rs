//! Debug endpoint: flag evaluation with resolution reasons.
//!
//! Pure functions — no I/O. The proxy shell calls these and writes the response.

use forgeguard_core::{
    evaluate_flags_detailed, DetailedResolvedFlags, FlagConfig, GroupName, TenantId, UserId,
};

use crate::error::{Error, Result};

/// Parsed query parameters for the flags debug endpoint.
pub struct FlagDebugQuery {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
}

impl FlagDebugQuery {
    /// Parse from raw query string (e.g., `"user_id=alice&tenant_id=acme&groups=admin,ops"`).
    ///
    /// `user_id` is required. `tenant_id` and `groups` are optional.
    /// `groups` is a comma-separated list of group names.
    pub fn parse(query: &str) -> Result<Self> {
        let mut user_id: Option<String> = None;
        let mut tenant_id: Option<String> = None;
        let mut groups_raw: Option<String> = None;

        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "user_id" => user_id = Some(value.into_owned()),
                "tenant_id" => tenant_id = Some(value.into_owned()),
                "groups" => groups_raw = Some(value.into_owned()),
                _ => {} // ignore unknown params
            }
        }

        let user_id_str = user_id.ok_or_else(|| {
            Error::InvalidQuery("missing required parameter: user_id".to_string())
        })?;

        let user_id = UserId::new(&user_id_str)
            .map_err(|e| Error::InvalidQuery(format!("invalid user_id: {e}")))?;

        let tenant_id = tenant_id
            .map(|t| {
                TenantId::new(&t)
                    .map_err(|e| Error::InvalidQuery(format!("invalid tenant_id: {e}")))
            })
            .transpose()?;

        let groups = match groups_raw {
            Some(raw) if !raw.is_empty() => raw
                .split(',')
                .map(|g| {
                    GroupName::new(g.trim())
                        .map_err(|e| Error::InvalidQuery(format!("invalid group name '{g}': {e}")))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };

        Ok(Self {
            user_id,
            tenant_id,
            groups,
        })
    }

    /// The parsed user ID.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The optional parsed tenant ID.
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// The parsed group names.
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }
}

/// Evaluate flags for a debug query and return the detailed result.
pub fn evaluate_debug(config: &FlagConfig, query: &FlagDebugQuery) -> DetailedResolvedFlags {
    evaluate_flags_detailed(config, query.tenant_id(), query.user_id(), query.groups())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_params() {
        let query = FlagDebugQuery::parse("user_id=alice&tenant_id=acme&groups=admin,ops").unwrap();
        assert_eq!(query.user_id().as_str(), "alice");
        assert_eq!(query.tenant_id().unwrap().as_str(), "acme");
        assert_eq!(query.groups().len(), 2);
        assert_eq!(query.groups()[0].as_str(), "admin");
        assert_eq!(query.groups()[1].as_str(), "ops");
    }

    #[test]
    fn parse_user_id_only() {
        let query = FlagDebugQuery::parse("user_id=bob").unwrap();
        assert_eq!(query.user_id().as_str(), "bob");
        assert!(query.tenant_id().is_none());
        assert!(query.groups().is_empty());
    }

    #[test]
    fn parse_missing_user_id_errors() {
        let result = FlagDebugQuery::parse("tenant_id=acme");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_user_id_errors() {
        // UserId rejects uppercase
        let result = FlagDebugQuery::parse("user_id=INVALID_UPPERCASE");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_group_name_errors() {
        let result = FlagDebugQuery::parse("user_id=alice&groups=admin,INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_groups_is_empty_vec() {
        let query = FlagDebugQuery::parse("user_id=alice&groups=").unwrap();
        assert!(query.groups().is_empty());
    }

    #[test]
    fn parse_ignores_unknown_params() {
        let query = FlagDebugQuery::parse("user_id=alice&foo=bar").unwrap();
        assert_eq!(query.user_id().as_str(), "alice");
    }

    #[test]
    fn evaluate_debug_returns_detailed_flags() {
        use forgeguard_core::{FlagConfig, FlagDefinition, FlagName, FlagType, FlagValue};

        let mut config = FlagConfig::default();
        config.flags.insert(
            FlagName::parse("test-flag").unwrap(),
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(true),
                enabled: true,
                overrides: vec![],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let query = FlagDebugQuery::parse("user_id=alice").unwrap();
        let result = evaluate_debug(&config, &query);
        let flag = result.get("test-flag").unwrap();
        assert_eq!(flag.value(), &FlagValue::Bool(true));
    }
}
