//! Verified Permissions client abstraction for V3's Active-org write path.
//!
//! ## Module structure
//!
//! - `mod` (this file) — `VpClient` trait, `Error`/`Result`, `NamedPolicy`,
//!   pure name <-> description encoding helpers shared with `xtask cedar sync`.
//! - `aws` — production impl `AwsVpClient` wrapping
//!   `aws_sdk_verifiedpermissions::Client`.
//! - `stub` — in-process `StubVpClient` for tests, with failure-injection knobs.
//!
//! ## Name encoding
//!
//! Verified Permissions does not expose a native `name` field on policies, so
//! we encode it as a `[name]` prefix in the `description` field. This is the
//! same convention used by `xtask/src/control_plane/cedar_io.rs`. The two
//! call sites are kept byte-compatible by sharing the encode/decode helpers
//! defined below — V6 will swap the xtask copy out for these.

// Wave 1A introduces the surface area; Waves 2/3 wire it into handlers and
// tests. Items are intentionally unused until then.
#![allow(dead_code)]

pub(crate) mod aws;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod stub;

/// Result type for `VpClient` operations.
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// All failure modes a `VpClient` operation can surface.
///
/// Variants are mapped from AWS SDK error categories at the AWS-impl boundary
/// (`aws::AwsVpClient`). Tests using `StubVpClient` construct them directly.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Resource (policy or store) does not exist.
    #[error("vp resource not found: {0}")]
    NotFound(String),
    /// Resource already exists or otherwise conflicts with the request.
    #[error("vp conflict: {0}")]
    Conflict(String),
    /// VP throttled the request.
    #[error("vp throttled: {0}")]
    Throttled(String),
    /// Catch-all for anything else (network, auth, parse, server-side).
    #[error("vp error: {0}")]
    Other(String),
}

/// A policy as listed by `VpClient::list_policy_ids`: VP-assigned id together
/// with the decoded resource name (when the description carried a `[name]`
/// prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedPolicy {
    pub(crate) policy_id: String,
    pub(crate) name: Option<String>,
}

/// Encode a resource name into the VP `description` field.
///
/// Format: `[name] description text` or `[name]` if no description.
///
/// Shared with `xtask cedar sync` — both must produce byte-identical output.
pub(crate) fn encode_name_in_description(name: &str, description: Option<&str>) -> String {
    match description {
        Some(desc) => format!("[{name}] {desc}"),
        None => format!("[{name}]"),
    }
}

/// Decode a resource name from a VP `description` field.
///
/// Returns `(name, remaining_description)`. If the description doesn't follow
/// the `[name]` encoding, returns `(None, original_description)`.
pub(crate) fn decode_name_from_description(
    description: Option<&str>,
) -> (Option<String>, Option<String>) {
    let Some(desc) = description else {
        return (None, None);
    };

    // Try to parse a `[name]` prefix from the description.
    let parsed = desc
        .strip_prefix('[')
        .and_then(|rest| rest.find(']').map(|end| (&rest[..end], &rest[end + 1..])))
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, after_bracket)| {
            let remaining = after_bracket.trim();
            let tail = if remaining.is_empty() {
                None
            } else {
                Some(remaining.to_string())
            };
            (Some(name.to_string()), tail)
        });

    parsed.unwrap_or_else(|| (None, Some(desc.to_string())))
}

/// Abstraction over the VP operations the V3 Active-org write path needs.
///
/// Three operations only — anything more complex belongs in a different
/// abstraction. The trait is `Send + Sync` so handlers can hold an
/// `Arc<dyn VpClient>` in `AppState`.
#[allow(async_fn_in_trait)]
pub(crate) trait VpClient: Send + Sync {
    /// Create a static policy in `store_id` with the given `name`, `description`,
    /// and Cedar `statement`. Returns the VP-assigned policy id.
    async fn create_policy(
        &self,
        store_id: &str,
        name: &str,
        description: Option<&str>,
        statement: &str,
    ) -> Result<String>;

    /// Resolve `name` to a policy id (via `list_policy_ids`), then delete it.
    /// Returns `Error::NotFound` if no policy with that encoded name exists.
    ///
    /// The list-then-delete is non-atomic: if the policy is deleted (or
    /// recreated under a new id) between the two calls, the delete may target
    /// a stale id and surface as `Error::NotFound`. Callers must treat
    /// `NotFound` from this method as "no policy is currently present under
    /// this name" and decide whether that is success (idempotent delete) or
    /// a conflict.
    async fn delete_policy_by_name(&self, store_id: &str, name: &str) -> Result<()>;

    /// List every static policy in `store_id`, decoding the `[name]` prefix
    /// from the description field.
    async fn list_policy_ids(&self, store_id: &str) -> Result<Vec<NamedPolicy>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_with_description() {
        assert_eq!(
            encode_name_in_description("admin", Some("Admin role")),
            "[admin] Admin role"
        );
    }

    #[test]
    fn encode_without_description() {
        assert_eq!(encode_name_in_description("admin", None), "[admin]");
    }

    #[test]
    fn decode_with_name_and_description() {
        let (name, desc) = decode_name_from_description(Some("[admin] Admin role"));
        assert_eq!(name.as_deref(), Some("admin"));
        assert_eq!(desc.as_deref(), Some("Admin role"));
    }

    #[test]
    fn decode_with_name_only() {
        let (name, desc) = decode_name_from_description(Some("[admin]"));
        assert_eq!(name.as_deref(), Some("admin"));
        assert_eq!(desc, None);
    }

    #[test]
    fn decode_with_no_brackets_returns_original_as_description() {
        let (name, desc) = decode_name_from_description(Some("plain text"));
        assert_eq!(name, None);
        assert_eq!(desc.as_deref(), Some("plain text"));
    }

    #[test]
    fn decode_none_input() {
        assert_eq!(decode_name_from_description(None), (None, None));
    }

    #[test]
    fn decode_empty_brackets_treated_as_no_name() {
        let (name, desc) = decode_name_from_description(Some("[]"));
        assert_eq!(name, None);
        assert_eq!(desc.as_deref(), Some("[]"));
    }

    #[test]
    fn round_trip_with_description() {
        let encoded = encode_name_in_description("cp-rbac-admin", Some("Admin role"));
        let (name, desc) = decode_name_from_description(Some(&encoded));
        assert_eq!(name.as_deref(), Some("cp-rbac-admin"));
        assert_eq!(desc.as_deref(), Some("Admin role"));
    }

    #[test]
    fn round_trip_without_description() {
        let encoded = encode_name_in_description("cp-rbac-admin", None);
        let (name, desc) = decode_name_from_description(Some(&encoded));
        assert_eq!(name.as_deref(), Some("cp-rbac-admin"));
        assert_eq!(desc, None);
    }
}
