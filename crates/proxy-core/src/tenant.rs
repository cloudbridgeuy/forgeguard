//! Tenant extraction — resolve an [`OrganizationId`] from a [`RequestInput`].
//!
//! Four built-in extractors plus a chain combinator:
//!
//! | Extractor              | Source                    | Example                                  |
//! |------------------------|---------------------------|------------------------------------------|
//! | [`SubdomainExtractor`] | First label of `host`     | `acme.api.example.com` → `acme`          |
//! | [`HostExtractor`]      | Full `host` header value  | `acme` (no dots) → `acme`                |
//! | [`HeaderExtractor`]    | Named header              | `x-organization-id: acme` → `acme`       |
//! | [`PathPrefixExtractor`]| First path segment        | `/acme/api/v1/users` → `acme`            |
//!
//! All extractors return `None` when the source is missing or the extracted
//! value is not a valid [`OrganizationId`] (i.e. not a valid [`Segment`]).
//!
//! [`Segment`]: forgeguard_core::Segment

use forgeguard_core::OrganizationId;

use crate::RequestInput;

// ---------------------------------------------------------------------------
// TenantExtractor trait
// ---------------------------------------------------------------------------

/// Extracts an [`OrganizationId`] from a [`RequestInput`].
///
/// Implementations inspect a single source (header, host, path, etc.) and
/// return `Some(org_id)` when extraction succeeds, or `None` when the source
/// is missing or the value is not a valid organization identifier.
pub trait TenantExtractor: Send + Sync {
    /// Attempt to extract an [`OrganizationId`] from the request.
    fn extract(&self, input: &RequestInput) -> Option<OrganizationId>;
}

// ---------------------------------------------------------------------------
// SubdomainExtractor
// ---------------------------------------------------------------------------

/// Extracts the organization from the first subdomain label of the `host`
/// header.
///
/// For `acme.api.example.com`, the first label is `acme`. Port suffixes on
/// the host (e.g. `acme.api.example.com:8080`) are stripped before splitting.
///
/// Returns `None` when:
/// - The `host` header is missing
/// - The host has no dots (single-label host like `localhost`)
/// - The first label is not a valid [`OrganizationId`]
#[derive(Debug)]
pub struct SubdomainExtractor {
    _private: (),
}

impl SubdomainExtractor {
    /// Create a new `SubdomainExtractor`.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SubdomainExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantExtractor for SubdomainExtractor {
    fn extract(&self, input: &RequestInput) -> Option<OrganizationId> {
        let host = strip_port(find_header(input.headers(), "host")?);

        // Must have at least one dot — single-label hosts have no subdomain
        let (first_label, _rest) = host.split_once('.')?;

        OrganizationId::new(first_label).ok()
    }
}

// ---------------------------------------------------------------------------
// HostExtractor
// ---------------------------------------------------------------------------

/// Extracts the full host header value as the organization identifier.
///
/// Only matches single-label hosts (no dots) since [`OrganizationId`]
/// requires [`Segment`] validation. For multi-label hosts (e.g.
/// `acme.example.com`), use [`SubdomainExtractor`] instead.
///
/// This is useful in internal or Docker Compose environments where hosts
/// are simple names like `acme` or `acme:8080`.
///
/// Returns `None` when:
/// - The `host` header is missing
/// - The host contains dots (not a valid [`Segment`])
/// - The host value is otherwise not a valid [`OrganizationId`]
///
/// [`Segment`]: forgeguard_core::Segment
#[derive(Debug)]
pub struct HostExtractor {
    _private: (),
}

impl HostExtractor {
    /// Create a new `HostExtractor`.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for HostExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantExtractor for HostExtractor {
    fn extract(&self, input: &RequestInput) -> Option<OrganizationId> {
        let host = strip_port(find_header(input.headers(), "host")?);

        OrganizationId::new(host).ok()
    }
}

// ---------------------------------------------------------------------------
// HeaderExtractor
// ---------------------------------------------------------------------------

/// Extracts the organization from a named request header.
///
/// The header name is configured at construction time and stored lowercased
/// (matching the convention that [`RequestInput`] headers are lowercased).
///
/// Returns `None` when:
/// - The configured header is missing from the request
/// - The header value is not a valid [`OrganizationId`]
#[derive(Debug)]
pub struct HeaderExtractor {
    header_name: String,
}

impl HeaderExtractor {
    /// Create a new `HeaderExtractor` that reads the given header.
    ///
    /// The `header_name` is lowercased at construction time to match the
    /// lowercased header names in [`RequestInput`].
    pub fn new(header_name: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into().to_ascii_lowercase(),
        }
    }
}

impl TenantExtractor for HeaderExtractor {
    fn extract(&self, input: &RequestInput) -> Option<OrganizationId> {
        let value = find_header(input.headers(), &self.header_name)?;

        OrganizationId::new(value).ok()
    }
}

// ---------------------------------------------------------------------------
// PathPrefixExtractor
// ---------------------------------------------------------------------------

/// Extracts the organization from the first path segment.
///
/// For `/acme/api/v1/users`, the first segment is `acme`. The remaining
/// path (`/api/v1/users`) is available for future use by the pipeline.
///
/// Returns `None` when:
/// - The path is just `/` (root, no segments)
/// - The first segment is empty (e.g. `//foo`)
/// - The first segment is not a valid [`OrganizationId`]
#[derive(Debug)]
pub struct PathPrefixExtractor {
    _private: (),
}

impl PathPrefixExtractor {
    /// Create a new `PathPrefixExtractor`.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for PathPrefixExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl PathPrefixExtractor {
    /// Given a path, return the remaining path after stripping the first
    /// segment (the org prefix).
    ///
    /// Returns `None` if the path has no extractable first segment.
    ///
    /// # Examples
    ///
    /// - `/acme/api/v1/users` → `Some("/api/v1/users")`
    /// - `/acme` → `Some("/")`
    /// - `/` → `None`
    pub fn stripped_path(path: &str) -> Option<String> {
        let (_, rest) = split_first_segment(path)?;
        Some(rest.to_string())
    }
}

impl TenantExtractor for PathPrefixExtractor {
    fn extract(&self, input: &RequestInput) -> Option<OrganizationId> {
        let (segment, _) = split_first_segment(input.path())?;
        OrganizationId::new(segment).ok()
    }
}

// ---------------------------------------------------------------------------
// TenantExtractorChain
// ---------------------------------------------------------------------------

/// Tries multiple [`TenantExtractor`]s in order, returning the first success.
///
/// Constructed with a list of extractors in priority order. The `extract`
/// method iterates through them and returns the first `Some` result. Returns
/// `None` if all extractors return `None`.
pub struct TenantExtractorChain {
    extractors: Vec<Box<dyn TenantExtractor>>,
}

impl TenantExtractorChain {
    /// Create a new chain from a list of extractors in priority order.
    pub fn new(extractors: Vec<Box<dyn TenantExtractor>>) -> Self {
        Self { extractors }
    }
}

impl TenantExtractor for TenantExtractorChain {
    fn extract(&self, input: &RequestInput) -> Option<OrganizationId> {
        self.extractors
            .iter()
            .find_map(|extractor| extractor.extract(input))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the first header matching `name` (case-sensitive -- callers must
/// ensure both sides are lowercased).
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Strip the port suffix from a host value (e.g. `"acme:8080"` -> `"acme"`).
///
/// Handles IPv6 bracket notation: `[::1]:8080` becomes `[::1]` (the bracket
/// form will fail [`Segment`] validation, which is correct — IPv6 literals
/// are not valid organization identifiers).
///
/// If no colon is present, returns the input unchanged.
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // IPv6 bracket notation — find the closing `]`
        match rest.find(']') {
            Some(pos) => &host[..pos + 2], // include both brackets
            None => host,                  // malformed, return as-is
        }
    } else {
        host.split_once(':').map_or(host, |(h, _)| h)
    }
}

/// Split a path into its first non-empty segment and the remaining path.
///
/// Returns `None` for root (`/`) or paths with an empty first segment (`//foo`).
/// The remaining path always starts with `/` (or is `"/"` when no trailing
/// content follows the first segment).
fn split_first_segment(path: &str) -> Option<(&str, &str)> {
    let without_leading = path.strip_prefix('/')?;

    if without_leading.is_empty() {
        return None;
    }

    match without_leading.split_once('/') {
        Some((segment, rest)) if !segment.is_empty() => {
            // rest may be empty (trailing slash) — the caller gets "/"
            if rest.is_empty() {
                Some((segment, "/"))
            } else {
                // Reconstruct with leading slash: "/rest..."
                // Since `rest` is a suffix of `without_leading` which is a suffix
                // of `path`, we can recover the slice starting one char before `rest`.
                let rest_start = segment.len() + 1; // skip "segment/"
                Some((segment, &path[rest_start..]))
            }
        }
        Some(_) => None, // empty first segment (e.g. "//foo")
        // No slash after the first segment — entire path is the prefix
        None => Some((without_leading, "/")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Helper to build a `RequestInput` with the given headers.
    fn request(path: &str, headers: Vec<(&str, &str)>) -> RequestInput {
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        RequestInput::new("GET", path, headers, None).unwrap()
    }

    // -----------------------------------------------------------------------
    // SubdomainExtractor
    // -----------------------------------------------------------------------

    mod subdomain {
        use super::*;

        #[test]
        fn extracts_first_label() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "acme.api.example.com")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn extracts_from_two_label_host() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "acme.example.com")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn strips_port() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "acme.example.com:8080")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn returns_none_for_single_label_host() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "localhost")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_single_label_host_with_port() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "localhost:3000")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_when_host_header_missing() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_invalid_segment_subdomain() {
            let ext = SubdomainExtractor::new();
            // Uppercase is not a valid Segment
            let req = request("/", vec![("host", "AcmeCorp.example.com")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_leading_hyphen_subdomain() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "-bad.example.com")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn numeric_subdomain_is_valid() {
            let ext = SubdomainExtractor::new();
            let req = request("/", vec![("host", "123.example.com")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "123");
        }
    }

    // -----------------------------------------------------------------------
    // HostExtractor
    // -----------------------------------------------------------------------

    mod host {
        use super::*;

        #[test]
        fn extracts_simple_host() {
            let ext = HostExtractor::new();
            let req = request("/", vec![("host", "acme")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn extracts_host_with_port() {
            let ext = HostExtractor::new();
            let req = request("/", vec![("host", "acme:8080")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn returns_none_for_host_with_dots() {
            let ext = HostExtractor::new();
            // "acme.example.com" contains dots, which are invalid for Segment
            let req = request("/", vec![("host", "acme.example.com")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_when_host_header_missing() {
            let ext = HostExtractor::new();
            let req = request("/", vec![]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_invalid_segment() {
            let ext = HostExtractor::new();
            let req = request("/", vec![("host", "AcmeCorp")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_empty_host() {
            let ext = HostExtractor::new();
            let req = request("/", vec![("host", "")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn hyphenated_host_is_valid() {
            let ext = HostExtractor::new();
            let req = request("/", vec![("host", "acme-corp")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme-corp");
        }
    }

    // -----------------------------------------------------------------------
    // HeaderExtractor
    // -----------------------------------------------------------------------

    mod header {
        use super::*;

        #[test]
        fn extracts_from_named_header() {
            let ext = HeaderExtractor::new("x-organization-id");
            let req = request("/", vec![("x-organization-id", "acme")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn header_name_is_lowercased() {
            // Constructor lowercases the name to match RequestInput convention
            let ext = HeaderExtractor::new("X-Organization-Id");
            let req = request("/", vec![("x-organization-id", "acme")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn returns_none_when_header_missing() {
            let ext = HeaderExtractor::new("x-organization-id");
            let req = request("/", vec![]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_invalid_segment_value() {
            let ext = HeaderExtractor::new("x-organization-id");
            let req = request("/", vec![("x-organization-id", "Not-Valid!")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_empty_value() {
            let ext = HeaderExtractor::new("x-organization-id");
            let req = request("/", vec![("x-organization-id", "")]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn custom_header_name() {
            let ext = HeaderExtractor::new("x-tenant");
            let req = request("/", vec![("x-tenant", "beta-org")]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "beta-org");
        }
    }

    // -----------------------------------------------------------------------
    // PathPrefixExtractor
    // -----------------------------------------------------------------------

    mod path_prefix {
        use super::*;

        #[test]
        fn extracts_first_segment() {
            let ext = PathPrefixExtractor::new();
            let req = request("/acme/api/v1/users", vec![]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn extracts_when_path_is_just_segment() {
            let ext = PathPrefixExtractor::new();
            let req = request("/acme", vec![]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn extracts_with_trailing_slash() {
            let ext = PathPrefixExtractor::new();
            let req = request("/acme/", vec![]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }

        #[test]
        fn returns_none_for_root_path() {
            let ext = PathPrefixExtractor::new();
            let req = request("/", vec![]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn returns_none_for_invalid_segment() {
            let ext = PathPrefixExtractor::new();
            let req = request("/AcmeCorp/api", vec![]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn stripped_path_with_trailing() {
            let stripped = PathPrefixExtractor::stripped_path("/acme/api/v1/users");
            assert_eq!(stripped.as_deref(), Some("/api/v1/users"));
        }

        #[test]
        fn stripped_path_single_segment() {
            let stripped = PathPrefixExtractor::stripped_path("/acme");
            assert_eq!(stripped.as_deref(), Some("/"));
        }

        #[test]
        fn stripped_path_single_segment_trailing_slash() {
            let stripped = PathPrefixExtractor::stripped_path("/acme/");
            assert_eq!(stripped.as_deref(), Some("/"));
        }

        #[test]
        fn stripped_path_root() {
            let stripped = PathPrefixExtractor::stripped_path("/");
            assert!(stripped.is_none());
        }

        #[test]
        fn returns_none_for_leading_hyphen_segment() {
            let ext = PathPrefixExtractor::new();
            let req = request("/-bad/api", vec![]);
            assert!(ext.extract(&req).is_none());
        }

        #[test]
        fn numeric_segment_is_valid() {
            let ext = PathPrefixExtractor::new();
            let req = request("/123/resource", vec![]);
            let org = ext.extract(&req).unwrap();
            assert_eq!(org.as_str(), "123");
        }

        #[test]
        fn returns_none_for_percent_encoded_segment() {
            // `%` is not valid in a Segment, so percent-encoded paths are
            // rejected. Callers must percent-decode before extraction if they
            // want this to match.
            let ext = PathPrefixExtractor::new();
            let req = request("/acme%2Dcorp/api", vec![]);
            assert!(ext.extract(&req).is_none());
        }
    }

    // -----------------------------------------------------------------------
    // TenantExtractorChain
    // -----------------------------------------------------------------------

    mod chain {
        use super::*;

        #[test]
        fn returns_first_match() {
            let chain = TenantExtractorChain::new(vec![
                Box::new(HeaderExtractor::new("x-organization-id")),
                Box::new(SubdomainExtractor::new()),
            ]);
            let req = request(
                "/",
                vec![("host", "beta.example.com"), ("x-organization-id", "alpha")],
            );
            let org = chain.extract(&req).unwrap();
            // Header extractor is first, so "alpha" wins
            assert_eq!(org.as_str(), "alpha");
        }

        #[test]
        fn falls_through_to_second() {
            let chain = TenantExtractorChain::new(vec![
                Box::new(HeaderExtractor::new("x-organization-id")),
                Box::new(SubdomainExtractor::new()),
            ]);
            // No header present, but subdomain is
            let req = request("/", vec![("host", "beta.example.com")]);
            let org = chain.extract(&req).unwrap();
            assert_eq!(org.as_str(), "beta");
        }

        #[test]
        fn returns_none_when_all_fail() {
            let chain = TenantExtractorChain::new(vec![
                Box::new(HeaderExtractor::new("x-organization-id")),
                Box::new(SubdomainExtractor::new()),
            ]);
            // No header, no subdomain (single-label host)
            let req = request("/", vec![("host", "localhost")]);
            assert!(chain.extract(&req).is_none());
        }

        #[test]
        fn empty_chain_returns_none() {
            let chain = TenantExtractorChain::new(vec![]);
            let req = request("/", vec![]);
            assert!(chain.extract(&req).is_none());
        }

        #[test]
        fn priority_order_matters() {
            // Subdomain first, then path
            let chain = TenantExtractorChain::new(vec![
                Box::new(SubdomainExtractor::new()),
                Box::new(PathPrefixExtractor::new()),
            ]);
            let req = request("/gamma/api", vec![("host", "delta.example.com")]);
            let org = chain.extract(&req).unwrap();
            // Subdomain extractor wins — "delta"
            assert_eq!(org.as_str(), "delta");
        }

        #[test]
        fn chain_with_all_four_extractors() {
            let chain = TenantExtractorChain::new(vec![
                Box::new(HeaderExtractor::new("x-org")),
                Box::new(SubdomainExtractor::new()),
                Box::new(HostExtractor::new()),
                Box::new(PathPrefixExtractor::new()),
            ]);

            // Only the path has a valid org — host has dots so HostExtractor
            // fails, and the first label is uppercase so SubdomainExtractor
            // also fails Segment validation.
            let req = request("/zeta/api", vec![("host", "INVALID.example.com")]);
            let org = chain.extract(&req).unwrap();
            assert_eq!(org.as_str(), "zeta");
        }

        #[test]
        fn chain_implements_tenant_extractor() {
            // Verify TenantExtractorChain can itself be boxed as a TenantExtractor
            let inner = TenantExtractorChain::new(vec![Box::new(HeaderExtractor::new("x-org"))]);
            let outer = TenantExtractorChain::new(vec![Box::new(inner)]);
            let req = request("/", vec![("x-org", "acme")]);
            let org = outer.extract(&req).unwrap();
            assert_eq!(org.as_str(), "acme");
        }
    }
}
