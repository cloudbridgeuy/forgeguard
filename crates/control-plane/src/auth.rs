//! Bearer token authentication — pure functions.

/// Result of extracting a bearer token from the Authorization header.
pub(crate) enum BearerToken<'a> {
    /// A valid `fgt_`-prefixed token was found.
    Valid(&'a str),
    /// No Authorization header present.
    Missing,
    /// Header present but not a valid `Bearer fgt_...` token.
    Invalid,
}

/// Extract a bearer token from the Authorization header value.
///
/// Expects format: `Bearer fgt_<token>`. Returns the full token string
/// including `fgt_` prefix.
pub(crate) fn extract_bearer_token(auth_header: Option<&str>) -> BearerToken<'_> {
    let Some(header) = auth_header else {
        return BearerToken::Missing;
    };
    let Some(token) = header.strip_prefix("Bearer ") else {
        return BearerToken::Invalid;
    };
    if !token.starts_with("fgt_") || token.len() <= 4 {
        return BearerToken::Invalid;
    }
    BearerToken::Valid(token)
}

/// Check whether a token is authorized to access a specific organization.
// TODO: use constant-time comparison (e.g., `subtle::ConstantTimeEq`) before production.
pub(crate) fn token_matches_org(request_token: &str, stored_token: &str) -> bool {
    request_token == stored_token
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_valid_fgt_token() {
        let result = extract_bearer_token(Some("Bearer fgt_acme_secret"));
        assert!(matches!(result, BearerToken::Valid("fgt_acme_secret")));
    }

    #[test]
    fn extract_missing_header() {
        let result = extract_bearer_token(None);
        assert!(matches!(result, BearerToken::Missing));
    }

    #[test]
    fn extract_non_bearer_scheme() {
        let result = extract_bearer_token(Some("Basic dXNlcjpwYXNz"));
        assert!(matches!(result, BearerToken::Invalid));
    }

    #[test]
    fn extract_bearer_without_fgt_prefix() {
        let result = extract_bearer_token(Some("Bearer some_other_token"));
        assert!(matches!(result, BearerToken::Invalid));
    }

    #[test]
    fn extract_bearer_empty_token() {
        let result = extract_bearer_token(Some("Bearer "));
        assert!(matches!(result, BearerToken::Invalid));
    }

    #[test]
    fn extract_bearer_only_fgt_prefix() {
        let result = extract_bearer_token(Some("Bearer fgt_"));
        assert!(matches!(result, BearerToken::Invalid));
    }

    #[test]
    fn token_matches_same() {
        assert!(token_matches_org("fgt_abc", "fgt_abc"));
    }

    #[test]
    fn token_does_not_match() {
        assert!(!token_matches_org("fgt_abc", "fgt_xyz"));
    }
}
