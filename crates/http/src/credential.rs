//! Credential extraction from HTTP headers.

use forgeguard_authn_core::Credential;

/// Extract a credential from HTTP headers.
///
/// Checks `Authorization: Bearer <token>` first, then `X-API-Key: <key>`.
/// Header names are compared case-insensitively (HTTP/2 mandates lowercase,
/// HTTP/1.1 is case-insensitive).
///
/// Returns the first credential found, or `None` if no credential is present.
pub fn extract_credential(headers: &[(String, String)]) -> Option<Credential> {
    // Priority 1: Authorization: Bearer
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("authorization") {
            let trimmed = value.trim();
            if let Some(token) = trimmed.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(Credential::Bearer(token.to_string()));
                }
            }
            // Also handle lowercase "bearer"
            if let Some(token) = trimmed.strip_prefix("bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(Credential::Bearer(token.to_string()));
                }
            }
        }
    }

    // Priority 2: X-API-Key
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-api-key") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(Credential::ApiKey(trimmed.to_string()));
            }
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn bearer_token_extracted() {
        let headers = h(&[("authorization", "Bearer tok_abc123")]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::Bearer("tok_abc123".to_string()));
    }

    #[test]
    fn api_key_extracted() {
        let headers = h(&[("x-api-key", "key_xyz")]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::ApiKey("key_xyz".to_string()));
    }

    #[test]
    fn bearer_takes_priority_over_api_key() {
        let headers = h(&[
            ("authorization", "Bearer tok_abc"),
            ("x-api-key", "key_xyz"),
        ]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::Bearer("tok_abc".to_string()));
    }

    #[test]
    fn no_credential_returns_none() {
        let headers = h(&[("content-type", "application/json")]);
        assert!(extract_credential(&headers).is_none());
    }

    #[test]
    fn empty_headers_returns_none() {
        assert!(extract_credential(&[]).is_none());
    }

    #[test]
    fn header_names_case_insensitive() {
        let headers = h(&[("Authorization", "Bearer tok_abc")]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::Bearer("tok_abc".to_string()));

        let headers = h(&[("X-Api-Key", "key_xyz")]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::ApiKey("key_xyz".to_string()));
    }

    #[test]
    fn bearer_prefix_case_insensitive() {
        let headers = h(&[("authorization", "bearer tok_abc")]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::Bearer("tok_abc".to_string()));
    }

    #[test]
    fn empty_bearer_token_skipped() {
        let headers = h(&[("authorization", "Bearer "), ("x-api-key", "key_xyz")]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::ApiKey("key_xyz".to_string()));
    }

    #[test]
    fn empty_api_key_skipped() {
        let headers = h(&[("x-api-key", "   ")]);
        assert!(extract_credential(&headers).is_none());
    }

    #[test]
    fn authorization_without_bearer_prefix_skipped() {
        let headers = h(&[
            ("authorization", "Basic dXNlcjpwYXNz"),
            ("x-api-key", "key_xyz"),
        ]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::ApiKey("key_xyz".to_string()));
    }
}
