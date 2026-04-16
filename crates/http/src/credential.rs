//! Credential extraction from HTTP headers.

use forgeguard_authn_core::Credential;

/// Case-insensitive header lookup returning the first matching value.
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Extract a credential from HTTP headers.
///
/// Priority order:
/// 1. `Authorization: Bearer <token>` — JWT
/// 2. `X-API-Key: <key>` — API key
/// 3. `X-ForgeGuard-Signature` + `X-ForgeGuard-Timestamp` + `X-ForgeGuard-Key-Id`
///    + `X-ForgeGuard-Trace-Id` — Ed25519 signed request (BYOC proxy)
///
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

    // Priority 3: X-ForgeGuard-Signature (Ed25519 signed request)
    let sig_header = find_header(headers, "x-forgeguard-signature");
    let ts_header = find_header(headers, "x-forgeguard-timestamp");
    let key_id_header = find_header(headers, "x-forgeguard-key-id");
    let trace_id_header = find_header(headers, "x-forgeguard-trace-id");

    if let (Some(sig), Some(ts), Some(key_id), Some(trace_id)) =
        (sig_header, ts_header, key_id_header, trace_id_header)
    {
        if let Ok(timestamp) = ts.parse::<u64>() {
            let identity_headers: Vec<(String, String)> = headers
                .iter()
                .filter(|(k, _)| {
                    let lower = k.to_ascii_lowercase();
                    lower.starts_with("x-forgeguard-")
                        && lower != "x-forgeguard-signature"
                        && lower != "x-forgeguard-timestamp"
                        && lower != "x-forgeguard-key-id"
                        && lower != "x-forgeguard-trace-id"
                })
                .cloned()
                .collect();

            return Some(Credential::SignedRequest {
                key_id: key_id.to_string(),
                timestamp,
                signature: sig.to_string(),
                trace_id: trace_id.to_string(),
                identity_headers,
            });
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

    #[test]
    fn signed_request_extracted() {
        let headers = h(&[
            ("x-forgeguard-signature", "v1:AAAA"),
            ("x-forgeguard-timestamp", "1700000000000"),
            ("x-forgeguard-key-id", "key-001"),
            ("x-forgeguard-trace-id", "trace-abc"),
        ]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(
            cred,
            Credential::SignedRequest {
                key_id: "key-001".into(),
                timestamp: 1_700_000_000_000,
                signature: "v1:AAAA".into(),
                trace_id: "trace-abc".into(),
                identity_headers: vec![],
            }
        );
    }

    #[test]
    fn signed_request_includes_identity_headers() {
        let headers = h(&[
            ("x-forgeguard-signature", "v1:AAAA"),
            ("x-forgeguard-timestamp", "1700000000000"),
            ("x-forgeguard-key-id", "key-001"),
            ("x-forgeguard-trace-id", "trace-abc"),
            ("X-ForgeGuard-Org-Id", "org-123"),
        ]);
        let cred = extract_credential(&headers).unwrap();
        match cred {
            Credential::SignedRequest {
                identity_headers, ..
            } => {
                assert_eq!(identity_headers.len(), 1);
                assert_eq!(identity_headers[0].0, "X-ForgeGuard-Org-Id");
                assert_eq!(identity_headers[0].1, "org-123");
            }
            other => panic!("expected SignedRequest, got {other:?}"),
        }
    }

    #[test]
    fn signed_request_missing_signature_returns_none() {
        // Only 3 of 4 required headers — no signature
        let headers = h(&[
            ("x-forgeguard-timestamp", "1700000000000"),
            ("x-forgeguard-key-id", "key-001"),
            ("x-forgeguard-trace-id", "trace-abc"),
        ]);
        assert!(extract_credential(&headers).is_none());
    }

    #[test]
    fn signed_request_invalid_timestamp_returns_none() {
        let headers = h(&[
            ("x-forgeguard-signature", "v1:AAAA"),
            ("x-forgeguard-timestamp", "not-a-number"),
            ("x-forgeguard-key-id", "key-001"),
            ("x-forgeguard-trace-id", "trace-abc"),
        ]);
        assert!(extract_credential(&headers).is_none());
    }

    #[test]
    fn bearer_takes_priority_over_signed_request() {
        let headers = h(&[
            ("authorization", "Bearer tok_abc"),
            ("x-forgeguard-signature", "v1:AAAA"),
            ("x-forgeguard-timestamp", "1700000000000"),
            ("x-forgeguard-key-id", "key-001"),
            ("x-forgeguard-trace-id", "trace-abc"),
        ]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::Bearer("tok_abc".into()));
    }

    #[test]
    fn api_key_takes_priority_over_signed_request() {
        let headers = h(&[
            ("x-api-key", "key_xyz"),
            ("x-forgeguard-signature", "v1:AAAA"),
            ("x-forgeguard-timestamp", "1700000000000"),
            ("x-forgeguard-key-id", "key-001"),
            ("x-forgeguard-trace-id", "trace-abc"),
        ]);
        let cred = extract_credential(&headers).unwrap();
        assert_eq!(cred, Credential::ApiKey("key_xyz".into()));
    }
}
