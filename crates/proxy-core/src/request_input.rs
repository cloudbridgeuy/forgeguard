//! Validated request input for the auth pipeline.

use std::net::IpAddr;

use forgeguard_http::HttpMethod;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// RequestInput
// ---------------------------------------------------------------------------

/// A validated, protocol-agnostic representation of an incoming request.
///
/// Constructed via [`RequestInput::new`] which validates method and path at
/// construction time (Parse Don't Validate). The path must start with `/`.
#[derive(Debug)]
pub struct RequestInput {
    method: HttpMethod,
    path: String,
    query_string: Option<String>,
    headers: Vec<(String, String)>,
    client_ip: Option<IpAddr>,
}

impl RequestInput {
    /// Construct a new `RequestInput`, validating the method and path.
    ///
    /// # Headers
    ///
    /// Header names are stored as-is in `(name, value)` pairs. Because HTTP
    /// header names are case-insensitive (RFC 9110 §5.1), but downstream code
    /// may perform **case-sensitive** lookups, callers **must** lowercase all
    /// header names before passing them here (e.g. `"content-type"`, not
    /// `"Content-Type"`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] if:
    /// - `method` is not a recognized HTTP method
    /// - `path` is empty or does not start with `/`
    pub fn new(
        method: &str,
        path: impl Into<String>,
        headers: Vec<(String, String)>,
        client_ip: Option<IpAddr>,
    ) -> Result<Self> {
        let method: HttpMethod = method
            .parse()
            .map_err(|_| Error::InvalidRequest(format!("unrecognized HTTP method: '{method}'")))?;

        let path = path.into();

        if path.is_empty() {
            return Err(Error::InvalidRequest("path cannot be empty".to_string()));
        }
        if !path.starts_with('/') {
            return Err(Error::InvalidRequest(format!(
                "path must start with '/': '{path}'"
            )));
        }

        Ok(Self {
            method,
            path,
            query_string: None,
            headers,
            client_ip,
        })
    }

    /// Set the query string (e.g. `"user_id=alice&tenant_id=acme"`).
    ///
    /// The query string is the part after `?` in the URI, without the leading `?`.
    /// Used by the debug endpoint to parse flag evaluation parameters.
    pub fn with_query_string(mut self, query: impl Into<String>) -> Self {
        self.query_string = Some(query.into());
        self
    }

    /// The parsed HTTP method.
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    /// The request path (always starts with `/`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query string, if present (without leading `?`).
    pub fn query_string(&self) -> Option<&str> {
        self.query_string.as_deref()
    }

    /// The request headers as `(name, value)` pairs.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The client IP address, if known.
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_get_request() {
        let input = RequestInput::new("GET", "/api/users", vec![], None).unwrap();
        assert_eq!(input.method(), HttpMethod::Get);
        assert_eq!(input.path(), "/api/users");
        assert!(input.headers().is_empty());
        assert!(input.client_ip().is_none());
    }

    #[test]
    fn valid_post_with_headers_and_ip() {
        let headers = vec![
            ("authorization".to_string(), "Bearer tok".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let input = RequestInput::new("POST", "/items", headers.clone(), Some(ip)).unwrap();
        assert_eq!(input.method(), HttpMethod::Post);
        assert_eq!(input.path(), "/items");
        assert_eq!(input.headers().len(), 2);
        assert_eq!(input.headers()[0].0, "authorization");
        assert_eq!(input.client_ip(), Some(ip));
    }

    #[test]
    fn case_insensitive_method() {
        let input = RequestInput::new("delete", "/resource", vec![], None).unwrap();
        assert_eq!(input.method(), HttpMethod::Delete);
    }

    #[test]
    fn root_path_is_valid() {
        let input = RequestInput::new("GET", "/", vec![], None).unwrap();
        assert_eq!(input.path(), "/");
    }

    #[test]
    fn rejects_empty_path() {
        let err = RequestInput::new("GET", "", vec![], None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "expected 'empty' in: {msg}");
    }

    #[test]
    fn rejects_path_without_leading_slash() {
        let err = RequestInput::new("GET", "no-slash", vec![], None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must start with '/'"),
            "expected slash message in: {msg}"
        );
    }

    #[test]
    fn rejects_invalid_method() {
        let err = RequestInput::new("CONNECT", "/path", vec![], None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unrecognized HTTP method"),
            "expected method message in: {msg}"
        );
    }

    #[test]
    fn ipv6_client_ip() {
        let ip: IpAddr = "::1".parse().unwrap();
        let input = RequestInput::new("GET", "/test", vec![], Some(ip)).unwrap();
        assert_eq!(input.client_ip(), Some(ip));
    }
}
