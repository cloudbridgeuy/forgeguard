//! HTTP method enum — no dependency on the `http` crate.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// HTTP methods supported by ForgeGuard route matching.
///
/// `Any` is a wildcard that matches all methods. Used when a route applies
/// regardless of the HTTP verb.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Any,
}

impl HttpMethod {
    /// Returns `true` if `self` matches `other`.
    ///
    /// `Any` matches everything. A concrete method matches itself or `Any`.
    pub fn matches(&self, other: &HttpMethod) -> bool {
        matches!(
            (self, other),
            (HttpMethod::Any, _)
                | (_, HttpMethod::Any)
                | (HttpMethod::Get, HttpMethod::Get)
                | (HttpMethod::Post, HttpMethod::Post)
                | (HttpMethod::Put, HttpMethod::Put)
                | (HttpMethod::Patch, HttpMethod::Patch)
                | (HttpMethod::Delete, HttpMethod::Delete)
        )
    }
}

impl FromStr for HttpMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "PATCH" => Ok(HttpMethod::Patch),
            "DELETE" => Ok(HttpMethod::Delete),
            "ANY" | "*" => Ok(HttpMethod::Any),
            _ => Err(Error::Config(format!("unknown HTTP method: '{s}'"))),
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Any => write!(f, "ANY"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const CONCRETE: &[HttpMethod] = &[
        HttpMethod::Get,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Patch,
        HttpMethod::Delete,
    ];

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("get".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("GET".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("Get".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("post".parse::<HttpMethod>().unwrap(), HttpMethod::Post);
        assert_eq!("put".parse::<HttpMethod>().unwrap(), HttpMethod::Put);
        assert_eq!("patch".parse::<HttpMethod>().unwrap(), HttpMethod::Patch);
        assert_eq!("delete".parse::<HttpMethod>().unwrap(), HttpMethod::Delete);
        assert_eq!("any".parse::<HttpMethod>().unwrap(), HttpMethod::Any);
        assert_eq!("ANY".parse::<HttpMethod>().unwrap(), HttpMethod::Any);
        assert_eq!("*".parse::<HttpMethod>().unwrap(), HttpMethod::Any);
    }

    #[test]
    fn from_str_invalid() {
        assert!("OPTIONS".parse::<HttpMethod>().is_err());
        assert!("HEAD".parse::<HttpMethod>().is_err());
        assert!("".parse::<HttpMethod>().is_err());
    }

    #[test]
    fn display_round_trip() {
        for method in CONCRETE {
            let s = method.to_string();
            let parsed: HttpMethod = s.parse().unwrap();
            assert_eq!(*method, parsed);
        }
        let any = HttpMethod::Any;
        let parsed: HttpMethod = any.to_string().parse().unwrap();
        assert_eq!(any, parsed);
    }

    #[test]
    fn matches_same_method() {
        assert!(HttpMethod::Get.matches(&HttpMethod::Get));
        assert!(HttpMethod::Post.matches(&HttpMethod::Post));
    }

    #[test]
    fn matches_any_matches_all() {
        for method in CONCRETE {
            assert!(HttpMethod::Any.matches(method));
            assert!(method.matches(&HttpMethod::Any));
        }
        assert!(HttpMethod::Any.matches(&HttpMethod::Any));
    }

    #[test]
    fn matches_different_concrete_methods_do_not_match() {
        assert!(!HttpMethod::Get.matches(&HttpMethod::Post));
        assert!(!HttpMethod::Put.matches(&HttpMethod::Delete));
        assert!(!HttpMethod::Patch.matches(&HttpMethod::Get));
    }
}
