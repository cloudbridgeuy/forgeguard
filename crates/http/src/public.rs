//! Public route matching: bypass auth for configured paths.

use std::collections::HashMap;

use crate::method::HttpMethod;
use crate::route::normalize_path;
use crate::Result;

// ---------------------------------------------------------------------------
// PublicAuthMode
// ---------------------------------------------------------------------------

/// How authentication is handled for a public route.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicAuthMode {
    /// No authentication attempted at all.
    Anonymous,
    /// Try to authenticate; if it fails, proceed without identity.
    Opportunistic,
}

// ---------------------------------------------------------------------------
// PublicRoute
// ---------------------------------------------------------------------------

/// A public route definition from the config file.
#[derive(Debug, Clone)]
pub struct PublicRoute {
    method: HttpMethod,
    path_pattern: String,
    auth_mode: PublicAuthMode,
}

impl PublicRoute {
    /// Construct a new public route.
    pub fn new(method: HttpMethod, path_pattern: String, auth_mode: PublicAuthMode) -> Self {
        Self {
            method,
            path_pattern,
            auth_mode,
        }
    }

    /// The HTTP method for this route.
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    /// The path pattern (matchit syntax).
    pub fn path_pattern(&self) -> &str {
        &self.path_pattern
    }

    /// The authentication mode.
    pub fn auth_mode(&self) -> PublicAuthMode {
        self.auth_mode
    }
}

// ---------------------------------------------------------------------------
// PublicMatch
// ---------------------------------------------------------------------------

/// The result of checking a request against public routes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicMatch {
    /// The request does not match any public route.
    NotPublic,
    /// The request matches a public route with anonymous mode.
    Anonymous,
    /// The request matches a public route with opportunistic mode.
    Opportunistic,
}

// ---------------------------------------------------------------------------
// PublicRouteMatcher
// ---------------------------------------------------------------------------

/// Radix-trie matcher for public routes. Same structure as `RouteMatcher`
/// but returns `PublicMatch` instead of `MatchedRoute`.
pub struct PublicRouteMatcher {
    routers: HashMap<HttpMethod, matchit::Router<PublicAuthMode>>,
    any_router: matchit::Router<PublicAuthMode>,
}

impl PublicRouteMatcher {
    /// Build a public route matcher from a list of public routes.
    pub fn new(routes: &[PublicRoute]) -> Result<Self> {
        let mut method_routers: HashMap<HttpMethod, matchit::Router<PublicAuthMode>> =
            HashMap::new();
        let mut any_router = matchit::Router::new();

        for route in routes {
            let pattern = normalize_path(route.path_pattern());

            if route.method() == HttpMethod::Any {
                any_router
                    .insert(&pattern, route.auth_mode())
                    .map_err(|e| {
                        crate::Error::Config(format!(
                            "failed to insert public route ANY {}: {e}",
                            route.path_pattern()
                        ))
                    })?;
            } else {
                let router = method_routers.entry(route.method()).or_default();
                router.insert(&pattern, route.auth_mode()).map_err(|e| {
                    crate::Error::Config(format!(
                        "failed to insert public route {} {}: {e}",
                        route.method(),
                        route.path_pattern()
                    ))
                })?;
            }
        }

        Ok(Self {
            routers: method_routers,
            any_router,
        })
    }

    /// Check a request against public routes.
    ///
    /// Method-specific router checked first, then `Any` fallback.
    pub fn check(&self, method: &str, path: &str) -> PublicMatch {
        let Ok(parsed_method) = method.parse::<HttpMethod>() else {
            return PublicMatch::NotPublic;
        };
        let normalized = normalize_path(path);

        // Try method-specific router first
        if let Some(router) = self.routers.get(&parsed_method) {
            if let Ok(matched) = router.at(&normalized) {
                return match matched.value {
                    PublicAuthMode::Anonymous => PublicMatch::Anonymous,
                    PublicAuthMode::Opportunistic => PublicMatch::Opportunistic,
                };
            }
        }

        // Fall back to Any router
        if let Ok(matched) = self.any_router.at(&normalized) {
            return match matched.value {
                PublicAuthMode::Anonymous => PublicMatch::Anonymous,
                PublicAuthMode::Opportunistic => PublicMatch::Opportunistic,
            };
        }

        PublicMatch::NotPublic
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_public(method: &str, pattern: &str, mode: PublicAuthMode) -> PublicRoute {
        PublicRoute::new(method.parse().unwrap(), pattern.to_string(), mode)
    }

    #[test]
    fn anonymous_match() {
        let routes = vec![make_public("GET", "/health", PublicAuthMode::Anonymous)];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(matcher.check("GET", "/health"), PublicMatch::Anonymous);
    }

    #[test]
    fn opportunistic_match() {
        let routes = vec![make_public(
            "GET",
            "/public/docs",
            PublicAuthMode::Opportunistic,
        )];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(
            matcher.check("GET", "/public/docs"),
            PublicMatch::Opportunistic
        );
    }

    #[test]
    fn not_public() {
        let routes = vec![make_public("GET", "/health", PublicAuthMode::Anonymous)];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(matcher.check("GET", "/private"), PublicMatch::NotPublic);
    }

    #[test]
    fn method_specificity() {
        let routes = vec![
            make_public("GET", "/data", PublicAuthMode::Anonymous),
            make_public("ANY", "/data", PublicAuthMode::Opportunistic),
        ];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        // GET matches method-specific route
        assert_eq!(matcher.check("GET", "/data"), PublicMatch::Anonymous);
        // POST falls back to ANY
        assert_eq!(matcher.check("POST", "/data"), PublicMatch::Opportunistic);
    }

    #[test]
    fn wrong_method_not_public() {
        let routes = vec![make_public("GET", "/health", PublicAuthMode::Anonymous)];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(matcher.check("POST", "/health"), PublicMatch::NotPublic);
    }

    #[test]
    fn trailing_slash_tolerance() {
        let routes = vec![make_public("GET", "/health", PublicAuthMode::Anonymous)];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(matcher.check("GET", "/health/"), PublicMatch::Anonymous);
    }

    #[test]
    fn param_in_public_route() {
        let routes = vec![make_public(
            "GET",
            "/docs/{slug}",
            PublicAuthMode::Anonymous,
        )];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(
            matcher.check("GET", "/docs/getting-started"),
            PublicMatch::Anonymous
        );
    }

    #[test]
    fn invalid_method_returns_not_public() {
        let routes = vec![make_public("GET", "/health", PublicAuthMode::Anonymous)];
        let matcher = PublicRouteMatcher::new(&routes).unwrap();
        assert_eq!(matcher.check("OPTIONS", "/health"), PublicMatch::NotPublic);
    }
}
