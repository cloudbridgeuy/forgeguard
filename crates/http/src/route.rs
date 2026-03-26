//! Route matching: `(method, path)` → `(action, resource)`.
//!
//! Uses `matchit` radix tries for O(1)-ish matching with path parameter extraction.

use std::collections::HashMap;

use forgeguard_core::{FlagName, QualifiedAction, ResourceId, ResourceRef};

use crate::method::HttpMethod;
use crate::Result;

// ---------------------------------------------------------------------------
// RouteMapping
// ---------------------------------------------------------------------------

/// A route definition from the config file. Links an HTTP method + path pattern
/// to a policy action and optional resource parameter extraction.
#[derive(Debug, Clone)]
pub struct RouteMapping {
    method: HttpMethod,
    path_pattern: String,
    action: QualifiedAction,
    resource_param: Option<String>,
    feature_gate: Option<FlagName>,
}

impl RouteMapping {
    /// Construct a new route mapping.
    pub fn new(
        method: HttpMethod,
        path_pattern: String,
        action: QualifiedAction,
        resource_param: Option<String>,
        feature_gate: Option<FlagName>,
    ) -> Self {
        Self {
            method,
            path_pattern,
            action,
            resource_param,
            feature_gate,
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

    /// The policy action triggered by this route.
    pub fn action(&self) -> &QualifiedAction {
        &self.action
    }

    /// The name of the path param to extract as a resource ID.
    pub fn resource_param(&self) -> Option<&str> {
        self.resource_param.as_deref()
    }

    /// Optional feature flag gate.
    pub fn feature_gate(&self) -> Option<&FlagName> {
        self.feature_gate.as_ref()
    }
}

// ---------------------------------------------------------------------------
// MatchedRoute
// ---------------------------------------------------------------------------

/// The result of a successful route match.
#[derive(Debug)]
pub struct MatchedRoute {
    action: QualifiedAction,
    resource: Option<ResourceRef>,
    path_params: HashMap<String, String>,
    feature_gate: Option<FlagName>,
}

impl MatchedRoute {
    /// The policy action for the matched route.
    pub fn action(&self) -> &QualifiedAction {
        &self.action
    }

    /// The extracted resource reference, if a resource_param was configured.
    pub fn resource(&self) -> Option<&ResourceRef> {
        self.resource.as_ref()
    }

    /// All extracted path parameters.
    pub fn path_params(&self) -> &HashMap<String, String> {
        &self.path_params
    }

    /// Optional feature flag gate.
    pub fn feature_gate(&self) -> Option<&FlagName> {
        self.feature_gate.as_ref()
    }
}

// ---------------------------------------------------------------------------
// RouteValue (stored inside the matchit router)
// ---------------------------------------------------------------------------

/// Data stored in each matchit router slot.
#[derive(Debug, Clone)]
struct RouteValue {
    action: QualifiedAction,
    resource_param: Option<String>,
    feature_gate: Option<FlagName>,
}

// ---------------------------------------------------------------------------
// RouteMatcher
// ---------------------------------------------------------------------------

/// Radix-trie route matcher backed by `matchit`.
///
/// Maintains one `matchit::Router` per concrete HTTP method plus one for `Any`.
/// Lookup checks the method-specific router first, then falls back to `Any`.
pub struct RouteMatcher {
    routers: HashMap<HttpMethod, matchit::Router<RouteValue>>,
    any_router: matchit::Router<RouteValue>,
}

impl RouteMatcher {
    /// Build a route matcher from a list of route mappings.
    ///
    /// Routes are inserted into per-method tries at construction time.
    /// The matcher is immutable after construction.
    pub fn new(routes: &[RouteMapping]) -> Result<Self> {
        let mut method_routers: HashMap<HttpMethod, matchit::Router<RouteValue>> = HashMap::new();
        let mut any_router = matchit::Router::new();

        for route in routes {
            let value = RouteValue {
                action: route.action().clone(),
                resource_param: route.resource_param.clone(),
                feature_gate: route.feature_gate.clone(),
            };

            let pattern = normalize_path(route.path_pattern());

            if route.method() == HttpMethod::Any {
                any_router.insert(&pattern, value).map_err(|e| {
                    crate::Error::Config(format!(
                        "failed to insert route ANY {}: {e}",
                        route.path_pattern()
                    ))
                })?;
            } else {
                let router = method_routers.entry(route.method()).or_default();
                router.insert(&pattern, value).map_err(|e| {
                    crate::Error::Config(format!(
                        "failed to insert route {} {}: {e}",
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

    /// Match a request method + path against the configured routes.
    ///
    /// Method-specific router is checked first; if no match, the `Any` router
    /// is consulted as a fallback. Returns `None` if no route matches.
    pub fn match_request(&self, method: &str, path: &str) -> Option<MatchedRoute> {
        let parsed_method: HttpMethod = method.parse().ok()?;
        let normalized = normalize_path(path);

        // Try method-specific router first
        if let Some(router) = self.routers.get(&parsed_method) {
            if let Ok(matched) = router.at(&normalized) {
                return Some(build_matched_route(&matched));
            }
        }

        // Fall back to Any router
        if let Ok(matched) = self.any_router.at(&normalized) {
            return Some(build_matched_route(&matched));
        }

        None
    }
}

/// Normalize a path by stripping trailing slash (unless the path is just "/").
pub(crate) fn normalize_path(path: &str) -> String {
    if path.len() > 1 && path.ends_with('/') {
        path[..path.len() - 1].to_string()
    } else {
        path.to_string()
    }
}

/// Build a `MatchedRoute` from a `matchit::Match`.
fn build_matched_route(matched: &matchit::Match<'_, '_, &RouteValue>) -> MatchedRoute {
    let value = matched.value;
    let params: HashMap<String, String> = matched
        .params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let resource = value.resource_param.as_ref().and_then(|param_name| {
        params
            .get(param_name)
            .and_then(|id_str| ResourceId::parse(id_str).ok())
            .map(|rid| ResourceRef::from_route(&value.action, rid))
    });

    MatchedRoute {
        action: value.action.clone(),
        resource,
        path_params: params,
        feature_gate: value.feature_gate.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_route(
        method: &str,
        pattern: &str,
        action: &str,
        resource_param: Option<&str>,
    ) -> RouteMapping {
        RouteMapping::new(
            method.parse().unwrap(),
            pattern.to_string(),
            QualifiedAction::parse(action).unwrap(),
            resource_param.map(String::from),
            None,
        )
    }

    #[test]
    fn exact_path_match() {
        let routes = vec![make_route("GET", "/users", "todo:list:user", None)];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher.match_request("GET", "/users").unwrap();
        assert_eq!(m.action().to_string(), "todo:list:user");
    }

    #[test]
    fn param_capture() {
        let routes = vec![make_route(
            "GET",
            "/users/{id}",
            "todo:read:user",
            Some("id"),
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher.match_request("GET", "/users/alice").unwrap();
        assert_eq!(m.action().to_string(), "todo:read:user");
        assert_eq!(m.path_params().get("id").unwrap(), "alice");
        assert!(m.resource().is_some());
    }

    #[test]
    fn multi_param() {
        let routes = vec![make_route(
            "GET",
            "/orgs/{org}/projects/{project}",
            "todo:read:project",
            Some("project"),
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher
            .match_request("GET", "/orgs/acme/projects/web-app")
            .unwrap();
        assert_eq!(m.path_params().get("org").unwrap(), "acme");
        assert_eq!(m.path_params().get("project").unwrap(), "web-app");
        assert!(m.resource().is_some());
    }

    #[test]
    fn catch_all() {
        let routes = vec![make_route(
            "ANY",
            "/admin/{*rest}",
            "admin:access:panel",
            None,
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher.match_request("GET", "/admin/users/list").unwrap();
        assert_eq!(m.path_params().get("rest").unwrap(), "users/list");
    }

    #[test]
    fn method_specificity_over_any() {
        let routes = vec![
            make_route("GET", "/items", "todo:read:item", None),
            make_route("ANY", "/items", "todo:access:item", None),
        ];
        let matcher = RouteMatcher::new(&routes).unwrap();

        // GET should match the specific GET route
        let m = matcher.match_request("GET", "/items").unwrap();
        assert_eq!(m.action().to_string(), "todo:read:item");

        // POST should fall back to ANY
        let m = matcher.match_request("POST", "/items").unwrap();
        assert_eq!(m.action().to_string(), "todo:access:item");
    }

    #[test]
    fn trailing_slash_tolerance() {
        let routes = vec![make_route("GET", "/users", "todo:list:user", None)];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher.match_request("GET", "/users/").unwrap();
        assert_eq!(m.action().to_string(), "todo:list:user");
    }

    #[test]
    fn no_match_returns_none() {
        let routes = vec![make_route("GET", "/users", "todo:list:user", None)];
        let matcher = RouteMatcher::new(&routes).unwrap();
        assert!(matcher.match_request("GET", "/nonexistent").is_none());
    }

    #[test]
    fn wrong_method_no_match() {
        let routes = vec![make_route("GET", "/users", "todo:list:user", None)];
        let matcher = RouteMatcher::new(&routes).unwrap();
        assert!(matcher.match_request("POST", "/users").is_none());
    }

    #[test]
    fn feature_gate_propagated() {
        let routes = vec![RouteMapping::new(
            HttpMethod::Get,
            "/beta".to_string(),
            QualifiedAction::parse("todo:read:beta").unwrap(),
            None,
            Some(FlagName::parse("beta-feature").unwrap()),
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher.match_request("GET", "/beta").unwrap();
        assert!(m.feature_gate().is_some());
        assert_eq!(m.feature_gate().unwrap().to_string(), "beta-feature");
    }

    #[test]
    fn resource_param_invalid_segment_skipped() {
        // Resource IDs must be valid Segments — uppercase is invalid
        let routes = vec![make_route(
            "GET",
            "/users/{id}",
            "todo:read:user",
            Some("id"),
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        // "Alice" has uppercase, so ResourceId::parse fails → resource is None
        let m = matcher.match_request("GET", "/users/Alice").unwrap();
        assert!(m.resource().is_none());
        assert_eq!(m.path_params().get("id").unwrap(), "Alice");
    }
}
