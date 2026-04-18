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
    /// Optional Cedar entity type for the resource. When set, overrides the
    /// auto-derived `{namespace}__{entity}` format in VP requests.
    resource_entity_type: Option<String>,
    /// Fallback resource ID used when no `resource_param` is present in the path.
    /// Enables collection-level endpoints to pass a synthetic resource to VP.
    default_resource_id: Option<ResourceId>,
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
            resource_entity_type: None,
            default_resource_id: None,
        }
    }

    /// Set an explicit Cedar entity type for the resource.
    pub fn with_resource_entity_type(mut self, entity_type: impl Into<String>) -> Self {
        self.resource_entity_type = Some(entity_type.into());
        self
    }

    /// Set a default resource ID used when no path parameter is present.
    ///
    /// The ID must be a valid `ResourceId` (kebab-case, `[a-z0-9-]`). Returns
    /// an error if the value is invalid so misconfigured routes fail at startup.
    pub fn with_default_resource_id(mut self, id: &str) -> Result<Self> {
        self.default_resource_id = Some(ResourceId::parse(id).map_err(|e| {
            crate::Error::Config(format!("invalid default_resource_id {id:?}: {e}"))
        })?);
        Ok(self)
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
    resource_entity_type: Option<String>,
    default_resource_id: Option<ResourceId>,
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
                resource_entity_type: route.resource_entity_type.clone(),
                default_resource_id: route.default_resource_id.clone(),
            };

            let pattern = normalize_pattern(&normalize_path(route.path_pattern()));

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

/// Convert user-facing `:param` path syntax to matchit's `{param}` syntax.
///
/// Only applied to route patterns during router construction, never to request paths.
/// Handles multiple params (`:id`, `:item_id`) and preserves `{param}` if already present.
///
/// # Examples
///
/// - `/api/lists/:id` → `/api/lists/{id}`
/// - `/api/lists/:id/items/:item_id` → `/api/lists/{id}/items/{item_id}`
/// - `/api/lists/{id}` → `/api/lists/{id}` (unchanged)
/// - `/health` → `/health` (unchanged)
pub(crate) fn normalize_pattern(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == ':' {
            let mut name = String::new();
            while let Some(&next) = chars.peek() {
                if next.is_alphanumeric() || next == '_' {
                    chars.next();
                    name.push(next);
                } else {
                    break;
                }
            }
            if name.is_empty() {
                // Bare colon with no param name — pass through literally
                result.push(':');
            } else {
                result.push('{');
                result.push_str(&name);
                result.push('}');
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Build a `MatchedRoute` from a `matchit::Match`.
fn build_matched_route(matched: &matchit::Match<'_, '_, &RouteValue>) -> MatchedRoute {
    let value = matched.value;
    let params: HashMap<String, String> = matched
        .params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let resolved_id = value
        .resource_param
        .as_ref()
        .and_then(|param_name| {
            params
                .get(param_name)
                .and_then(|id_str| ResourceId::parse(id_str).ok())
        })
        .or_else(|| value.default_resource_id.clone());

    let resource = resolved_id.map(|rid| match &value.resource_entity_type {
        Some(entity_type) => {
            ResourceRef::from_route_with_entity_type(&value.action, rid, entity_type.clone())
        }
        None => ResourceRef::from_route(&value.action, rid),
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
    fn normalize_pattern_single_param() {
        assert_eq!(normalize_pattern("/users/:id"), "/users/{id}");
    }

    #[test]
    fn normalize_pattern_multiple_params() {
        assert_eq!(
            normalize_pattern("/lists/:id/items/:item_id"),
            "/lists/{id}/items/{item_id}"
        );
    }

    #[test]
    fn normalize_pattern_no_params() {
        assert_eq!(normalize_pattern("/health"), "/health");
    }

    #[test]
    fn normalize_pattern_already_braced() {
        assert_eq!(normalize_pattern("/users/{id}"), "/users/{id}");
    }

    #[test]
    fn normalize_pattern_mixed() {
        assert_eq!(
            normalize_pattern("/orgs/:org/projects/{project}"),
            "/orgs/{org}/projects/{project}"
        );
    }

    #[test]
    fn normalize_pattern_underscore_in_param() {
        assert_eq!(
            normalize_pattern("/items/:item_id/complete"),
            "/items/{item_id}/complete"
        );
    }

    #[test]
    fn normalize_pattern_bare_colon() {
        assert_eq!(normalize_pattern("/users/:"), "/users/:");
    }

    #[test]
    fn colon_param_syntax_matches() {
        let routes = vec![make_route(
            "GET",
            "/users/:id",
            "todo:read:user",
            Some("id"),
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher.match_request("GET", "/users/alice").unwrap();
        assert_eq!(m.path_params().get("id").unwrap(), "alice");
    }

    #[test]
    fn colon_multi_param_syntax_matches() {
        let routes = vec![make_route(
            "GET",
            "/lists/:id/items/:item_id",
            "todo:read:item",
            Some("item_id"),
        )];
        let matcher = RouteMatcher::new(&routes).unwrap();
        let m = matcher
            .match_request("GET", "/lists/abc/items/xyz")
            .unwrap();
        assert_eq!(m.path_params().get("id").unwrap(), "abc");
        assert_eq!(m.path_params().get("item_id").unwrap(), "xyz");
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

    #[test]
    fn default_resource_used_when_no_path_param() {
        let route = RouteMapping::new(
            HttpMethod::Get,
            "/organizations".to_string(),
            QualifiedAction::parse("cp:organization:read").unwrap(),
            None,
            None,
        )
        .with_resource_entity_type("Organization")
        .with_default_resource_id("collection")
        .unwrap();

        let matcher = RouteMatcher::new(&[route]).unwrap();
        let m = matcher.match_request("GET", "/organizations").unwrap();

        let resource = m.resource().expect("should have a default resource");
        let project = forgeguard_core::ProjectId::new("test-app").unwrap();
        assert_eq!(resource.vp_entity_type(&project), "test_app::Organization");
        assert_eq!(resource.id().as_str(), "collection");
    }

    #[test]
    fn path_param_takes_precedence_over_default_resource() {
        let route = RouteMapping::new(
            HttpMethod::Get,
            "/organizations/{org_id}".to_string(),
            QualifiedAction::parse("cp:organization:read").unwrap(),
            Some("org_id".to_string()),
            None,
        )
        .with_resource_entity_type("Organization")
        .with_default_resource_id("collection")
        .unwrap();

        let matcher = RouteMatcher::new(&[route]).unwrap();
        let m = matcher
            .match_request("GET", "/organizations/org-acme")
            .unwrap();

        let resource = m.resource().expect("should have resource from path");
        assert_eq!(resource.id().as_str(), "org-acme");
    }

    #[test]
    fn with_default_resource_id_rejects_invalid_id() {
        let result = RouteMapping::new(
            HttpMethod::Get,
            "/organizations".to_string(),
            QualifiedAction::parse("cp:organization:read").unwrap(),
            None,
            None,
        )
        .with_default_resource_id("Invalid_ID");

        assert!(result.is_err(), "uppercase/underscore IDs must be rejected");
    }
}
