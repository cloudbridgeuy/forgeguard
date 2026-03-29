# CORS V1: Pure Types + Config Parsing — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add CORS config types to `forgeguard_http` — parsing, validation, origin matching, and header builders — all pure, all unit-tested.

**Architecture:** `RawCorsConfig` (serde) → `CorsConfig` (validated) via `TryFrom`. `AllowedOrigin` ADT handles origin matching. Two pure header builders produce `Vec<(String, String)>` for preflight and normal responses. No I/O, no Pingora — this is the functional core.

**Tech Stack:** Rust, serde, thiserror, existing `forgeguard_http` patterns.

**Patterns:**
- MUST: Functional Core / Imperative Shell — everything in this slice is pure
- MUST: Parse Don't Validate — `RawCorsConfig` → `CorsConfig`
- MUST: Algebraic Data Types — `AllowedOrigin` enum
- MUST: Make Impossible States Impossible — wildcard + credentials conflict rejected at parse time

**Shaping doc:** `.claude/designs/cors-shaping.md`
**Design doc:** `.local/plans/2026-03-27-cors-design.md`

---

## Task 1: Add `ValidationErrorKind::InvalidCorsConfig` variant

**File:** `crates/http/src/error.rs`

### 1.1 Add the variant

Add `InvalidCorsConfig` to the `ValidationErrorKind` enum:

```rust
// In ValidationErrorKind enum, after CircularGroupNesting:
/// Invalid CORS configuration.
InvalidCorsConfig,
```

Add the `Display` arm:

```rust
// In Display for ValidationErrorKind, after CircularGroupNesting:
Self::InvalidCorsConfig => write!(f, "invalid-cors-config"),
```

### 1.2 Run lint

```bash
cargo xtask lint
```

Expected: passes (new variant is used in later tasks; clippy won't flag an unused enum variant behind `pub`).

---

## Task 2: Create `cors.rs` with `AllowedOrigin` and `RawCorsConfig`

**File:** `crates/http/src/cors.rs` (new file)

### 2.1 Create the file

```rust
//! CORS configuration types and pure logic.
//!
//! All types and functions are pure — no I/O, no Pingora.
//! The imperative shell in `forgeguard_proxy` consumes these.

use serde::Deserialize;

use crate::error::{ValidationError, ValidationErrorKind};

// ---------------------------------------------------------------------------
// AllowedOrigin
// ---------------------------------------------------------------------------

/// A parsed origin pattern from the `allowed_origins` config list.
///
/// Closed variant set — parsed once at config load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AllowedOrigin {
    /// Exact match: `"https://app.forgeguard.dev"`.
    Exact(String),
    /// Suffix match: `"*.forgeguard.dev"` → stores `".forgeguard.dev"`.
    Suffix(String),
    /// Wildcard: `"*"` — matches all origins.
    Any,
}

impl AllowedOrigin {
    /// Parse an origin string from config into the appropriate variant.
    ///
    /// Validates that exact origins contain a scheme (`://`) and suffix
    /// origins have at least one dot in the domain portion. This catches
    /// typos like `"app.forgeguard.dev"` (missing scheme) or `"*."` (empty
    /// suffix) at config load time rather than silently never matching.
    fn parse(s: &str) -> Result<Self, String> {
        if s == "*" {
            return Ok(Self::Any);
        }
        if let Some(suffix) = s.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err("suffix origin '*.' must have at least one character after '*.'".into());
            }
            if !suffix.contains('.') {
                return Err(format!(
                    "suffix origin '*.{suffix}' must be a domain with at least two labels (e.g., '*.example.com')"
                ));
            }
            return Ok(Self::Suffix(format!(".{suffix}")));
        }
        if s.is_empty() {
            return Err("origin must not be empty".into());
        }
        // Exact origins must be valid scheme://host[:port] — reject common mistakes
        if !s.contains("://") {
            return Err(format!(
                "origin '{s}' must include a scheme (e.g., 'https://{s}')"
            ));
        }
        let after_scheme = s.split("://").nth(1).unwrap_or("");
        if after_scheme.is_empty() {
            return Err(format!("origin '{s}' has no host after the scheme"));
        }
        // Reject origins with paths — CORS origins are scheme://host[:port] only
        let host_port = after_scheme.split('/').next().unwrap_or("");
        if after_scheme.len() != host_port.len() {
            return Err(format!(
                "origin '{s}' must not contain a path — use 'scheme://host[:port]' only"
            ));
        }
        Ok(Self::Exact(s.to_string()))
    }

    /// Check if a request origin matches this pattern.
    ///
    /// Returns the value to set in `Access-Control-Allow-Origin`:
    /// - `Exact` → the configured origin string
    /// - `Suffix` → the request origin (not the suffix)
    /// - `Any` → `"*"`
    fn matches<'a>(&'a self, origin: &'a str) -> Option<&'a str> {
        match self {
            Self::Exact(expected) => {
                if origin == expected {
                    Some(expected.as_str())
                } else {
                    None
                }
            }
            Self::Suffix(suffix) => {
                if origin.ends_with(suffix.as_str()) {
                    Some(origin)
                } else {
                    None
                }
            }
            Self::Any => Some("*"),
        }
    }
}

// ---------------------------------------------------------------------------
// RawCorsConfig
// ---------------------------------------------------------------------------

/// Raw CORS config as it appears in TOML. Deserialized, not yet validated.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawCorsConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) allowed_origins: Vec<String>,
    #[serde(default = "default_allowed_methods")]
    pub(crate) allowed_methods: Vec<String>,
    #[serde(default = "default_allowed_headers")]
    pub(crate) allowed_headers: Vec<String>,
    #[serde(default)]
    pub(crate) expose_headers: Vec<String>,
    #[serde(default)]
    pub(crate) allow_credentials: bool,
    #[serde(default = "default_max_age_secs")]
    pub(crate) max_age_secs: u64,
}

fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "POST".into(),
        "PUT".into(),
        "PATCH".into(),
        "DELETE".into(),
    ]
}

fn default_allowed_headers() -> Vec<String> {
    vec![
        "Content-Type".into(),
        "Authorization".into(),
        "X-API-Key".into(),
    ]
}

fn default_max_age_secs() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// CorsConfig
// ---------------------------------------------------------------------------

/// Validated CORS configuration. Private fields, constructed via `TryFrom<RawCorsConfig>`.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    origins: Vec<AllowedOrigin>,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    expose_headers: Vec<String>,
    allow_credentials: bool,
    max_age_secs: u64,
}

impl CorsConfig {
    /// Check if a request origin matches any configured origin.
    ///
    /// Returns the value for the `Access-Control-Allow-Origin` header,
    /// or `None` if no origin matched.
    pub fn matches_origin<'a>(&'a self, origin: &'a str) -> Option<&'a str> {
        self.origins.iter().find_map(|o| o.matches(origin))
    }

    /// Build the full set of CORS headers for a 204 preflight response.
    pub fn preflight_headers(&self, origin: &str) -> Vec<(String, String)> {
        let mut headers = Vec::with_capacity(6);
        headers.push(("Access-Control-Allow-Origin".into(), origin.into()));
        headers.push((
            "Access-Control-Allow-Methods".into(),
            self.allowed_methods.join(", "),
        ));
        headers.push((
            "Access-Control-Allow-Headers".into(),
            self.allowed_headers.join(", "),
        ));
        headers.push((
            "Access-Control-Max-Age".into(),
            self.max_age_secs.to_string(),
        ));
        if self.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }
        if !self.expose_headers.is_empty() {
            headers.push((
                "Access-Control-Expose-Headers".into(),
                self.expose_headers.join(", "),
            ));
        }
        headers
    }

    /// Build CORS headers for normal/error responses (subset of preflight).
    pub fn response_headers(&self, origin: &str) -> Vec<(String, String)> {
        let mut headers = Vec::with_capacity(3);
        headers.push(("Access-Control-Allow-Origin".into(), origin.into()));
        if self.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }
        if !self.expose_headers.is_empty() {
            headers.push((
                "Access-Control-Expose-Headers".into(),
                self.expose_headers.join(", "),
            ));
        }
        headers
    }
}

// ---------------------------------------------------------------------------
// TryFrom<RawCorsConfig>
// ---------------------------------------------------------------------------

impl TryFrom<RawCorsConfig> for CorsConfig {
    type Error = Vec<ValidationError>;

    fn try_from(raw: RawCorsConfig) -> Result<Self, Self::Error> {
        let mut errors = Vec::new();

        // Only validate when enabled
        if !raw.enabled {
            // Disabled — return a config with empty origins (matches nothing)
            return Ok(CorsConfig {
                origins: Vec::new(),
                allowed_methods: raw.allowed_methods,
                allowed_headers: raw.allowed_headers,
                expose_headers: raw.expose_headers,
                allow_credentials: raw.allow_credentials,
                max_age_secs: raw.max_age_secs,
            });
        }

        // allowed_origins must not be empty when enabled
        if raw.allowed_origins.is_empty() {
            errors.push(ValidationError::new(
                ValidationErrorKind::InvalidCorsConfig,
                "allowed_origins must not be empty when cors is enabled",
                "cors.allowed_origins",
            ));
        }

        // Parse each origin
        let mut origins = Vec::with_capacity(raw.allowed_origins.len());
        let mut has_any = false;
        for (i, origin_str) in raw.allowed_origins.iter().enumerate() {
            match AllowedOrigin::parse(origin_str) {
                Ok(origin) => {
                    if matches!(origin, AllowedOrigin::Any) {
                        has_any = true;
                    }
                    origins.push(origin);
                }
                Err(msg) => {
                    errors.push(ValidationError::new(
                        ValidationErrorKind::InvalidCorsConfig,
                        msg,
                        format!("cors.allowed_origins[{i}]"),
                    ));
                }
            }
        }

        // Wildcard + credentials conflict
        if has_any && raw.allow_credentials {
            errors.push(ValidationError::new(
                ValidationErrorKind::InvalidCorsConfig,
                "wildcard origin '*' cannot be used with allow_credentials = true",
                "cors",
            ));
        }

        // max_age_secs must be > 0
        if raw.max_age_secs == 0 {
            errors.push(ValidationError::new(
                ValidationErrorKind::InvalidCorsConfig,
                "max_age_secs must be greater than zero",
                "cors.max_age_secs",
            ));
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(CorsConfig {
            origins,
            allowed_methods: raw.allowed_methods,
            allowed_headers: raw.allowed_headers,
            expose_headers: raw.expose_headers,
            allow_credentials: raw.allow_credentials,
            max_age_secs: raw.max_age_secs,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- AllowedOrigin::parse -------------------------------------------------

    #[test]
    fn parse_exact_origin() {
        let o = AllowedOrigin::parse("https://app.forgeguard.dev").unwrap();
        assert_eq!(o, AllowedOrigin::Exact("https://app.forgeguard.dev".into()));
    }

    #[test]
    fn parse_suffix_origin() {
        let o = AllowedOrigin::parse("*.forgeguard.dev").unwrap();
        assert_eq!(o, AllowedOrigin::Suffix(".forgeguard.dev".into()));
    }

    #[test]
    fn parse_any_origin() {
        let o = AllowedOrigin::parse("*").unwrap();
        assert_eq!(o, AllowedOrigin::Any);
    }

    #[test]
    fn parse_empty_origin_fails() {
        assert!(AllowedOrigin::parse("").is_err());
    }

    #[test]
    fn parse_bare_wildcard_dot_fails() {
        assert!(AllowedOrigin::parse("*.").is_err());
    }

    #[test]
    fn parse_suffix_single_label_fails() {
        // *.com is too broad and likely a mistake — require at least two labels
        let err = AllowedOrigin::parse("*.com").unwrap_err();
        assert!(err.contains("two labels"));
    }

    #[test]
    fn parse_exact_missing_scheme_fails() {
        let err = AllowedOrigin::parse("app.forgeguard.dev").unwrap_err();
        assert!(err.contains("scheme"));
    }

    #[test]
    fn parse_exact_empty_host_fails() {
        assert!(AllowedOrigin::parse("https://").is_err());
    }

    #[test]
    fn parse_exact_with_path_fails() {
        let err = AllowedOrigin::parse("https://app.forgeguard.dev/api").unwrap_err();
        assert!(err.contains("path"));
    }

    #[test]
    fn parse_exact_with_port_succeeds() {
        let o = AllowedOrigin::parse("http://localhost:3000").unwrap();
        assert_eq!(o, AllowedOrigin::Exact("http://localhost:3000".into()));
    }

    // -- AllowedOrigin::matches -----------------------------------------------

    #[test]
    fn exact_matches_same_origin() {
        let o = AllowedOrigin::Exact("https://app.forgeguard.dev".into());
        assert_eq!(o.matches("https://app.forgeguard.dev"), Some("https://app.forgeguard.dev"));
    }

    #[test]
    fn exact_rejects_different_origin() {
        let o = AllowedOrigin::Exact("https://app.forgeguard.dev".into());
        assert_eq!(o.matches("https://evil.com"), None);
    }

    #[test]
    fn suffix_matches_subdomain() {
        let o = AllowedOrigin::Suffix(".forgeguard.dev".into());
        assert_eq!(o.matches("https://app.forgeguard.dev"), Some("https://app.forgeguard.dev"));
    }

    #[test]
    fn suffix_rejects_non_matching() {
        let o = AllowedOrigin::Suffix(".forgeguard.dev".into());
        assert_eq!(o.matches("https://evil.com"), None);
    }

    #[test]
    fn any_matches_everything() {
        let o = AllowedOrigin::Any;
        assert_eq!(o.matches("https://anything.com"), Some("*"));
    }

    // -- CorsConfig::try_from -------------------------------------------------

    fn raw_enabled() -> RawCorsConfig {
        RawCorsConfig {
            enabled: true,
            allowed_origins: vec!["https://app.forgeguard.dev".into()],
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
            expose_headers: vec![],
            allow_credentials: false,
            max_age_secs: 3600,
        }
    }

    #[test]
    fn valid_config_parses() {
        let config = CorsConfig::try_from(raw_enabled()).unwrap();
        assert_eq!(config.origins.len(), 1);
    }

    #[test]
    fn disabled_config_always_succeeds() {
        let raw = RawCorsConfig {
            enabled: false,
            ..Default::default()
        };
        let config = CorsConfig::try_from(raw).unwrap();
        assert!(config.origins.is_empty());
    }

    #[test]
    fn empty_origins_when_enabled_fails() {
        let raw = RawCorsConfig {
            enabled: true,
            allowed_origins: vec![],
            ..raw_enabled()
        };
        let errs = CorsConfig::try_from(raw).unwrap_err();
        assert!(errs.iter().any(|e| e.message().contains("allowed_origins")));
    }

    #[test]
    fn wildcard_with_credentials_fails() {
        let raw = RawCorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: true,
            ..raw_enabled()
        };
        let errs = CorsConfig::try_from(raw).unwrap_err();
        assert!(errs.iter().any(|e| e.message().contains("wildcard")));
    }

    #[test]
    fn zero_max_age_fails() {
        let raw = RawCorsConfig {
            max_age_secs: 0,
            ..raw_enabled()
        };
        let errs = CorsConfig::try_from(raw).unwrap_err();
        assert!(errs.iter().any(|e| e.message().contains("max_age_secs")));
    }

    #[test]
    fn multiple_errors_collected() {
        let raw = RawCorsConfig {
            enabled: true,
            allowed_origins: vec!["*".into()],
            allow_credentials: true,
            max_age_secs: 0,
            ..raw_enabled()
        };
        let errs = CorsConfig::try_from(raw).unwrap_err();
        assert!(errs.len() >= 2);
    }

    // -- CorsConfig::matches_origin -------------------------------------------

    #[test]
    fn matches_origin_finds_exact() {
        let config = CorsConfig::try_from(raw_enabled()).unwrap();
        assert_eq!(
            config.matches_origin("https://app.forgeguard.dev"),
            Some("https://app.forgeguard.dev"),
        );
    }

    #[test]
    fn matches_origin_returns_none_for_unknown() {
        let config = CorsConfig::try_from(raw_enabled()).unwrap();
        assert_eq!(config.matches_origin("https://evil.com"), None);
    }

    #[test]
    fn matches_origin_suffix() {
        let raw = RawCorsConfig {
            allowed_origins: vec!["*.forgeguard.dev".into()],
            ..raw_enabled()
        };
        let config = CorsConfig::try_from(raw).unwrap();
        assert_eq!(
            config.matches_origin("https://app.forgeguard.dev"),
            Some("https://app.forgeguard.dev"),
        );
    }

    #[test]
    fn matches_origin_wildcard() {
        let raw = RawCorsConfig {
            allowed_origins: vec!["*".into()],
            ..raw_enabled()
        };
        let config = CorsConfig::try_from(raw).unwrap();
        assert_eq!(config.matches_origin("https://anything.com"), Some("*"));
    }

    // -- CorsConfig::preflight_headers ----------------------------------------

    #[test]
    fn preflight_headers_include_all_fields() {
        let raw = RawCorsConfig {
            allow_credentials: false,
            expose_headers: vec!["X-Request-Id".into()],
            ..raw_enabled()
        };
        let config = CorsConfig::try_from(raw).unwrap();
        let headers = config.preflight_headers("https://app.forgeguard.dev");

        let header_map: std::collections::HashMap<&str, &str> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(header_map["Access-Control-Allow-Origin"], "https://app.forgeguard.dev");
        assert!(header_map["Access-Control-Allow-Methods"].contains("GET"));
        assert!(header_map["Access-Control-Allow-Headers"].contains("Content-Type"));
        assert_eq!(header_map["Access-Control-Max-Age"], "3600");
        assert_eq!(header_map["Access-Control-Expose-Headers"], "X-Request-Id");
        assert!(!header_map.contains_key("Access-Control-Allow-Credentials"));
    }

    #[test]
    fn preflight_headers_include_credentials_when_set() {
        let raw = RawCorsConfig {
            allowed_origins: vec!["https://app.forgeguard.dev".into()],
            allow_credentials: true,
            ..raw_enabled()
        };
        let config = CorsConfig::try_from(raw).unwrap();
        let headers = config.preflight_headers("https://app.forgeguard.dev");

        let has_creds = headers.iter().any(|(k, v)| {
            k == "Access-Control-Allow-Credentials" && v == "true"
        });
        assert!(has_creds);
    }

    // -- CorsConfig::response_headers -----------------------------------------

    #[test]
    fn response_headers_subset_of_preflight() {
        let config = CorsConfig::try_from(raw_enabled()).unwrap();
        let headers = config.response_headers("https://app.forgeguard.dev");

        let header_map: std::collections::HashMap<&str, &str> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(header_map["Access-Control-Allow-Origin"], "https://app.forgeguard.dev");
        // Should NOT contain preflight-only headers
        assert!(!header_map.contains_key("Access-Control-Allow-Methods"));
        assert!(!header_map.contains_key("Access-Control-Allow-Headers"));
        assert!(!header_map.contains_key("Access-Control-Max-Age"));
    }

    #[test]
    fn response_headers_include_expose_headers() {
        let raw = RawCorsConfig {
            expose_headers: vec!["X-Request-Id".into(), "X-Trace-Id".into()],
            ..raw_enabled()
        };
        let config = CorsConfig::try_from(raw).unwrap();
        let headers = config.response_headers("https://app.forgeguard.dev");

        let expose = headers.iter().find(|(k, _)| k == "Access-Control-Expose-Headers");
        assert!(expose.is_some());
        assert!(expose.unwrap().1.contains("X-Request-Id"));
    }
}
```

### 2.2 Run lint

```bash
cargo xtask lint
```

Expected: passes (module not yet registered in `lib.rs`, so it won't compile as part of the crate — register it in the next task).

---

## Task 3: Register `cors` module in `lib.rs` and export `CorsConfig`

**File:** `crates/http/src/lib.rs`

### 3.1 Add module declaration

After `pub(crate) mod config_raw;`, add:

```rust
pub mod cors;
```

### 3.2 Add public re-export

After the existing re-exports, add:

```rust
pub use cors::CorsConfig;
```

### 3.3 Run lint

```bash
cargo xtask lint
```

Expected: passes. All tests in `cors.rs` should run and pass.

---

## Task 4: Wire `RawCorsConfig` into `RawProxyConfig`

**File:** `crates/http/src/config_raw.rs`

### 4.1 Add field

Add to `RawProxyConfig`, after the `schema` field:

```rust
    #[serde(default)]
    pub(crate) cors: Option<crate::cors::RawCorsConfig>,
```

### 4.2 Run lint

```bash
cargo xtask lint
```

Expected: passes. `RawCorsConfig` is `Default` so `Option<RawCorsConfig>` with `#[serde(default)]` handles missing section.

---

## Task 5: Wire `CorsConfig` into `ProxyConfig` + `TryFrom`

**File:** `crates/http/src/config.rs`

### 5.1 Add field to `ProxyConfig`

After `policy_tests: Vec<PolicyTest>`, add:

```rust
    cors: Option<crate::cors::CorsConfig>,
```

### 5.2 Add getter

Inside `impl ProxyConfig`, after `policy_tests()`:

```rust
    pub fn cors(&self) -> Option<&crate::cors::CorsConfig> {
        self.cors.as_ref()
    }
```

### 5.3 Add parsing in `TryFrom<RawProxyConfig>`

After the `policy_tests` parsing block (before `Ok(ProxyConfig { ... })`), add:

```rust
        let cors = raw
            .cors
            .map(crate::cors::CorsConfig::try_from)
            .transpose()
            .map_err(|cors_errors| {
                Error::Validation(cors_errors)
            })?;
```

### 5.4 Add `cors` to the `ProxyConfig` construction

In the `Ok(ProxyConfig { ... })` block, add `cors,` after `policy_tests,`.

### 5.5 Run lint

```bash
cargo xtask lint
```

Expected: passes. Existing tests still pass (no `[cors]` section = `None`).

---

## Task 6: Add CORS config parsing tests

**File:** `crates/http/src/config.rs` — in the `#[cfg(test)]` module

### 6.1 Add test: CORS section absent

```rust
    #[test]
    fn parse_cors_absent() {
        let config = parse_config(MINIMAL_TOML).unwrap();
        assert!(config.cors().is_none());
    }
```

### 6.2 Add test: CORS enabled with valid config

```rust
    #[test]
    fn parse_cors_enabled() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[cors]
enabled = true
allowed_origins = ["https://app.forgeguard.dev", "*.forgeguard.dev"]
allow_credentials = true
"#;
        let config = parse_config(toml).unwrap();
        let cors = config.cors().unwrap();
        assert_eq!(
            cors.matches_origin("https://app.forgeguard.dev"),
            Some("https://app.forgeguard.dev"),
        );
        assert_eq!(
            cors.matches_origin("https://staging.forgeguard.dev"),
            Some("https://staging.forgeguard.dev"),
        );
        assert_eq!(cors.matches_origin("https://evil.com"), None);
    }
```

### 6.3 Add test: CORS disabled

```rust
    #[test]
    fn parse_cors_disabled() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[cors]
enabled = false
"#;
        let config = parse_config(toml).unwrap();
        // Disabled CORS parses but matches nothing
        let cors = config.cors().unwrap();
        assert_eq!(cors.matches_origin("https://anything.com"), None);
    }
```

### 6.4 Add test: wildcard + credentials rejected

```rust
    #[test]
    fn parse_cors_wildcard_credentials_rejected() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[cors]
enabled = true
allowed_origins = ["*"]
allow_credentials = true
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("validation failed"));
    }
```

### 6.5 Run lint

```bash
cargo xtask lint
```

Expected: all tests pass.

---

## Task 7: Add CORS validation to `validate.rs`

**File:** `crates/http/src/validate.rs`

### 7.1 Add CORS validation check

Add a call in `validate()` after the last check:

```rust
    check_cors_config(config, &mut errors);
```

Add the function:

```rust
/// Validate CORS config constraints that depend on the full proxy config.
///
/// Note: most CORS validation happens in `CorsConfig::try_from()`.
/// This catches cross-cutting concerns if any arise.
fn check_cors_config(_config: &ProxyConfig, _errors: &mut Vec<ValidationError>) {
    // Currently all CORS validation is self-contained in CorsConfig::try_from.
    // This hook exists for future cross-cutting checks (e.g., CORS vs public routes).
}
```

### 7.2 Run lint

```bash
cargo xtask lint
```

Expected: passes. The function is intentionally a no-op placeholder — all real validation happens in `TryFrom`.

---

## Task 8: Final verification

### 8.1 Run full lint

```bash
cargo xtask lint
```

Expected: exit code 0, zero output.

### 8.2 Verify test count

```bash
cargo test -p forgeguard_http -- --list 2>&1 | grep "cors" | head -20
```

Expected: ~20 tests from `cors::tests::*` plus ~4 tests from `config::tests::parse_cors_*`.

---

## Summary of changes

| File | Change |
|------|--------|
| `crates/http/src/error.rs` | Add `InvalidCorsConfig` variant to `ValidationErrorKind` |
| `crates/http/src/cors.rs` | New file: `AllowedOrigin`, `RawCorsConfig`, `CorsConfig`, `TryFrom`, tests |
| `crates/http/src/lib.rs` | Register `cors` module, export `CorsConfig` |
| `crates/http/src/config_raw.rs` | Add `cors: Option<RawCorsConfig>` field |
| `crates/http/src/config.rs` | Add `cors: Option<CorsConfig>` field, getter, parsing, tests |
| `crates/http/src/validate.rs` | Add `check_cors_config` hook |

**No other crates touched.** This is entirely within `forgeguard_http`.
