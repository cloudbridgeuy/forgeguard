# CORS V2+V3: Proxy Wiring — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Wire CORS into the Pingora proxy — preflight interception, CORS headers on all responses (errors + proxied upstream), and migrate all `respond_error_with_body` sites to a helper that supports custom headers.

**Architecture:** Three layers: (1) `send_json_response` helper replaces all 10 `respond_error_with_body` calls with a function that supports custom headers; (2) preflight interception in `request_filter` returns 204 with CORS headers before auth; (3) `response_filter` hook injects CORS headers on proxied upstream responses. `ctx.cors_origin` carries the matched origin across lifecycle phases.

**Tech Stack:** Rust, Pingora 0.8 (`pingora_proxy::Session`, `pingora_http::ResponseHeader`), existing `forgeguard_http::CorsConfig`.

**Patterns:**
- MUST: Functional Core / Imperative Shell — CORS logic stays in `forgeguard_http` (pure); proxy just calls it
- MUST: Make Impossible States Impossible — wildcard+credentials already rejected at parse time (V1)

**Shaping doc:** `.claude/designs/cors-shaping.md` (parts A5–A9, affordances N10–N17)

---

## Task 1: Add `cors` field to `ProxyParams` and `ForgeGuardProxy`

**File:** `crates/proxy/src/proxy.rs`

### 1.1 Add import

At the top, in the `forgeguard_http` import block, add `CorsConfig`:

```rust
use forgeguard_http::{
    build_query, evaluate_debug, extract_credential, inject_headers, ClientIpSource, CorsConfig,
    DefaultPolicy, FlagDebugQuery, IdentityProjection, MatchedRoute, PublicMatch,
    PublicRouteMatcher, RouteMatcher,
};
```

### 1.2 Add field to `ProxyParams`

After `pub debug_mode: bool,`:

```rust
    pub cors: Option<CorsConfig>,
```

### 1.3 Add field to `ForgeGuardProxy`

After `debug_mode: bool,`:

```rust
    cors: Option<CorsConfig>,
```

### 1.4 Wire in `ForgeGuardProxy::new`

In the `Self { ... }` block inside `new()`, after `debug_mode: params.debug_mode,`:

```rust
            cors: params.cors,
```

### 1.5 Run lint

```bash
cargo xtask lint
```

Expected: may warn about unused field — that's fine, it gets used in later tasks.

---

## Task 2: Wire CORS config from `main.rs`

**File:** `crates/proxy/src/main.rs`

### 2.1 Add cors to ProxyParams construction

In the `ForgeGuardProxy::new(ProxyParams { ... })` block (around line 82–96), after `debug_mode: opts.debug,`:

```rust
        cors: config.cors().cloned(),
```

### 2.2 Run lint

```bash
cargo xtask lint
```

Expected: passes.

---

## Task 3: Add `cors_origin` field to `RequestCtx`

**File:** `crates/proxy/src/proxy.rs`

### 3.1 Add field

In the `RequestCtx` struct, after `client_ip: Option<IpAddr>,`:

```rust
    cors_origin: Option<String>,
```

### 3.2 Initialize in `new_ctx`

In `new_ctx()`, after `client_ip: None,`:

```rust
            cors_origin: None,
```

### 3.3 Run lint

```bash
cargo xtask lint
```

Expected: may warn about unused field — that's fine, used in later tasks.

---

## Task 4: Create `send_json_response` helper

**File:** `crates/proxy/src/proxy.rs`

### 4.1 Add import

Add `pingora_http::ResponseHeader` to the imports:

```rust
use pingora_http::{RequestHeader, ResponseHeader};
```

### 4.2 Add helper function

After the `extract_client_ip` function at the bottom of the file, add:

```rust
/// Send a JSON response with optional extra headers.
///
/// Replaces `respond_error_with_body` — supports CORS and other custom headers.
async fn send_json_response(
    session: &mut Session,
    status: u16,
    body: &[u8],
    extra_headers: &[(String, String)],
) -> pingora_core::Result<()> {
    let mut resp = ResponseHeader::build(status, Some(4 + extra_headers.len()))?;
    resp.insert_header("Content-Type", "application/json")?;
    for (name, value) in extra_headers {
        resp.insert_header(name.as_str(), value.as_str())?;
    }
    resp.set_content_length(body.len())?;
    session
        .downstream_session
        .write_response_header(Box::new(resp))
        .await?;
    session
        .downstream_session
        .write_response_body(Bytes::from(body.to_vec()), true)
        .await?;
    Ok(())
}
```

### 4.3 Add helper for building CORS headers from context

After `send_json_response`, add:

```rust
/// Build CORS response headers from ctx, or return an empty slice.
fn cors_headers(
    cors: &Option<CorsConfig>,
    cors_origin: &Option<String>,
) -> Vec<(String, String)> {
    match (cors, cors_origin) {
        (Some(config), Some(origin)) => config.response_headers(origin),
        _ => Vec::new(),
    }
}
```

### 4.4 Run lint

```bash
cargo xtask lint
```

Expected: may warn about unused functions — that's fine, used in next tasks.

---

## Task 5: Add preflight interception in `request_filter`

**File:** `crates/proxy/src/proxy.rs`

### 5.1 Add preflight logic

In `request_filter`, after the health check block (after `return Ok(true);` for `HEALTH_PATH`, around line 128) and **before** the debug endpoint block, add:

```rust
        // 1a. CORS preflight — respond before auth
        if ctx.method == "OPTIONS" {
            if let Some(cors) = &self.cors {
                let origin = session
                    .downstream_session
                    .req_header()
                    .headers
                    .get("origin")
                    .and_then(|v| v.to_str().ok());
                let acrm = session
                    .downstream_session
                    .req_header()
                    .headers
                    .get("access-control-request-method");

                if let (Some(origin), Some(_)) = (origin, acrm) {
                    if let Some(matched) = cors.matches_origin(origin) {
                        let headers = cors.preflight_headers(matched);
                        let _ =
                            send_json_response(session, 204, b"", &headers).await;
                        return Ok(true);
                    }
                }
            }
            // Not a valid preflight or CORS disabled — fall through to normal routing
        }

        // 1b. Set CORS origin for non-preflight requests
        if let Some(cors) = &self.cors {
            let origin = session
                .downstream_session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok());
            if let Some(origin) = origin {
                if cors.matches_origin(origin).is_some() {
                    ctx.cors_origin = Some(origin.to_string());
                }
            }
        }
```

### 5.2 Run lint

```bash
cargo xtask lint
```

Expected: passes (or warns about unused `cors_origin` in ctx — fixed in next tasks).

---

## Task 6: Migrate all 10 `respond_error_with_body` sites

**File:** `crates/proxy/src/proxy.rs`

Replace every `respond_error_with_body` call with `send_json_response`, passing CORS headers from context. The pattern for each site is:

**Before:**
```rust
let _ = session
    .respond_error_with_body(STATUS, Bytes::from(body.to_string()))
    .await;
```

**After:**
```rust
let headers = cors_headers(&self.cors, &ctx.cors_origin);
let _ = send_json_response(session, STATUS, body.to_string().as_bytes(), &headers).await;
```

### 6.1 Health check (line ~124–126)

The health check runs before CORS origin is set, so it should use empty headers:

```rust
            let _ = send_json_response(session, 200, body.to_string().as_bytes(), &[]).await;
```

### 6.2 Flags debug — success (line ~138–140)

This also runs before CORS origin is set:

```rust
                        let _ =
                            send_json_response(session, 200, json.as_bytes(), &[]).await;
```

### 6.3 Flags debug — serialization error (line ~144–146)

```rust
                            let _ = send_json_response(
                                session,
                                500,
                                body.to_string().as_bytes(),
                                &[],
                            )
                            .await;
```

### 6.4 Flags debug — query parse error (line ~152–154)

```rust
                    let _ = send_json_response(
                        session,
                        400,
                        body.to_string().as_bytes(),
                        &[],
                    )
                    .await;
```

### 6.5 Credential resolution failed (line ~182–184)

```rust
                            let headers = cors_headers(&self.cors, &ctx.cors_origin);
                            let _ = send_json_response(
                                session,
                                401,
                                body.to_string().as_bytes(),
                                &headers,
                            )
                            .await;
```

### 6.6 No credential provided (line ~194–196)

```rust
                    let headers = cors_headers(&self.cors, &ctx.cors_origin);
                    let _ = send_json_response(
                        session,
                        401,
                        body.to_string().as_bytes(),
                        &headers,
                    )
                    .await;
```

### 6.7 Feature gate disabled (line ~228–230)

```rust
                    let headers = cors_headers(&self.cors, &ctx.cors_origin);
                    let _ = send_json_response(
                        session,
                        404,
                        body.to_string().as_bytes(),
                        &headers,
                    )
                    .await;
```

### 6.8 Policy denied — decision (line ~246–248)

```rust
                            let headers = cors_headers(&self.cors, &ctx.cors_origin);
                            let _ = send_json_response(
                                session,
                                403,
                                body.to_string().as_bytes(),
                                &headers,
                            )
                            .await;
```

### 6.9 Policy denied — engine error (line ~257–259)

```rust
                        let headers = cors_headers(&self.cors, &ctx.cors_origin);
                        let _ = send_json_response(
                            session,
                            403,
                            body.to_string().as_bytes(),
                            &headers,
                        )
                        .await;
```

### 6.10 No route matched — default deny (line ~272–274)

```rust
                    let headers = cors_headers(&self.cors, &ctx.cors_origin);
                    let _ = send_json_response(
                        session,
                        403,
                        body.to_string().as_bytes(),
                        &headers,
                    )
                    .await;
```

### 6.11 Run lint

```bash
cargo xtask lint
```

Expected: passes. No more `respond_error_with_body` calls.

---

## Task 7: Add `response_filter` hook for upstream CORS injection

**File:** `crates/proxy/src/proxy.rs`

### 7.1 Add the hook

Inside `impl ProxyHttp for ForgeGuardProxy`, after the `upstream_request_filter` method, add:

```rust
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(origin) = &ctx.cors_origin {
            if let Some(cors) = &self.cors {
                let headers = cors.response_headers(origin);
                for (name, value) in &headers {
                    let _ = upstream_response.insert_header(name.as_str(), value.as_str());
                }
            }
        }
        Ok(())
    }
```

This overwrites any upstream CORS headers (R3 from shaping doc) and injects CORS headers on all proxied responses when the origin matched.

### 7.2 Run lint

```bash
cargo xtask lint
```

Expected: passes.

---

## Task 8: Final verification

### 8.1 Run full lint

```bash
cargo xtask lint
```

Expected: exit code 0, zero output.

### 8.2 Verify no `respond_error_with_body` remains

```bash
grep -r "respond_error_with_body" crates/proxy/ || echo "All migrated"
```

Expected: "All migrated"

### 8.3 Manual test (if upstream available)

Start the proxy with CORS enabled in `forgeguard.toml`:

```toml
[cors]
enabled = true
allowed_origins = ["http://localhost:3001"]
allow_credentials = true
```

Test preflight:
```bash
curl -v -X OPTIONS http://127.0.0.1:8080/api/todos \
  -H "Origin: http://localhost:3001" \
  -H "Access-Control-Request-Method: GET"
```

Expected: 204 response with:
- `Access-Control-Allow-Origin: http://localhost:3001`
- `Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE`
- `Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key`
- `Access-Control-Max-Age: 3600`
- `Access-Control-Allow-Credentials: true`

Test non-matching origin:
```bash
curl -v -X OPTIONS http://127.0.0.1:8080/api/todos \
  -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: GET"
```

Expected: falls through to normal routing (no 204, no CORS headers).

Test error response with CORS:
```bash
curl -v http://127.0.0.1:8080/api/todos \
  -H "Origin: http://localhost:3001"
```

Expected: 401/403 response includes `Access-Control-Allow-Origin: http://localhost:3001`.

---

## Summary of changes

| File | Change |
|------|--------|
| `crates/proxy/src/proxy.rs` | Add `cors` field, `cors_origin` ctx field, `send_json_response` helper, `cors_headers` helper, preflight interception, migrate 10 response sites, add `response_filter` hook |
| `crates/proxy/src/main.rs` | Pass `config.cors().cloned()` to `ProxyParams` |

**No changes to pure crates.** This is entirely within the imperative shell (`forgeguard_proxy`).
