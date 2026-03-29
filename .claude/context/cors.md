# CORS Support

The proxy handles CORS entirely — the upstream service remains CORS-unaware.

## Config

```toml
[cors]
enabled = true
allowed_origins = ["https://app.forgeguard.dev", "*.forgeguard.dev"]
allowed_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
allowed_headers = ["Content-Type", "Authorization", "X-API-Key"]
expose_headers = ["X-Request-Id"]
allow_credentials = true
max_age_secs = 3600
```

Disabled by default. When `enabled = false` or the section is absent, no CORS
headers are emitted on any response.

## Origin Matching

Origins parse into `AllowedOrigin` (closed enum) at config load time:

| Pattern | Variant | Example |
|---------|---------|---------|
| `"*"` | `Any` | Matches all origins |
| `"*.example.com"` | `Suffix(".example.com")` | Must have ≥2 domain labels |
| `"https://app.example.com"` | `Exact(...)` | Must include scheme, no path |

Validation rejects: missing scheme, paths in origins, single-label suffixes,
wildcard + `allow_credentials = true`.

## Crate Placement (FCIS)

| Crate | What |
|-------|------|
| `forgeguard_http` (pure) | `AllowedOrigin`, `RawCorsConfig`, `CorsConfig`, `matches_origin()`, `preflight_headers()`, `response_headers()` |
| `forgeguard_proxy` (I/O) | Preflight interception, `send_json_response()`, `cors_headers()`, `response_filter()` |

## Request Flow

| Path | When | What happens |
|------|------|-------------|
| Preflight | OPTIONS + ACRM + origin matches | 204 with full CORS headers, bypasses auth |
| Preflight (no match) | OPTIONS + ACRM + origin not in list | Falls through to normal routing (avoids leaking CORS config) |
| Error response | 401/403/404 + origin matches | CORS headers injected via `send_json_response()` |
| Upstream response | Proxied + origin matches | CORS headers injected in `response_filter()`, overwriting upstream's |
| CORS disabled | Any | No CORS headers on any response |

## Design Decisions

- **Non-matching preflights fall through** rather than returning 403 — avoids
  revealing "CORS is enabled" to arbitrary origins.
- **`Vary: Origin`** is emitted for non-wildcard configs so caches don't serve
  wrong CORS headers. Appended (not inserted) to preserve upstream `Vary` values.
- **`send_json_response()`** replaces all `respond_error_with_body()` calls —
  supports custom headers (CORS) and correct `Content-Length`.

## Design Documents

- Shaping: `.claude/designs/cors-shaping.md`
- Design: `.local/plans/2026-03-27-cors-design.md`
- V1 plan: `.claude/plans/2026-03-28-cors-v1-pure-types-config.md`
