# forgeguard_control_plane

ForgeGuard control plane API server. This is an **I/O binary crate**.

Serves per-organization proxy configuration to BYOC connected proxies. File-backed config store for development; DynamoDB + S3 in production (future).

## Classification

**Binary / I/O** -- depends on `axum`, `tokio`, `tower-http`, file I/O.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | None | Health check -- returns `{"status": "ok"}` |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | Bearer `fgt_...` | Per-org proxy config with ETag caching |

### Response Codes (proxy-config)

| Code | Meaning |
|------|---------|
| 200 | Config returned with `ETag` header |
| 304 | Config unchanged (`If-None-Match` matched) |
| 401 | Missing or invalid bearer token |
| 403 | Token not authorized for this organization |
| 404 | Organization not found |

## Quick Start

A test config with two orgs (`org-acme`, `org-globex`) is included at
`examples/control-plane/orgs.test.json`. No real AWS resources needed.

### 1. Control plane only

```sh
# Terminal 1 — start the control plane
cargo run -p forgeguard_control_plane -- \
  --config examples/control-plane/orgs.test.json

# Terminal 2 — test all response codes
# Health check -> 200
curl -s http://localhost:3001/health | jq .

# Valid token -> 200 + ETag
curl -si \
  -H "Authorization: Bearer fgt_acme-test-token-do-not-use-in-production" \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config

# No token -> 401
curl -si http://localhost:3001/api/v1/organizations/org-acme/proxy-config

# Wrong org's token -> 403
curl -si \
  -H "Authorization: Bearer fgt_globex-test-token-do-not-use-in-production" \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config

# Unknown org -> 404
curl -si \
  -H "Authorization: Bearer fgt_acme-test-token-do-not-use-in-production" \
  http://localhost:3001/api/v1/organizations/org-unknown/proxy-config

# ETag match -> 304 (paste the ETag from the 200 response above)
curl -si \
  -H "Authorization: Bearer fgt_acme-test-token-do-not-use-in-production" \
  -H 'If-None-Match: "<paste-etag>"' \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config
```

### 2. Dogfooding — proxy in front of the control plane

The BYOC proxy can sit in front of the control plane in static mode,
demonstrating ForgeGuard protecting its own API.

```sh
# Terminal 1 — start the control plane (port 3001)
cargo run -p forgeguard_control_plane -- \
  --config examples/control-plane/orgs.test.json

# Terminal 2 — start the proxy in front (port 8080 -> 3001)
cargo run -p forgeguard_proxy -- run \
  --config examples/control-plane/proxy.toml

# Terminal 3 — hit the proxy instead of the control plane
curl -si \
  -H "Authorization: Bearer fgt_acme-test-token-do-not-use-in-production" \
  http://localhost:8080/api/v1/organizations/org-acme/proxy-config
```

### 3. With your own orgs

For real AWS resources, copy the sample and fill in your values:

```sh
cp examples/control-plane/orgs.sample.json orgs.json
# Edit orgs.json — add your Cognito pool ID, JWKS URL, VP policy store ID, etc.

cargo run -p forgeguard_control_plane -- --config orgs.json
```

The `orgs.json` file is gitignored (contains tokens and AWS resource IDs).

### CLI Options

| Flag | Env | Description |
|------|-----|-------------|
| `--config` | `FORGEGUARD_CP_CONFIG` | Path to org config JSON file (required) |
| `--listen` | `FORGEGUARD_CP_LISTEN` | Listen address (default: `127.0.0.1:3001`) |
| `--log-level` | `FORGEGUARD_CP_LOG_LEVEL` | Log level filter (default: `info`) |

## Dependencies

| Crate | Role |
|-------|------|
| `forgeguard_core` (pure) | `OrganizationId` validation |
| `axum` | HTTP framework |
| `tower-http` | Middleware (tracing, timeout) |
| `xxhash-rust` | ETag computation |
