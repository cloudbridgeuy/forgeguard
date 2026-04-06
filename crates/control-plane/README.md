# forgeguard_control_plane

ForgeGuard control plane API server. This is an **I/O binary crate**.

Serves per-organization proxy configuration to BYOC connected proxies. File-backed config store for development; DynamoDB + S3 in production (future).

Authentication and authorization are handled by the `forgeguard-axum` middleware layer. In dev mode, the default configuration uses `DefaultPolicy::Passthrough` with `StaticPolicyEngine::Allow`, so all requests pass through without auth enforcement.

## Classification

**Binary / I/O** -- depends on `axum`, `tokio`, `tower-http`, `forgeguard-axum`, file I/O.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check -- returns `{"status": "ok"}` |
| `GET` | `/api/v1/organizations/{org_id}/proxy-config` | Per-org proxy config with ETag caching |

### Response Codes (proxy-config)

| Code | Meaning |
|------|---------|
| 200 | Config returned with `ETag` header |
| 304 | Config unchanged (`If-None-Match` matched) |
| 404 | Organization not found |

## Quick Start

A test config with two orgs (`org-acme`, `org-globex`) is included at
`examples/control-plane/orgs.test.json`. No real AWS resources needed.

### 1. Start the control plane

```sh
# Terminal 1 -- start the control plane
cargo run -p forgeguard_control_plane -- \
  --config examples/control-plane/orgs.test.json

# Terminal 2 -- test endpoints
# Health check -> 200
curl -s http://localhost:3001/health | jq .

# Fetch org config -> 200 + ETag
curl -si http://localhost:3001/api/v1/organizations/org-acme/proxy-config

# Unknown org -> 404
curl -si http://localhost:3001/api/v1/organizations/org-unknown/proxy-config

# ETag match -> 304 (paste the ETag from the 200 response above)
curl -si \
  -H 'If-None-Match: "<paste-etag>"' \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config
```

### 2. With your own orgs

For real AWS resources, copy the sample and fill in your values:

```sh
cp examples/control-plane/orgs.sample.json orgs.json
# Edit orgs.json -- add your Cognito pool ID, JWKS URL, VP policy store ID, etc.

cargo run -p forgeguard_control_plane -- --config orgs.json
```

The `orgs.json` file is gitignored (contains AWS resource IDs).

### CLI Options

| Flag | Env | Description |
|------|-----|-------------|
| `--config` | `FORGEGUARD_CP_CONFIG` | Path to org config JSON file (required) |
| `--listen` | `FORGEGUARD_CP_LISTEN` | Listen address (default: `127.0.0.1:3001`) |
| `--log-level` | `FORGEGUARD_CP_LOG_LEVEL` | Log level filter (default: `info`) |

## Config File Format

JSON file mapping `org_id` to its proxy config:

```json
{
  "organizations": {
    "org-acme": {
      "config": {
        "organization_id": "org-acme",
        "cognito_pool_id": "...",
        "cognito_jwks_url": "...",
        "policy_store_id": "...",
        "project_id": "...",
        "upstream_url": "...",
        "default_policy": "deny",
        "routes": [...],
        "public_routes": [...],
        "features": {}
      }
    }
  }
}
```

The `token` field previously used for bearer auth is no longer needed. Old config files that still contain it will parse without error (serde ignores unknown fields), but the field is unused.

## ETag Caching

Every org config response includes an `ETag` header (xxHash64 of the canonical JSON). Proxies send `If-None-Match` on subsequent polls and receive `304 Not Modified` when nothing has changed, saving bandwidth.

## Dependencies

| Crate | Role |
|-------|------|
| `forgeguard_core` (pure) | `OrganizationId` validation |
| `forgeguard-axum` | Auth middleware (identity + policy) |
| `axum` | HTTP framework |
| `tower-http` | Middleware (tracing, timeout) |
| `xxhash-rust` | ETag computation |
