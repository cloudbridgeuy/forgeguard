# ForgeGuard Demo — TODO App

A multi-tenant TODO API (Python/FastAPI) running behind the ForgeGuard proxy.
The app has **zero ForgeGuard imports** — it reads `X-ForgeGuard-*` headers
injected by the proxy to scope all data by tenant.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Rust toolchain (for building the proxy)
- AWS credentials configured (`~/.aws/credentials` with `admin` profile)
- ForgeGuard Cognito deployment (`cargo xtask dev setup --cognito`)

## Quick Start

```bash
# Terminal 1: Start the Python app
cd examples/todo-app
uv run uvicorn app:app --port 3000

# Terminal 2: Start the proxy
cargo run --bin forgeguard-proxy -- run --config examples/todo-app/forgeguard.toml --debug
```

The proxy listens on `localhost:8080`, the app on `localhost:3000`.

## Docker Compose (alternative)

If you have Docker installed, you can run the entire demo with a single command:

```bash
cd examples/todo-app
docker compose up --build
```

This builds both the Python app and the ForgeGuard proxy, wiring them together
automatically. The proxy overrides `upstream_url` via the `FORGEGUARD_UPSTREAM`
environment variable so it can reach the app container by service name.

Ports are the same as the manual setup: proxy on `localhost:8080`, app on
`localhost:3000`. All `curl` commands in the demo scenarios below work unchanged.

To tear everything down:

```bash
docker compose down
```

## Demo Scenarios

### 1. Public routes (no credentials)

```bash
# Health check — anonymous
curl http://localhost:8080/health

# Webhook — anonymous
curl -X POST http://localhost:8080/webhooks/github

# Docs — opportunistic (works with or without auth)
curl http://localhost:8080/docs/getting-started
```

### 2. Tenant isolation — acme-corp vs globex-corp

```bash
# Alice (acme-corp admin) — sees acme-corp lists only
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists

# Dave (globex-corp admin) — sees globex-corp lists only
curl -H "X-API-Key: sk-test-dave-admin" http://localhost:8080/api/lists
```

The proxy asserts each user's tenant. The app scopes data by
`X-ForgeGuard-Tenant-Id`. Alice never sees globex-corp data.

### 3. RBAC within a tenant

```bash
# Bob (acme-corp member) — can create a list
curl -X POST -H "X-API-Key: sk-test-bob-member" http://localhost:8080/api/lists

# Charlie (acme-corp viewer) — try to create (expect 403)
curl -X POST -H "X-API-Key: sk-test-charlie-viewer" http://localhost:8080/api/lists

# Eve (globex-corp viewer) — can read but not create
curl -H "X-API-Key: sk-test-eve-viewer" http://localhost:8080/api/lists
curl -X POST -H "X-API-Key: sk-test-eve-viewer" http://localhost:8080/api/lists
```

### 4. Feature flags (tenant-scoped)

```bash
# AI suggestions — enabled for acme-corp via tenant override
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists/default/suggestions

# AI suggestions — disabled for globex-corp (no override)
curl -H "X-API-Key: sk-test-dave-admin" http://localhost:8080/api/lists/default/suggestions
```

### 5. Resource-level access

```bash
# Alice can read top-secret (admin + top-secret-readers)
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists/top-secret

# Charlie cannot read top-secret (viewer only — denied by policy)
curl -H "X-API-Key: sk-test-charlie-viewer" http://localhost:8080/api/lists/top-secret
```

### 6. Debug context

```bash
# See all injected headers
curl -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/debug/context
```

### 7. CLI commands

```bash
# Validate config
cargo run --bin forgeguard -- check --config examples/todo-app/forgeguard.toml

# Show route table
cargo run --bin forgeguard -- routes --config examples/todo-app/forgeguard.toml
```

## API Keys

| Key | User | Tenant | Groups |
|-----|------|--------|--------|
| `sk-test-alice-admin` | alice | acme-corp | admin, top-secret-readers |
| `sk-test-bob-member` | bob | acme-corp | member |
| `sk-test-charlie-viewer` | charlie | acme-corp | viewer |
| `sk-test-dave-admin` | dave | globex-corp | admin |
| `sk-test-eve-viewer` | eve | globex-corp | viewer |

## Prometheus Metrics + Stress Test

The proxy exposes Pingora metrics at `localhost:9090` when `[metrics] enabled = true`
in the config (already enabled in `forgeguard.dev.toml`).

### Start Prometheus via Docker

Create a Prometheus config that scrapes the proxy:

```bash
cat > /tmp/prometheus.yml <<'EOF'
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: forgeguard-proxy
    static_configs:
      - targets: ["host.docker.internal:9090"]
EOF
```

Run Prometheus:

```bash
docker run -d \
  --name forgeguard-prometheus \
  -p 9091:9090 \
  -v /tmp/prometheus.yml:/etc/prometheus/prometheus.yml:ro \
  prom/prometheus:latest
```

Open `http://localhost:9091` to access the Prometheus UI.

### Stress test with `hey`

Install [hey](https://github.com/rakyll/hey) if you don't have it:

```bash
brew install hey
```

Run a stress test against an authenticated endpoint:

```bash
# 1000 requests, 10 concurrent — tests VP cache effectiveness
hey -n 1000 -c 10 -H "X-API-Key: sk-test-alice-admin" http://localhost:8080/api/lists
```

Run against a public endpoint (no auth, no VP):

```bash
hey -n 5000 -c 50 http://localhost:8080/health
```

### Useful Prometheus Queries

After the stress test, query in the Prometheus UI (`http://localhost:9091`):

- `rate(pingora_upstream_connect_total[1m])` — upstream connections per second
- `pingora_upstream_response_latency_bucket` — response latency histogram
- `pingora_connections_total` — total connections handled

### Cleanup

```bash
docker rm -f forgeguard-prometheus
rm /tmp/prometheus.yml
```

## Architecture

```
Client → proxy:8080 → app:3000
           │
           ├─ Health check    → 200 (no auth)
           ├─ CORS preflight  → 204 (no auth)
           ├─ Public route    → pass through (anonymous/opportunistic)
           ├─ Extract credential (Bearer JWT / X-API-Key)
           ├─ Resolve identity (CognitoJwtResolver / StaticApiKeyResolver)
           ├─ Evaluate feature flags
           ├─ Match route → action
           ├─ Check feature gate
           ├─ Evaluate policy (Verified Permissions)
           ├─ Inject X-ForgeGuard-* headers (user, tenant, groups, features)
           └─ Proxy to upstream (app scopes data by tenant header)
```
