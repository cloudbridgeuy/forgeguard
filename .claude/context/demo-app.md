# Demo App (`examples/todo-app/`)

End-to-end demonstration of the ForgeGuard proxy with a Python/FastAPI backend.

## Purpose

Proves the proxy works end-to-end: JWT auth, API key auth, public routes, feature flags, feature gates, feature-driven branching, policy evaluation, header injection — all with a language-agnostic upstream that has **zero ForgeGuard imports**.

Two distinct feature flag mechanisms are demonstrated:
- **Gate** (`todo:ai-suggestions`): proxy blocks the route entirely when the flag is disabled for a tenant
- **Branch** (`todo:premium-ai`): app reads the flag value from `X-ForgeGuard-Features` to select the AI model per tenant

## Files

| File | Purpose |
|------|---------|
| `app.py` | FastAPI TODO app — reads `X-ForgeGuard-*` headers only |
| `forgeguard.toml` | Full demo config exercising every proxy feature |
| `pyproject.toml` | Python dependencies (fastapi, uvicorn) via uv |
| `README.md` | Setup and demo instructions |
| `docker-compose.yml` | One-command demo: app + proxy + Prometheus |
| `Dockerfile` | Python app image (python:3.12-slim + uv) |
| `prometheus.yml` | Scrape config targeting proxy metrics on port 6150 |
| `.dockerignore` | Excludes `.venv/`, `__pycache__/` from Docker build context |

## Running

### Native (two terminals)

```bash
# Terminal 1: Start the Python app
cd examples/todo-app
uv run uvicorn app:app --port 3000

# Terminal 2: Start the proxy (works natively on macOS)
cargo run --bin forgeguard-proxy -- run --config examples/todo-app/forgeguard.toml --debug
```

Requires AWS credentials (`admin` profile) for Cognito JWKS + Verified Permissions.

### Docker Compose

```bash
cd examples/todo-app
docker compose up --build
```

Starts: Python app (`:3000`), proxy (`:8080`), Prometheus (`:9090`). The proxy overrides `upstream_url` and `listen_addr` via `FORGEGUARD_UPSTREAM` and `FORGEGUARD_LISTEN` env vars for container networking.

## Demo Config Highlights

- **Auth chain:** `["jwt", "api-key"]`
- **5 API keys:** alice (admin), bob (member), charlie (viewer) @ acme-corp; dave (admin), eve (viewer) @ globex-corp
- **8 routes** with Cedar actions, resource params, and a feature gate
- **3 public routes:** health (anonymous), webhooks (anonymous), docs (opportunistic)
- **4 policies:** admin-full, member-crud, viewer-read, top-secret-deny with `except`
- **5 feature flags:** maintenance-mode, todo:ai-suggestions (tenant override), todo:sharing (rollout), todo:max-upload-mb (number + override), todo:premium-ai (string + override)
- **Metrics:** Prometheus endpoint on port 6150 (`[metrics] enabled = true`)

## Integration Tests

`crates/proxy/tests/integration.rs` — 11 end-to-end tests exercising the proxy binary.

Run: `cargo test -p forgeguard_proxy`

Tests use a harness that spawns an axum echo upstream + proxy child process per test, polls health until ready, and kills on drop. Config uses API keys only (no AWS deps), `default_policy = "deny"`, and `AllowAllEngine` (no `[authz]` section).

| Test | Verifies |
|------|----------|
| `health_returns_200` | Health endpoint returns `{"status":"ok"}` |
| `no_credential_returns_401` | Protected route rejects unauthenticated |
| `invalid_api_key_returns_401` | Bad API key rejected |
| `valid_credential_returns_200` | Valid key passes through |
| `valid_credential_injects_headers` | Proxy injects `X-ForgeGuard-*` identity headers |
| `unmatched_route_returns_403` | Unmatched route denied by default policy |
| `anonymous_public_route_returns_200` | Anonymous public route works |
| `opportunistic_without_cred` | Opportunistic route works without creds |
| `opportunistic_with_cred` | Opportunistic route injects headers with creds |
| `feature_gate_enabled_returns_200` | Feature-gated route passes for enabled tenant |
| `feature_gate_disabled_returns_404` | Feature-gated route blocked for disabled tenant |
