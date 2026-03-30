# Demo App (`examples/todo-app/`)

End-to-end demonstration of the ForgeGuard proxy with a Python/FastAPI backend.

## Purpose

Proves the proxy works end-to-end: JWT auth, API key auth, public routes, feature flags, feature gates, policy evaluation, header injection — all with a language-agnostic upstream that has **zero ForgeGuard imports**.

## Files

| File | Purpose |
|------|---------|
| `app.py` | FastAPI TODO app — reads `X-ForgeGuard-*` headers only |
| `forgeguard.toml` | Full demo config exercising every proxy feature |
| `requirements.txt` | Python dependencies (fastapi, uvicorn) |
| `docker-compose.yml` | Proxy + app containers |
| `README.md` | Setup and demo instructions |

## Running

```bash
# Docker (required for macOS — Pingora needs Linux)
cd examples/todo-app && docker compose up --build

# Or native Linux
uvicorn app:app --port 3000 &
cargo run --bin forgeguard-proxy -- run --config examples/todo-app/forgeguard.toml --debug
```

## Demo Config Highlights

- **Auth chain:** `["jwt", "api-key"]`
- **3 API keys:** alice (admin), bob (member), charlie (viewer)
- **8 routes** with Cedar actions, resource params, and a feature gate
- **3 public routes:** health (anonymous), webhooks (anonymous), docs (opportunistic)
- **4 policies:** admin-full, member-crud, viewer-read, top-secret-deny with `except`
- **3 feature flags:** maintenance-mode, todo:ai-suggestions (tenant override), todo:sharing (rollout)

## Docker Architecture

```
docker-compose.yml
├── app (python:3.12-slim)
│   └── uvicorn app:app --port 3000
└── proxy (crates/proxy/Dockerfile)
    └── forgeguard-proxy run --config /etc/forgeguard/forgeguard.toml
```

The proxy Dockerfile is a multi-stage build at `crates/proxy/Dockerfile`. The compose file mounts `~/.aws` for VP authorization and the demo `forgeguard.toml`.
