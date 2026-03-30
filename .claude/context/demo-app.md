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
| `README.md` | Setup and demo instructions |

## Running

```bash
# Terminal 1: Start the Python app
cd examples/todo-app
pip install -r requirements.txt
uvicorn app:app --port 3000

# Terminal 2: Start the proxy (works natively on macOS)
cargo run --bin forgeguard-proxy -- run --config examples/todo-app/forgeguard.toml --debug
```

Requires AWS credentials (`admin` profile) for Cognito JWKS + Verified Permissions.

## Demo Config Highlights

- **Auth chain:** `["jwt", "api-key"]`
- **5 API keys:** alice (admin), bob (member), charlie (viewer) @ acme-corp; dave (admin), eve (viewer) @ globex-corp
- **8 routes** with Cedar actions, resource params, and a feature gate
- **3 public routes:** health (anonymous), webhooks (anonymous), docs (opportunistic)
- **4 policies:** admin-full, member-crud, viewer-read, top-secret-deny with `except`
- **3 feature flags:** maintenance-mode, todo:ai-suggestions (tenant override), todo:sharing (rollout)
