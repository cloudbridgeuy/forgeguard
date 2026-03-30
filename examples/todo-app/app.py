"""ForgeGuard Demo — TODO API.

Zero ForgeGuard imports. Reads X-ForgeGuard-* headers injected by the proxy.
All data is in-memory (no database). Multi-tenant: data is scoped by tenant.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="ForgeGuard TODO Demo", version="0.1.0")

# ---------------------------------------------------------------------------
# In-memory store — keyed by tenant
# ---------------------------------------------------------------------------

STORE: dict[str, dict[str, dict[str, Any]]] = {
    "acme-corp": {
        "default": {
            "id": "default",
            "name": "Acme Tasks",
            "owner": "alice",
            "items": [],
        },
        "top-secret": {
            "id": "top-secret",
            "name": "Top Secret Plans",
            "owner": "alice",
            "items": [],
        },
    },
    "globex-corp": {
        "default": {
            "id": "default",
            "name": "Globex Tasks",
            "owner": "dave",
            "items": [],
        },
        "project-omega": {
            "id": "project-omega",
            "name": "Project Omega",
            "owner": "dave",
            "items": [],
        },
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_identity(request: Request) -> dict[str, Any]:
    """Extract ForgeGuard identity from proxy-injected headers."""
    user_id = request.headers.get("x-forgeguard-user-id")
    tenant_id = request.headers.get("x-forgeguard-tenant-id")
    groups_raw = request.headers.get("x-forgeguard-groups", "")
    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
    provider = request.headers.get("x-forgeguard-auth-provider")
    features_raw = request.headers.get("x-forgeguard-features")
    features = json.loads(features_raw) if features_raw else {}
    client_ip = request.headers.get("x-forgeguard-client-ip")

    return {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "groups": groups,
        "auth_provider": provider,
        "features": features,
        "client_ip": client_ip,
    }


def get_tenant_store(tenant_id: str | None) -> dict[str, dict[str, Any]]:
    """Get the store for a tenant, creating it if needed."""
    if not tenant_id:
        raise HTTPException(status_code=400, detail="no tenant context")
    if tenant_id not in STORE:
        STORE[tenant_id] = {}
    return STORE[tenant_id]


# ---------------------------------------------------------------------------
# Public routes (anonymous)
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "todo-app"}


@app.post("/webhooks/{provider}")
def webhook(provider: str):
    return {"received": True, "provider": provider}


# ---------------------------------------------------------------------------
# Public routes (opportunistic)
# ---------------------------------------------------------------------------

@app.get("/docs/{page}")
def docs(page: str, request: Request):
    identity = get_identity(request)
    response = {"page": page, "content": f"Documentation for {page}"}
    if identity["user_id"]:
        response["personalized_for"] = identity["user_id"]
    return response


# ---------------------------------------------------------------------------
# Authenticated routes — all scoped to tenant
# ---------------------------------------------------------------------------

@app.get("/api/lists")
def list_lists(request: Request):
    identity = get_identity(request)
    tenant_store = get_tenant_store(identity["tenant_id"])
    return {
        "lists": list(tenant_store.values()),
        "identity": identity,
    }


@app.post("/api/lists")
def create_list(request: Request):
    identity = get_identity(request)
    tenant_store = get_tenant_store(identity["tenant_id"])
    list_id = str(uuid.uuid4())[:8]
    new_list = {
        "id": list_id,
        "name": f"List by {identity['user_id']}",
        "owner": identity["user_id"],
        "items": [],
    }
    tenant_store[list_id] = new_list
    return {"created": new_list, "identity": identity}


@app.get("/api/lists/{list_id}")
def get_list(list_id: str, request: Request):
    identity = get_identity(request)
    tenant_store = get_tenant_store(identity["tenant_id"])
    if list_id not in tenant_store:
        raise HTTPException(status_code=404, detail="list not found")
    return {"list": tenant_store[list_id], "identity": identity}


@app.delete("/api/lists/{list_id}")
def delete_list(list_id: str, request: Request):
    identity = get_identity(request)
    tenant_store = get_tenant_store(identity["tenant_id"])
    if list_id not in tenant_store:
        raise HTTPException(status_code=404, detail="list not found")
    deleted = tenant_store.pop(list_id)
    return {"deleted": deleted, "identity": identity}


@app.post("/api/lists/{list_id}/items")
def add_item(list_id: str, request: Request):
    identity = get_identity(request)
    tenant_store = get_tenant_store(identity["tenant_id"])
    if list_id not in tenant_store:
        raise HTTPException(status_code=404, detail="list not found")
    item = {
        "id": str(uuid.uuid4())[:8],
        "text": f"Item by {identity['user_id']}",
        "completed": False,
    }
    tenant_store[list_id]["items"].append(item)
    return {"item": item, "identity": identity}


@app.patch("/api/lists/{list_id}/items/{item_id}/complete")
def complete_item(list_id: str, item_id: str, request: Request):
    identity = get_identity(request)
    tenant_store = get_tenant_store(identity["tenant_id"])
    if list_id not in tenant_store:
        raise HTTPException(status_code=404, detail="list not found")
    for item in tenant_store[list_id]["items"]:
        if item["id"] == item_id:
            item["completed"] = True
            return {"item": item, "identity": identity}
    raise HTTPException(status_code=404, detail="item not found")


# ---------------------------------------------------------------------------
# Feature-gated route
# ---------------------------------------------------------------------------

@app.get("/api/lists/{list_id}/suggestions")
def suggestions(list_id: str, request: Request):
    """This route is feature-gated behind 'todo:ai-suggestions'."""
    identity = get_identity(request)
    return {
        "suggestions": ["Buy milk", "Call dentist", "Review PR"],
        "identity": identity,
    }


# ---------------------------------------------------------------------------
# Debug
# ---------------------------------------------------------------------------

@app.get("/debug/context")
def debug_context(request: Request):
    """Dump all X-ForgeGuard-* headers for debugging."""
    fg_headers = {
        k: v for k, v in request.headers.items() if k.startswith("x-forgeguard-")
    }
    return {"forgeguard_headers": fg_headers, "identity": get_identity(request)}
