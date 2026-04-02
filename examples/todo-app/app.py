"""ForgeGuard Demo — TODO API.

Zero ForgeGuard imports. Reads X-ForgeGuard-* headers injected by the proxy.
All data is in-memory (no database). Multi-tenant: data is scoped by tenant.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="ForgeGuard TODO Demo", version="0.1.0")

# ---------------------------------------------------------------------------
# Signature verification (optional)
# ---------------------------------------------------------------------------
# Set FORGEGUARD_PUBLIC_KEY to the path of the Ed25519 public key PEM file.
# When set, every request with signature headers is verified and the result
# is included in the response as "signature_verified": true/false.

_VERIFYING_KEY = None
_PUBLIC_KEY_PATH = os.environ.get("FORGEGUARD_PUBLIC_KEY")

if _PUBLIC_KEY_PATH:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    with open(_PUBLIC_KEY_PATH, "rb") as f:
        _VERIFYING_KEY = load_pem_public_key(f.read())


def verify_signature(request: Request) -> dict[str, Any] | None:
    """Verify the Ed25519 signature on X-ForgeGuard-* headers.

    Returns None if no signature headers are present or no public key is
    configured. Otherwise returns {"verified": bool, "error": str | None}.
    """
    sig_header = request.headers.get("x-forgeguard-signature")
    if not sig_header or not _VERIFYING_KEY:
        return None

    try:
        trace_id = request.headers.get("x-forgeguard-trace-id", "")
        timestamp = request.headers.get("x-forgeguard-timestamp", "")

        # Collect identity headers (exclude signature-related ones)
        skip = {
            "x-forgeguard-signature",
            "x-forgeguard-timestamp",
            "x-forgeguard-trace-id",
            "x-forgeguard-key-id",
        }
        identity_headers = sorted(
            (k, v)
            for k, v in request.headers.items()
            if k.startswith("x-forgeguard-") and k not in skip
        )

        # Reconstruct canonical payload (must match Rust CanonicalPayload::new)
        lines = [
            "forgeguard-sig-v1",
            f"trace-id:{trace_id}",
            f"timestamp:{timestamp}",
        ]
        for name, value in identity_headers:
            lines.append(f"{name}:{value}")
        canonical = "".join(line + "\n" for line in lines).encode()

        # Parse "v1:{base64}" signature
        if not sig_header.startswith("v1:"):
            return {"verified": False, "error": "unknown signature version"}
        sig_bytes = base64.b64decode(sig_header[3:])

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        assert isinstance(_VERIFYING_KEY, Ed25519PublicKey)
        _VERIFYING_KEY.verify(sig_bytes, canonical)
        return {"verified": True, "error": None}
    except Exception as exc:
        return {"verified": False, "error": str(exc)}

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

    result = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "groups": groups,
        "auth_provider": provider,
        "features": features,
        "client_ip": client_ip,
    }

    sig_result = verify_signature(request)
    if sig_result is not None:
        result["signature_verified"] = sig_result["verified"]
        if sig_result["error"]:
            result["signature_error"] = sig_result["error"]

    return result


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
    """This route is feature-gated behind 'todo:ai-suggestions'.

    Reads the 'todo:premium-ai' flag to select the AI model — demonstrates
    feature-flag-driven branching behavior (gate = proxy, branch = app).
    """
    identity = get_identity(request)
    flags = identity["features"].get("flags", {})
    model = flags.get("todo:premium-ai", "gpt-4o-mini")
    return {
        "suggestions": ["Buy milk", "Call dentist", "Review PR"],
        "model": model,
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
