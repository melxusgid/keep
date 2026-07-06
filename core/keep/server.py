"""Keep REST API server — agent-friendly HTTP interface to the vault."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from keep.vault import Vault, LockedError, Error

app = FastAPI(
    title="Keep",
    description="Encrypted secrets vault — agent-friendly API",
    version="0.1.0",
)

_vault: Vault | None = None


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault()
    return _vault


# ── Models ─────────────────────────────────────────────────────────

class UnlockRequest(BaseModel):
    password: str


class SetRequest(BaseModel):
    value: str
    note: str = ""


class StatusResponse(BaseModel):
    locked: bool
    secret_count: int = 0
    audit_entries: int = 0
    vault_path: str = ""


class SecretResponse(BaseModel):
    name: str
    value: str


class SecretListItem(BaseModel):
    name: str
    created_at: float
    updated_at: float
    metadata: dict = {}


class AuditEntry(BaseModel):
    action: str
    secret_name: str
    context: str
    timestamp: float


class EnvResponse(BaseModel):
    secrets: dict[str, str]


class Message(BaseModel):
    message: str


# ── Middleware ──────────────────────────────────────────────────────

def _check_unlocked():
    v = get_vault()
    if v.locked:
        raise HTTPException(status_code=423, detail="Vault is locked. POST /unlock first.")


# ── Routes ─────────────────────────────────────────────────────────

@app.get("/health")
def health():
    v = get_vault()
    return {"status": "ok", "locked": v.locked}


@app.post("/init", response_model=Message)
def init_vault(req: UnlockRequest):
    """Create a new vault. WARNING: overwrites existing vault."""
    v = get_vault()
    v.init(req.password)
    return {"message": "Vault created."}


@app.post("/unlock", response_model=Message)
def unlock_vault(req: UnlockRequest):
    """Unlock the vault with a master password."""
    v = get_vault()
    try:
        v.unlock(req.password)
        return {"message": "Vault unlocked."}
    except Error as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.post("/lock", response_model=Message)
def lock_vault():
    """Lock the vault and wipe the key from memory."""
    v = get_vault()
    v.lock()
    return {"message": "Vault locked."}


@app.get("/secrets", response_model=list[SecretListItem])
def list_secrets():
    """List all secret names with metadata (values stay encrypted)."""
    _check_unlocked()
    v = get_vault()
    return v.list()


@app.get("/secrets/{name}", response_model=SecretResponse)
def get_secret(name: str):
    """Retrieve a decrypted secret value."""
    _check_unlocked()
    v = get_vault()
    value = v.get(name)
    if value is None:
        raise HTTPException(status_code=404, detail=f"Secret '{name}' not found.")
    return SecretResponse(name=name, value=value)


@app.post("/secrets/{name}", response_model=Message)
def set_secret(name: str, req: SetRequest):
    """Store a new secret (encrypted at rest)."""
    _check_unlocked()
    v = get_vault()
    v.set(name, req.value, note=req.note)
    return {"message": f"Secret '{name}' stored."}


@app.delete("/secrets/{name}", response_model=Message)
def delete_secret(name: str):
    """Delete a secret."""
    _check_unlocked()
    v = get_vault()
    if v.delete(name):
        return {"message": f"Secret '{name}' deleted."}
    raise HTTPException(status_code=404, detail=f"Secret '{name}' not found.")


@app.post("/secrets/{name}/rotate", response_model=SecretResponse)
def rotate_secret(name: str, length: int = 32):
    """Generate a random secret and store it."""
    _check_unlocked()
    v = get_vault()
    new_val = v.rotate(name, length=length)
    if new_val is None:
        raise HTTPException(status_code=500, detail="Rotation failed.")
    return SecretResponse(name=name, value=new_val)


@app.get("/audit", response_model=list[AuditEntry])
def get_audit(limit: int = 50):
    """Retrieve audit log entries."""
    _check_unlocked()
    v = get_vault()
    return v.audit(limit=limit)


@app.get("/env", response_model=EnvResponse)
def get_env():
    """Export all secrets as a flat dict (for environment injection)."""
    _check_unlocked()
    v = get_vault()
    return EnvResponse(secrets=v.env())


@app.get("/status", response_model=StatusResponse)
def get_status():
    """Show vault status without unlocking."""
    v = get_vault()
    result = StatusResponse(
        locked=v.locked,
        vault_path=str(v.path),
    )
    if not v.locked:
        try:
            stats = v.stats()
            result.secret_count = stats["secret_count"]
            result.audit_entries = stats["audit_entries"]
        except Exception:
            pass
    return result


# ── Entry point ────────────────────────────────────────────────────

def serve(host: str = "127.0.0.1", port: int = 7391):
    uvicorn.run(
        "keep.server:app",
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    serve()
