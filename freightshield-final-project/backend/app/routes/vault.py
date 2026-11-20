"""Admin-only management of encrypted integration secrets. Secret values are write-only."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.security import _ip, require_permission
from app.services import audit, secret_vault
from app.services.secret_vault import VaultUnavailable

router = APIRouter(prefix="/vault", tags=["secret-vault"])


class SecretInput(BaseModel):
    value: str = Field(min_length=1, max_length=4096)


@router.get("/secrets")
def list_secrets(request: Request, user: dict = Depends(require_permission("users:write"))) -> dict:
    audit.record(user, "vault_inventory", "integration_secrets", ip=_ip(request))
    return {"items": secret_vault.inventory()}


@router.put("/secrets/{name}")
def set_secret(name: str, body: SecretInput, request: Request,
               user: dict = Depends(require_permission("users:write"))) -> dict:
    try:
        secret_vault.put(name, body.value)
    except ValueError:
        raise HTTPException(400, "Unsupported secret name.")
    except VaultUnavailable as exc:
        raise HTTPException(503, str(exc))
    audit.record(user, "vault_secret_set", name, ip=_ip(request), detail="encrypted secret stored; value omitted")
    return {"name": name, "stored_encrypted": True}


@router.delete("/secrets/{name}")
def remove_secret(name: str, request: Request,
                  user: dict = Depends(require_permission("users:write"))) -> dict:
    try:
        removed = secret_vault.delete(name)
    except ValueError:
        raise HTTPException(400, "Unsupported secret name.")
    audit.record(user, "vault_secret_delete", name, ip=_ip(request), detail="secret value omitted")
    return {"name": name, "deleted": removed}
