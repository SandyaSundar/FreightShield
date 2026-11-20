"""RBAC introspection: who am I, and what can each role do."""
from fastapi import APIRouter, Depends

from app.core.roles import ROLE_LABELS, ROLE_PERMISSIONS, profile
from app.core.security import current_user, require_permission

router = APIRouter(prefix="/rbac", tags=["rbac"])


@router.get("/me")
def me(user: dict = Depends(current_user)) -> dict:
    return profile(user)


@router.get("/roles", dependencies=[Depends(require_permission("users:read"))])
def roles() -> dict:
    return {"roles": {r: sorted(p) for r, p in ROLE_PERMISSIONS.items()}, "labels": ROLE_LABELS}
