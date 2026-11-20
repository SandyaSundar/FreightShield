"""User management (admin only). Every mutation is audited."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core.roles import Role
from app.core.security import _ip, require_permission
from app.services import audit, users

router = APIRouter(prefix="/users", tags=["users"])
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class NewUser(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=254)
    role: Role


class UserPatch(BaseModel):
    role: Role | None = None
    active: bool | None = None


@router.get("")
def list_users(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), role: Role | None = None,
               active: bool | None = None, _: dict = Depends(require_permission("users:read"))):
    items, total = users.list_users(limit, (page - 1) * limit, role, active)
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/{user_id}")
def get_user(user_id: int, _: dict = Depends(require_permission("users:read"))):
    u = users.get_by_id(user_id)
    if not u:
        raise HTTPException(404, "User not found.")
    return u


@router.post("", status_code=201)
def create_user(body: NewUser, request: Request, actor: dict = Depends(require_permission("users:write"))):
    u = users.create(body.email, body.role)
    audit.record(actor, "user_create", f"user:{u['id']}", ip=_ip(request), detail=f"role={u['role']}")
    return u


@router.patch("/{user_id}")
def patch_user(user_id: int, body: UserPatch, request: Request,
               actor: dict = Depends(require_permission("users:write"))):
    if body.role is None and body.active is None:
        raise HTTPException(422, "Nothing to update.")
    try:
        u = users.update(user_id, actor["id"], body.role, body.active)
    except HTTPException as e:
        audit.record(actor, "user_update", f"user:{user_id}", "denied", _ip(request), e.detail)
        raise
    audit.record(actor, "user_update", f"user:{user_id}", ip=_ip(request), detail=f"role={u['role']} active={u['active']}")
    return u


@router.delete("/{user_id}")
def delete_user(user_id: int, request: Request, actor: dict = Depends(require_permission("users:write"))):
    try:
        u = users.delete(user_id, actor["id"])
    except HTTPException as e:
        audit.record(actor, "user_delete", f"user:{user_id}", "denied", _ip(request), e.detail)
        raise
    audit.record(actor, "user_delete", f"user:{user_id}", ip=_ip(request), detail=f"email={u['email']}")
    return {"deleted": user_id}
