"""Backend authentication + RBAC guard (fail-closed).

The login flow (app/routes/auth.py) is not implemented yet and no fake login exists.
This module only VERIFIES a signed session JWT (HS256, AUTH_JWT_SECRET) carried in the
httpOnly session cookie or an Authorization: Bearer header, and checks the role claim.
With no secret configured, or no/invalid token, protected routes are refused.
"""
import jwt
from fastapi import Depends, HTTPException, Request

from app.core.config import Settings, get_settings

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"wazuh:read", "wazuh:agents", "wazuh:alerts"}),
    "analyst": frozenset({"wazuh:read", "wazuh:agents", "wazuh:alerts"}),
    "viewer": frozenset(),
}
MIN_SECRET_LEN = 32


def _extract_token(request: Request, s: Settings) -> str | None:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("bearer ") and h[7:].strip():
        return h[7:].strip()
    return request.cookies.get(s.auth_cookie_name) or None


def current_user(request: Request, s: Settings = Depends(get_settings)) -> dict:
    if len(s.auth_jwt_secret) < MIN_SECRET_LEN:
        raise HTTPException(503, "Authentication is not configured on the server.")
    token = _extract_token(request, s)
    if not token:
        raise HTTPException(401, "Authentication required.")
    try:
        claims = jwt.decode(token, s.auth_jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired session.")
    return {"sub": claims["sub"], "role": str(claims.get("role", ""))}


def require_permission(permission: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if permission not in ROLE_PERMISSIONS.get(user["role"], frozenset()):
            raise HTTPException(403, "Insufficient permissions.")
        return user
    return dep
