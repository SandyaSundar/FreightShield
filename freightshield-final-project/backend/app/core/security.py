"""Backend authentication + RBAC guard (fail-closed).

Authentication: a signed session JWT (HS256, AUTH_JWT_SECRET) in the httpOnly cookie or a Bearer header.
Phase 10: tokens carry iss/aud/iat/nbf/exp/jti, all verified; logout revokes the jti server-side.
Authorization: the token's `sub` is the user id; the role and active flag are read from the user store on
every request (so demotion/disable takes effect immediately) and checked against core/roles.py.
Tokens are issued only by routes/auth.py after a verified Google sign-in of a pre-registered, active user.
"""
import hmac
import secrets
import time

import jwt
from fastapi import Depends, HTTPException, Request

from app.core.config import Settings, get_settings
from app.core.db import connect
from app.core.roles import ROLE_PERMISSIONS
from app.services import audit, users

MIN_SECRET_LEN = 32
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]


def issue_token(user: dict, s: Settings) -> str:
    now = int(time.time())
    return jwt.encode({"sub": str(user["id"]), "iat": now, "nbf": now, "exp": now + s.auth_token_ttl_minutes * 60,
                       "iss": s.auth_jwt_issuer, "aud": s.auth_jwt_audience, "jti": secrets.token_urlsafe(16)},
                      s.auth_jwt_secret, algorithm="HS256")


def decode_token(token: str, s: Settings) -> dict:
    """Raises jwt.PyJWTError on any problem. Algorithm is pinned (no 'none', no RS/HS confusion)."""
    return jwt.decode(token, s.auth_jwt_secret, algorithms=["HS256"], audience=s.auth_jwt_audience,
                      issuer=s.auth_jwt_issuer, leeway=10, options={"require": REQUIRED_CLAIMS})


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_matches(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a, b)


def revoke(claims: dict) -> None:
    now = int(time.time())
    with connect() as c:
        c.execute("DELETE FROM revoked_tokens WHERE exp < ?", (now,))
        c.execute("INSERT OR IGNORE INTO revoked_tokens(jti, exp) VALUES (?, ?)", (str(claims["jti"]), int(claims["exp"])))


def is_revoked(jti: str) -> bool:
    with connect() as c:
        return c.execute("SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)).fetchone() is not None


def _ip(request: Request) -> str | None:
    if get_settings().trust_proxy:
        fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if fwd:
            return fwd[:64]
    return request.client.host if request.client else None


def _extract_token(request: Request, s: Settings) -> str | None:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("bearer ") and h[7:].strip():
        return h[7:].strip()
    return request.cookies.get(s.auth_cookie_name) or None


def session_claims(request: Request, s: Settings) -> dict:
    if len(s.auth_jwt_secret) < MIN_SECRET_LEN:
        raise HTTPException(503, "Authentication is not configured on the server.")
    token = _extract_token(request, s)
    if not token:
        raise HTTPException(401, "Authentication required.")
    if len(token) > 4096:
        raise HTTPException(401, "Invalid or expired session.")
    try:
        claims = decode_token(token, s)
        int(claims["sub"])
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired session.")
    if is_revoked(str(claims["jti"])):
        raise HTTPException(401, "Invalid or expired session.")
    return claims


def current_user(request: Request, s: Settings = Depends(get_settings)) -> dict:
    claims = session_claims(request, s)
    user = users.get_by_id(int(claims["sub"]))
    if not user:
        raise HTTPException(401, "Invalid or expired session.")
    if not user["active"]:
        audit.record(user, "auth_denied", request.url.path, "denied", _ip(request), "account disabled")
        raise HTTPException(403, "Account disabled.")
    return user


def require_permission(permission: str, audit_success: bool = False):
    """Route dependency. Denials are always audited; successes only when audit_success (sensitive data)."""
    def dep(request: Request, user: dict = Depends(current_user)) -> dict:
        if permission not in ROLE_PERMISSIONS.get(user["role"], frozenset()):
            audit.record(user, "access_denied", request.url.path, "denied", _ip(request), permission)
            raise HTTPException(403, "Insufficient permissions.")
        if audit_success:
            audit.record(user, "access", request.url.path, "success", _ip(request), permission)
        return user
    return dep
