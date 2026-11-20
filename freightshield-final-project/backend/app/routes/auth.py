"""Google sign-in / self-sign-up -> httpOnly session cookie (HS256 JWT).
POST /auth/google         sign in: only existing, active users (unchanged behaviour).
POST /auth/google/signup  sign up: a verified Google identity with no account gets the least-privileged `user` role.
The role is always decided server-side (user store / SELF_SIGNUP_ROLE), never by Google or the client."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.core.config import Settings, get_settings
from app.core.roles import profile
from app.core.security import MIN_SECRET_LEN, _ip, current_user, issue_token, new_csrf_token, revoke, session_claims
from app.services import audit, google_auth, users

router = APIRouter(prefix="/auth", tags=["auth"])

SELF_SIGNUP_ROLE = "user"  # constant on purpose: not configurable, not client-supplied, never admin/vendor


class GoogleLogin(BaseModel):
    credential: str = Field(min_length=20, max_length=4096)


@router.get("/status")
def auth_status(s: Settings = Depends(get_settings)) -> dict:
    """Configuration state only (no secrets): lets operators and the login page see what is missing."""
    return {"google_configured": bool(s.google_client_id), "jwt_configured": len(s.auth_jwt_secret) >= MIN_SECRET_LEN}


@router.post("/google")
def google_login(body: GoogleLogin, request: Request, response: Response, s: Settings = Depends(get_settings)) -> dict:
    ip = _ip(request)
    if len(s.auth_jwt_secret) < MIN_SECRET_LEN:
        raise HTTPException(503, "Authentication is not configured on the server.")
    try:
        claims = google_auth.verify_id_token(body.credential)
    except HTTPException:
        audit.record(None, "login", "google", "denied", ip, "invalid google credential")
        raise
    user = users.get_by_email(claims["email"])
    if not user or not user["active"]:
        audit.record(user, "login", "google", "denied", ip,
                     "account disabled" if user else f"unregistered email={claims['email']}")
        raise HTTPException(403, "This account is not registered or is disabled. Ask an IT Security Administrator for access.")
    csrf = _set_session_cookies(response, s, issue_token(user, s))
    audit.record(user, "login", "google", ip=ip)
    return {**profile(user), "csrf_token": csrf}


@router.post("/google/signup")
def google_signup(body: GoogleLogin, request: Request, response: Response, s: Settings = Depends(get_settings)) -> dict:
    """Self-registration. The body carries ONLY the Google ID token: identity comes from the verified token and the role
    is fixed server-side to SELF_SIGNUP_ROLE ('user'). Existing accounts are never modified or upgraded here."""
    ip = _ip(request)
    if len(s.auth_jwt_secret) < MIN_SECRET_LEN:
        raise HTTPException(503, "Authentication is not configured on the server.")
    if not s.self_signup_enabled:
        raise HTTPException(403, "Self-registration is disabled. Ask an IT Security Administrator for access.")
    try:
        claims = google_auth.verify_id_token(body.credential)
    except HTTPException:
        audit.record(None, "signup", "google", "denied", ip, "invalid google credential")
        raise
    email = claims["email"].lower()
    if users.get_by_email(email):
        audit.record(None, "signup", "google", "denied", ip, f"already registered email={email}")
        raise HTTPException(409, "An account with this Google email already exists. Use Sign in instead.")
    user = users.create(email, SELF_SIGNUP_ROLE)  # 409 on a concurrent duplicate (UNIQUE email)
    csrf = _set_session_cookies(response, s, issue_token(user, s))
    audit.record(user, "signup", "google", ip=ip, detail=f"self-registered role={SELF_SIGNUP_ROLE}")
    return {**profile(user), "csrf_token": csrf}


def _cookie_attrs(s: Settings) -> dict:
    secure = s.app_env.lower() == "production"  # cross-site (Vercel -> API) cookies need SameSite=None; Secure
    return {"httponly": True, "secure": secure, "samesite": "none" if secure else "lax", "path": "/api"}


def _set_session_cookies(response: Response, s: Settings, token: str, csrf: str | None = None) -> str:
    """Session + CSRF cookies are both httpOnly and scoped to /api; the CSRF value is handed to the SPA in the body."""
    csrf = csrf or new_csrf_token()
    attrs, ttl = _cookie_attrs(s), s.auth_token_ttl_minutes * 60
    if token:
        response.set_cookie(s.auth_cookie_name, token, max_age=ttl, **attrs)
    response.set_cookie(s.csrf_cookie_name, csrf, max_age=ttl, **attrs)
    return csrf


@router.get("/me")
def me(request: Request, response: Response, user: dict = Depends(current_user), s: Settings = Depends(get_settings)) -> dict:
    """Also (re)issues the CSRF token so a reloaded SPA can resume its cookie session."""
    csrf = request.cookies.get(s.csrf_cookie_name)
    if request.cookies.get(s.auth_cookie_name):
        csrf = _set_session_cookies(response, s, "", csrf)
    return {**profile(user), "csrf_token": csrf}


@router.post("/logout")
def logout(request: Request, response: Response, s: Settings = Depends(get_settings)) -> dict:
    try:
        claims = session_claims(request, s)
        user = current_user(request, s)
        revoke(claims)  # the token is dead server-side even if a copy was stolen
        audit.record(user, "logout", "session", ip=_ip(request))
    except HTTPException:
        pass  # expired/invalid session: still clear the cookie
    attrs = _cookie_attrs(s)
    for name in (s.auth_cookie_name, s.csrf_cookie_name):
        response.delete_cookie(name, path=attrs["path"], secure=attrs["secure"], httponly=True, samesite=attrs["samesite"])
        response.delete_cookie(name, path="/")  # legacy pre-Phase-10 cookie path
    return {"logged_out": True}
