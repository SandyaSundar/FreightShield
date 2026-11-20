"""Phase 10 HTTP hardening: secure headers, request-size limits, rate limiting and CSRF protection.

CSRF model (double-submit, works cross-site Vercel -> API): sign-in sets an httpOnly `fs_csrf` cookie and returns the
same random token in the JSON body; the SPA keeps it in memory and echoes it in `X-CSRF-Token` on every unsafe request.
Requests authenticated with a Bearer header are exempt (a browser never attaches that header cross-site on its own).
Unsafe cookie requests from an Origin outside CORS_ALLOWED_ORIGINS are rejected outright.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.core.security import _ip, csrf_matches

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_EXEMPT = {"/api/auth/google", "/api/auth/google/signup", "/api/auth/logout"}  # sign-in has no session yet (Google credential is unforgeable); forced logout is harmless
MAX_URL = 2048

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class RateLimiter:
    """In-memory sliding window per (bucket, key). Single-process only: use a shared store (Redis) when scaling out."""

    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, bucket: str, key: str, limit: int, window: float = 60.0) -> int:
        """Returns 0 when allowed, else seconds until retry."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[(bucket, key)]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory under IP-spraying
                for k in [k for k, v in self._hits.items() if not v][:25_000]:
                    del self._hits[k]
            return 0

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def _bucket(path: str, s) -> tuple[str, int]:
    if path.startswith("/api/auth/google"):
        return "auth", s.rate_limit_auth_per_minute
    if path.startswith("/api/ai/"):
        return "ai", s.rate_limit_ai_per_minute
    return "api", s.rate_limit_per_minute


def _err(status: int, code: str, detail: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "detail": detail}, headers=headers)


class HardeningMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        s = get_settings()
        resp = await self._guard(request, s)
        if resp is None:
            resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if s.app_env.lower() == "production":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        if "server" in resp.headers:
            del resp.headers["server"]
        return resp

    async def _guard(self, request: Request, s):
        path, method = request.url.path, request.method.upper()
        if len(str(request.url)) > MAX_URL:
            return _err(414, "uri_too_long", "Request URI too long.")
        if method == "OPTIONS":
            return None  # CORS preflight is answered by CORSMiddleware
        cl = request.headers.get("content-length")
        if cl is not None:
            if not cl.isdigit() or int(cl) > s.max_body_bytes:
                return _err(413, "payload_too_large", "Request body too large.")
        elif method not in SAFE_METHODS and request.headers.get("transfer-encoding"):
            body = await request.body()  # chunked upload: enforce the same cap
            if len(body) > s.max_body_bytes:
                return _err(413, "payload_too_large", "Request body too large.")
        if s.rate_limit_enabled and path.startswith("/api/") and path != "/api/health":
            bucket, limit = _bucket(path, s)
            retry = limiter.hit(bucket, _ip(request) or "unknown", limit)
            if retry:
                return _err(429, "rate_limited", "Too many requests. Slow down and retry later.", {"Retry-After": str(retry)})
        if method not in SAFE_METHODS and path.startswith("/api/") and path not in CSRF_EXEMPT:
            uses_bearer = request.headers.get("authorization", "").lower().startswith("bearer ")
            if not uses_bearer and request.cookies.get(s.auth_cookie_name):
                origin = request.headers.get("origin")
                if origin and origin.rstrip("/") not in s.cors_allowed_origins:
                    return _err(403, "csrf_failed", "Cross-origin request rejected.")
                if not csrf_matches(request.headers.get("x-csrf-token"), request.cookies.get(s.csrf_cookie_name)):
                    return _err(403, "csrf_failed", "Missing or invalid CSRF token. Reload the page and sign in again.")
        return None


def install(app: FastAPI) -> None:
    app.add_middleware(HardeningMiddleware)
