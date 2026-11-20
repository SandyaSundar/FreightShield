"""Phase 10 security hardening: JWT, sessions, cookies, CSRF, rate limiting, input validation, secure headers,
the three-role access matrix over every API route, and vendor isolation."""
import re
from datetime import datetime, timezone

import httpx
import jwt
import pytest

from app.core.config import get_settings
from app.core.db import connect
from app.core.roles import ROLE_PERMISSIONS
from app.main import app
from app.services import google_auth, users, vendor_agents
from tests.helpers import SECRET, claims, make_user, token


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def H(uid, **kw):
    return {"Authorization": f"Bearer {token(uid, **kw)}"}


@pytest.fixture
def google(monkeypatch):
    monkeypatch.setattr(google_auth, "verify_id_token", lambda cred: {"email": cred.split(":", 1)[1]})


async def login(c, email):
    r = await c.post("/api/auth/google", json={"credential": "x" * 20 + ":" + email})
    assert r.status_code == 200, r.text
    jar = {k: v for k, v in r.cookies.items()}
    return r, jar


# ---------- JWT ----------
@pytest.mark.anyio
@pytest.mark.parametrize("bad", [dict(iss="evil"), dict(aud="other-api"), dict(jti=None), dict(iat=None), dict(nbf=None),
                                 dict(nbf=9_999_999_999)])
async def test_jwt_rejects_wrong_or_missing_claims(bad):
    u = make_user("admin")
    async with client() as c:
        assert (await c.get("/api/rbac/me", headers=H(u["id"], **bad))).status_code == 401


@pytest.mark.anyio
async def test_jwt_alg_none_and_wrong_alg_rejected():
    u = make_user("admin")
    none_tok = jwt.encode(claims(u["id"]), key=None, algorithm="none")
    hs512 = jwt.encode(claims(u["id"]), SECRET, algorithm="HS512")
    async with client() as c:
        for t in (none_tok, hs512, "a" * 5000):
            assert (await c.get("/api/rbac/me", headers={"Authorization": f"Bearer {t}"})).status_code == 401


def test_issued_token_has_hardened_claims():
    from app.core.security import decode_token, issue_token
    s = get_settings()
    c = decode_token(issue_token(make_user("vendor"), s), s)
    assert {"iss", "aud", "jti", "iat", "nbf", "exp"} <= set(c) and "role" not in c
    assert c["exp"] - c["iat"] == s.auth_token_ttl_minutes * 60


# ---------- sessions & cookies ----------
@pytest.mark.anyio
async def test_login_cookies_are_httponly_scoped_and_return_csrf(google):
    make_user("admin")
    async with client() as c:
        r = await c.post("/api/auth/google", json={"credential": "x" * 20 + ":admin@test.local"})
        assert r.status_code == 200 and len(r.json()["csrf_token"]) >= 32
        sc = r.headers.get_list("set-cookie")
        sess = next(x for x in sc if x.startswith("fs_session="))
        csrf = next(x for x in sc if x.startswith("fs_csrf="))
        for ck in (sess, csrf):
            assert "HttpOnly" in ck and "Path=/api" in ck and "samesite=lax" in ck.lower()


@pytest.mark.anyio
async def test_production_cookies_are_secure_samesite_none(google, monkeypatch):
    monkeypatch.setattr(get_settings(), "app_env", "production")
    make_user("admin")
    async with client() as c:
        r = await c.post("/api/auth/google", json={"credential": "x" * 20 + ":admin@test.local"})
        for ck in r.headers.get_list("set-cookie"):
            assert "Secure" in ck and "samesite=none" in ck.lower()
        assert "max-age=63072000" in r.headers["strict-transport-security"]


@pytest.mark.anyio
async def test_logout_revokes_token_server_side(google):
    make_user("admin")
    async with client() as c:
        r, jar = await login(c, "admin@test.local")
        stolen = jar["fs_session"]
        assert (await c.get("/api/auth/me")).status_code == 200
        assert (await c.post("/api/auth/logout")).status_code == 200
    async with client() as c2:  # a stolen copy of the cookie/token no longer works
        assert (await c2.get("/api/auth/me", headers={"Authorization": f"Bearer {stolen}"})).status_code == 401


@pytest.mark.anyio
async def test_me_reissues_csrf_for_resumed_session(google):
    make_user("admin")
    async with client() as c:
        r, jar = await login(c, "admin@test.local")
        me = await c.get("/api/auth/me")
        assert me.json()["csrf_token"] == r.json()["csrf_token"]


# ---------- CSRF ----------
@pytest.mark.anyio
async def test_csrf_required_for_cookie_mutations(google):
    make_user("admin")
    async with client() as c:
        r, _ = await login(c, "admin@test.local")
        body = {"email": "new@test.local", "role": "user"}
        assert (await c.post("/api/users", json=body)).status_code == 403
        assert (await c.post("/api/users", json=body, headers={"X-CSRF-Token": "forged" * 8})).status_code == 403
        evil = {"X-CSRF-Token": r.json()["csrf_token"], "Origin": "https://evil.example"}
        assert (await c.post("/api/users", json=body, headers=evil)).status_code == 403
        ok = await c.post("/api/users", json=body, headers={"X-CSRF-Token": r.json()["csrf_token"]})
        assert ok.status_code in (200, 201)
        assert users.get_by_email("new@test.local") is not None


@pytest.mark.anyio
async def test_bearer_clients_are_csrf_exempt():
    u = make_user("admin")
    async with client() as c:
        r = await c.post("/api/users", json={"email": "b@test.local", "role": "user"}, headers=H(u["id"]))
        assert r.status_code in (200, 201)


# ---------- rate limiting ----------
@pytest.mark.anyio
async def test_login_rate_limited(monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_auth_per_minute", 3)
    async with client() as c:
        codes = [(await c.post("/api/auth/google", json={"credential": "x"})).status_code for _ in range(5)]
    assert codes[:3] == [422] * 3 and codes[3:] == [429, 429]


@pytest.mark.anyio
async def test_api_rate_limited_with_retry_after(monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_per_minute", 5)
    u = make_user("admin")
    async with client() as c:
        rs = [await c.get("/api/rbac/me", headers=H(u["id"])) for _ in range(7)]
        assert [r.status_code for r in rs[:5]] == [200] * 5 and rs[5].status_code == 429
        assert int(rs[5].headers["retry-after"]) >= 1
        assert (await c.get("/api/health")).status_code == 200  # liveness probe never throttled


# ---------- input validation ----------
@pytest.mark.anyio
async def test_oversized_body_and_url_rejected():
    u = make_user("admin")
    async with client() as c:
        big = await c.post("/api/users", content=b"{" + b" " * 1_100_000 + b"}", headers={**H(u["id"]), "Content-Type": "application/json"})
        assert big.status_code == 413
        assert (await c.get("/api/rbac/me?x=" + "a" * 3000, headers=H(u["id"]))).status_code == 414


@pytest.mark.anyio
async def test_validation_errors_do_not_echo_input():
    u = make_user("admin")
    payload = "<script>alert(1)</script>secret-value"
    async with client() as c:
        r = await c.post("/api/users", json={"email": payload, "role": "root"}, headers=H(u["id"]))
    assert r.status_code == 422 and "secret-value" not in r.text and "<script>" not in r.text


@pytest.mark.anyio
async def test_sql_injection_strings_are_inert():
    u = make_user("admin")
    async with client() as c:
        r = await c.get("/api/users?role=admin' OR '1'='1", headers=H(u["id"]))
        assert r.status_code == 422
        r = await c.get("/api/users/1 OR 1=1", headers=H(u["id"]))
        assert r.status_code == 422


# ---------- secure headers / secrets ----------
@pytest.mark.anyio
async def test_secure_headers_on_every_response():
    async with client() as c:
        for r in (await c.get("/api/health"), await c.get("/api/rbac/me"), await c.get("/api/nope")):
            assert r.headers["x-content-type-options"] == "nosniff"
            assert r.headers["x-frame-options"] == "DENY"
            assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
            assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"


@pytest.mark.anyio
async def test_cors_never_reflects_untrusted_origin():
    async with client() as c:
        r = await c.options("/api/users", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        assert r.headers.get("access-control-allow-origin") != "https://evil.example"
        ok = await c.options("/api/users", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
                                                     "Access-Control-Request-Headers": "x-csrf-token"})
        assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"


@pytest.mark.anyio
async def test_no_secret_values_leak_from_status_endpoints(monkeypatch):
    s = get_settings()
    for k, v in {"smtp_password": "SMTPSECRETVALUE", "virustotal_api_key": "VTSECRETVALUE", "wazuh_manager_password": "WZSECRETVALUE"}.items():
        monkeypatch.setattr(s, k, v)
    u = make_user("admin")
    async with client() as c:
        texts = [(await c.get(p, headers=H(u["id"]))).text for p in
                 ("/api/health", "/api/auth/status", "/api/rbac/me", "/api/ti/status", "/api/notifications/status")]
    assert not any(sec in t for t in texts for sec in (SECRET, "SMTPSECRETVALUE", "VTSECRETVALUE", "WZSECRETVALUE"))


# ---------- three-role matrix over every route ----------
def _routes():
    app.openapi_schema = None
    out = []
    for raw, ops in app.openapi()["paths"].items():
        if raw.startswith("/api/"):
            for m in ops:
                out.append((m.upper(), re.sub(r"\{[^}]+\}", "1", raw), raw))
    assert len(out) > 80, "route discovery broken"
    return out


PUBLIC = {"/api/health", "/api/auth/status", "/api/auth/google", "/api/auth/google/signup", "/api/auth/logout"}
SELF = {"/api/auth/me", "/api/rbac/me", "/api/rbac/roles"}


@pytest.mark.anyio
async def test_unauthenticated_denied_everywhere():
    async with client() as c:
        for m, path, raw in _routes():
            if raw in PUBLIC:
                continue
            r = await c.request(m, path, json={})
            assert r.status_code == 401, (m, raw, r.status_code)


@pytest.mark.anyio
async def test_user_role_has_no_security_data_access():
    u = make_user("user")
    async with client() as c:
        for m, path, raw in _routes():
            if raw in PUBLIC or raw in SELF:
                continue
            r = await c.request(m, path, json={}, headers=H(u["id"]))
            assert r.status_code in (403, 422), (m, raw, r.status_code)  # 422 = body rejected before reaching data


@pytest.mark.anyio
async def test_vendor_cannot_reach_admin_routes_and_admin_not_vendor_routes():
    v, a = make_user("vendor"), make_user("admin")
    async with client() as c:
        for m, path, raw in _routes():
            if raw in PUBLIC or raw in SELF:
                continue
            if raw.startswith("/api/vendor/"):
                r = await c.request(m, path, json={}, headers=H(a["id"]))
                assert r.status_code in (403, 422), ("admin->vendor", m, raw, r.status_code)
            else:
                r = await c.request(m, path, json={}, headers=H(v["id"]))
                assert r.status_code in (403, 422), ("vendor->admin", m, raw, r.status_code)


def test_role_permission_sets_are_disjoint():
    assert ROLE_PERMISSIONS["user"] == frozenset()
    assert not (ROLE_PERMISSIONS["vendor"] & ROLE_PERMISSIONS["admin"])
    assert all(p.startswith("vendor:") for p in ROLE_PERMISSIONS["vendor"])


# ---------- vendor isolation (DB-backed views) ----------
def _seed_alert(agent):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as c:
        return c.execute("INSERT INTO detection_alerts (dedupe_key, rule_key, title, severity, agent_id, event_count, first_seen,"
                         " last_seen, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (f"k{agent}", "brute_force", f"alert on {agent}", "high", agent, 5, now, now, now, now)).lastrowid


def _agent_ids(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "agent_id" and isinstance(v, str):
                yield v
            else:
                yield from _agent_ids(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from _agent_ids(x)


@pytest.mark.anyio
async def test_vendor_isolation_on_detections():
    v1 = users.create("v1@test.local", "vendor")
    v2 = users.create("v2@test.local", "vendor")
    vendor_agents.assign(v1["id"], "001")
    vendor_agents.assign(v2["id"], "002")
    a1, a2 = _seed_alert("001"), _seed_alert("002")
    async with client() as c:
        r1 = await c.get("/api/vendor/detections/alerts", headers=H(v1["id"]))
        r2 = await c.get("/api/vendor/detections/alerts", headers=H(v2["id"]))
        assert r1.status_code == r2.status_code == 200
        assert set(_agent_ids(r1.json())) == {"001"} and set(_agent_ids(r2.json())) == {"002"}
        assert (await c.get(f"/api/vendor/detections/alerts/{a2}", headers=H(v1["id"]))).status_code == 404
        assert (await c.get(f"/api/vendor/detections/alerts/{a1}", headers=H(v1["id"]))).status_code == 200
        # forged agent filter cannot widen scope
        assert (await c.get("/api/vendor/alerts?agent_id=002", headers=H(v1["id"]))).status_code == 404
