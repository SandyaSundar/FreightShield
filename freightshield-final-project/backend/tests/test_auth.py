"""Google sign-in + session JWT. Google's key fetch is replaced by a local RSA key to test OUR verification logic;
this proves nothing about live Google connectivity (see scripts/verify_integration.py for that)."""
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app.core.config import get_settings
from app.core.roles import ROLES
from app.main import app
from app.services import audit, google_auth, users
from tests.helpers import SECRET, make_user

CID = "test-client.apps.googleusercontent.com"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def gtoken(**over):
    c = {"iss": "https://accounts.google.com", "aud": CID, "sub": "123", "email": "vendor@test.local",
         "email_verified": True, "exp": int(time.time()) + 300, **over}
    return jwt.encode({k: v for k, v in c.items() if v is not None}, KEY, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def google(monkeypatch):
    monkeypatch.setattr(get_settings(), "google_client_id", CID)
    monkeypatch.setattr(google_auth, "_jwks", SimpleNamespace(
        get_signing_key_from_jwt=lambda t: SimpleNamespace(key=KEY.public_key())))


def test_exactly_three_roles_and_db_rejects_others():
    assert ROLES == ("admin", "user", "vendor")
    with pytest.raises(HTTPException) as e:
        users.create("x@test.local", "analyst")
    assert e.value.status_code == 422
    import sqlite3
    from app.core.db import connect
    with pytest.raises(sqlite3.IntegrityError), connect() as c:
        c.execute("INSERT INTO users (email, role, active, created_at) VALUES ('a@b.co','analyst',1,'x')")


@pytest.mark.parametrize("over", [{"aud": "other"}, {"iss": "https://evil.example"}, {"email_verified": False},
                                  {"exp": int(time.time()) - 600}, {"email": None}])
def test_verify_id_token_rejects_bad_tokens(google, over):
    with pytest.raises(HTTPException) as e:
        google_auth.verify_id_token(gtoken(**over))
    assert e.value.status_code == 401


def test_verify_id_token_accepts_valid(google):
    assert google_auth.verify_id_token(gtoken())["email"] == "vendor@test.local"


@pytest.mark.anyio
async def test_login_issues_httponly_session_and_me_works(google):
    v = make_user("vendor")
    async with client() as c:
        r = await c.post("/api/auth/google", json={"credential": gtoken()})
        assert r.status_code == 200 and r.json()["role"] == "vendor" and r.json()["role_label"] == "Vendor"
        sc = r.headers["set-cookie"]
        assert sc.startswith("fs_session=") and "HttpOnly" in sc
        cookie = sc.split(";")[0]
        me = await c.get("/api/auth/me", headers={"Cookie": cookie})
        assert me.status_code == 200 and me.json()["id"] == v["id"]
        claims = jwt.decode(cookie.split("=", 1)[1], SECRET, algorithms=["HS256"], audience="freightshield-api")
        assert claims["sub"] == str(v["id"]) and "role" not in claims  # role is never trusted from the token
        out = await c.post("/api/auth/logout", headers={"Cookie": cookie})
        assert out.status_code == 200 and "fs_session=" in out.headers["set-cookie"]
    acts = [(i["action"], i["outcome"]) for i in audit.list_logs(50, 0)[0]]
    assert ("login", "success") in acts and ("logout", "success") in acts


@pytest.mark.anyio
async def test_login_denied_cases_are_audited(google):
    users.create("off@test.local", "user")
    users.update(users.get_by_email("off@test.local")["id"], None, None, False)
    async with client() as c:
        unreg = await c.post("/api/auth/google", json={"credential": gtoken(email="nobody@test.local")})
        off = await c.post("/api/auth/google", json={"credential": gtoken(email="off@test.local")})
        bad = await c.post("/api/auth/google", json={"credential": gtoken(aud="other")})
        short = await c.post("/api/auth/google", json={"credential": "x"})
    assert (unreg.status_code, off.status_code, bad.status_code, short.status_code) == (403, 403, 401, 422)
    assert "set-cookie" not in unreg.headers
    assert audit.list_logs(50, 0, action="login", outcome="denied")[1] == 3


@pytest.mark.anyio
async def test_login_fails_closed_when_not_configured(monkeypatch):
    s = get_settings()
    async with client() as c:
        monkeypatch.setattr(s, "google_client_id", "")
        assert (await c.post("/api/auth/google", json={"credential": "x" * 30})).status_code == 503
        monkeypatch.setattr(s, "auth_jwt_secret", "short")
        assert (await c.post("/api/auth/google", json={"credential": "x" * 30})).status_code == 503


@pytest.mark.anyio
async def test_demoted_or_disabled_user_loses_access_immediately(google):
    u = make_user("user")
    async with client() as c:
        cookie = (await c.post("/api/auth/google", json={"credential": gtoken(email="user@test.local")})).headers["set-cookie"].split(";")[0]
        users.update(u["id"], None, "vendor", None)
        assert (await c.get("/api/auth/me", headers={"Cookie": cookie})).json()["role"] == "vendor"
        users.update(u["id"], None, None, False)
        assert (await c.get("/api/auth/me", headers={"Cookie": cookie})).status_code == 403


# ---- Google self-sign-up (POST /api/auth/google/signup) ----

@pytest.mark.anyio
async def test_signup_creates_least_privileged_user_and_session(google):
    async with client() as c:
        r = await c.post("/api/auth/google/signup", json={"credential": gtoken(email="New.Person@test.local")})
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == "user" and body["permissions"] == [] and body["email"] == "new.person@test.local"
        sc = r.headers["set-cookie"]
        assert sc.startswith("fs_session=") and "HttpOnly" in sc
        cookie = sc.split(";")[0]
        assert (await c.get("/api/auth/me", headers={"Cookie": cookie})).json()["role"] == "user"
        assert (await c.post("/api/auth/logout", headers={"Cookie": cookie})).status_code == 200
        assert (await c.get("/api/auth/me", headers={"Cookie": cookie})).status_code == 401  # logout revokes server-side
    assert users.get_by_email("new.person@test.local")["role"] == "user"
    assert audit.list_logs(50, 0, action="signup", outcome="success")[1] == 1


@pytest.mark.anyio
@pytest.mark.parametrize("extra", [{"role": "admin"}, {"role": "vendor"}, {"email": "admin@evil.test"}, {"user_id": 1}])
async def test_signup_ignores_client_supplied_role_or_identity(google, extra):
    async with client() as c:
        r = await c.post("/api/auth/google/signup", json={"credential": gtoken(email="sneaky@test.local"), **extra})
    assert r.status_code == 200 and r.json()["role"] == "user" and r.json()["email"] == "sneaky@test.local"
    assert users.get_by_email("admin@evil.test") is None


@pytest.mark.anyio
async def test_signup_never_touches_existing_accounts(google):
    make_user("admin")
    async with client() as c:
        r = await c.post("/api/auth/google/signup", json={"credential": gtoken(email="admin@test.local")})
    assert r.status_code == 409 and "set-cookie" not in r.headers
    assert users.get_by_email("admin@test.local")["role"] == "admin"
    assert audit.list_logs(50, 0, action="signup", outcome="denied")[1] == 1


@pytest.mark.anyio
@pytest.mark.parametrize("over", [{"aud": "other"}, {"iss": "https://evil.example"}, {"email_verified": False},
                                  {"exp": int(time.time()) - 600}, {"email": None}])
async def test_signup_rejects_invalid_google_credentials(google, over):
    async with client() as c:
        r = await c.post("/api/auth/google/signup", json={"credential": gtoken(**over)})
        short = await c.post("/api/auth/google/signup", json={"credential": "x"})
        forged = await c.post("/api/auth/google/signup", json={"credential": "a.b.c" + "x" * 30})
    assert r.status_code == 401 and short.status_code == 422 and forged.status_code == 401
    assert "set-cookie" not in r.headers and users.get_by_email("vendor@test.local") is None


@pytest.mark.anyio
async def test_signup_fails_closed_and_can_be_disabled(google, monkeypatch):
    s = get_settings()
    async with client() as c:
        monkeypatch.setattr(s, "self_signup_enabled", False)
        assert (await c.post("/api/auth/google/signup", json={"credential": gtoken()})).status_code == 403
        assert set((await c.get("/api/auth/status")).json()) == {"google_configured", "jwt_configured"}  # contract unchanged
        monkeypatch.setattr(s, "self_signup_enabled", True)
        monkeypatch.setattr(s, "google_client_id", "")
        assert (await c.post("/api/auth/google/signup", json={"credential": "x" * 30})).status_code == 503
        monkeypatch.setattr(s, "auth_jwt_secret", "short")
        assert (await c.post("/api/auth/google/signup", json={"credential": "x" * 30})).status_code == 503


@pytest.mark.anyio
async def test_signup_does_not_change_sign_in_rules_and_user_stays_unprivileged(google):
    async with client() as c:
        # /auth/google still refuses unregistered emails (sign-in must not auto-create accounts)
        assert (await c.post("/api/auth/google", json={"credential": gtoken(email="fresh@test.local")})).status_code == 403
        assert users.get_by_email("fresh@test.local") is None
        r = await c.post("/api/auth/google/signup", json={"credential": gtoken(email="fresh@test.local")})
        cookie = r.headers["set-cookie"].split(";")[0]
        # standard user gets no admin/vendor data and cannot reach privileged routes
        for path in ("/api/users", "/api/audit", "/api/wazuh/agents", "/api/vendor/agents"):
            assert (await c.get(path, headers={"Cookie": cookie})).status_code == 403, path
        # sign-in then works for the new account
        assert (await c.post("/api/auth/google", json={"credential": gtoken(email="fresh@test.local")})).status_code == 200


@pytest.mark.anyio
async def test_signup_csrf_exempt_only_for_credential_endpoint_other_posts_still_need_csrf(google):
    async with client() as c:
        r = await c.post("/api/auth/google/signup", json={"credential": gtoken(email="csrf@test.local")})
        cookie = r.headers["set-cookie"].split(";")[0]
        # a stale session cookie must not block signup/sign-in (credential endpoints), but state-changing calls need the token
        assert (await c.post("/api/auth/google", json={"credential": gtoken(email="csrf@test.local")}, headers={"Cookie": cookie})).status_code == 200
        bad = await c.post("/api/users", json={"email": "z@test.local", "role": "admin"}, headers={"Cookie": cookie})
        assert bad.status_code == 403
