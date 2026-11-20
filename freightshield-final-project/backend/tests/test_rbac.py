import httpx
import pytest

from app.core.roles import ROLE_LABELS, ROLE_PERMISSIONS
from app.main import app
from app.services import audit, users
from tests.helpers import auth_headers, make_user, token


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def H(uid):
    return {"Authorization": f"Bearer {token(uid)}"}


@pytest.mark.anyio
async def test_everything_but_health_and_login_is_protected():
    paths = ["/rbac/me", "/rbac/roles", "/users", "/users/1", "/audit/logs", "/ai/status",
             "/wazuh/manager/info", "/wazuh/manager/agents", "/wazuh/indexer/health", "/wazuh/indexer/alerts"]
    async with client() as c:
        for p in paths:
            assert (await c.get(f"/api{p}")).status_code == 401, p
        assert (await c.post("/api/users", json={"email": "a@b.co", "role": "user"})).status_code == 401
        assert (await c.patch("/api/users/1", json={"active": False})).status_code == 401
        assert (await c.delete("/api/users/1")).status_code == 401
        assert (await c.get("/api/health")).status_code == 200
        assert (await c.get("/api/auth/status")).status_code == 200


@pytest.mark.anyio
@pytest.mark.parametrize("role", ["user", "vendor"])
async def test_non_admin_cannot_manage_or_audit(role):
    h = auth_headers(role)
    async with client() as c:
        assert (await c.get("/api/users", headers=h)).status_code == 403
        assert (await c.post("/api/users", json={"email": "x@y.co", "role": "admin"}, headers=h)).status_code == 403
        assert (await c.patch("/api/users/1", json={"role": "admin"}, headers=h)).status_code == 403
        assert (await c.delete("/api/users/1", headers=h)).status_code == 403
        assert (await c.get("/api/audit/logs", headers=h)).status_code == 403
        assert (await c.get("/api/rbac/roles", headers=h)).status_code == 403
        assert (await c.get("/api/ai/status", headers=h)).status_code == 403
        me = (await c.get("/api/rbac/me", headers=h)).json()
    assert me["role"] == role and me["permissions"] == sorted(ROLE_PERMISSIONS[role])
    assert me["role_label"] == ROLE_LABELS[role]


@pytest.mark.anyio
async def test_me_and_roles_for_admin():
    async with client() as c:
        me = (await c.get("/api/rbac/me", headers=auth_headers())).json()
        roles = (await c.get("/api/rbac/roles", headers=auth_headers())).json()["roles"]
    assert me["role"] == "admin" and "users:write" in me["permissions"]
    assert set(roles) == {"admin", "user", "vendor"}
    assert roles["user"] == []
    assert {"vendor:agents", "vendor:alerts", "vendor:reports"}.issubset(roles["vendor"])


@pytest.mark.anyio
async def test_user_crud_and_validation():
    h = auth_headers()
    async with client() as c:
        r = await c.post("/api/users", json={"email": "Shop@Example.com", "role": "vendor"}, headers=h)
        assert r.status_code == 201 and r.json()["email"] == "shop@example.com" and r.json()["active"] is True
        uid = r.json()["id"]
        assert (await c.post("/api/users", json={"email": "shop@example.com", "role": "user"}, headers=h)).status_code == 409
        for bad in ({"email": "nope", "role": "user"}, {"email": "a@b.co", "role": "root"}, {"email": "a@b.co"}):
            assert (await c.post("/api/users", json=bad, headers=h)).status_code == 422
        assert (await c.get(f"/api/users/{uid}", headers=h)).json()["role"] == "vendor"
        assert (await c.get("/api/users/9999", headers=h)).status_code == 404
        r = await c.patch(f"/api/users/{uid}", json={"role": "user", "active": False}, headers=h)
        assert r.json()["role"] == "user" and r.json()["active"] is False
        assert (await c.patch(f"/api/users/{uid}", json={}, headers=h)).status_code == 422
        assert (await c.patch("/api/users/9999", json={"active": True}, headers=h)).status_code == 404
        d = (await c.get("/api/users?role=user&active=false", headers=h)).json()
        assert d["total"] == 1 and d["items"][0]["id"] == uid
        assert (await c.get("/api/users?limit=101", headers=h)).status_code == 422
        assert (await c.delete(f"/api/users/{uid}", headers=h)).status_code == 200
        assert (await c.delete(f"/api/users/{uid}", headers=h)).status_code == 404


@pytest.mark.anyio
async def test_pagination():
    h = auth_headers()
    for i in range(5):
        users.create(f"u{i}@x.co", "user")
    async with client() as c:
        d = (await c.get("/api/users?limit=2&page=2", headers=h)).json()
    assert d["total"] == 6 and len(d["items"]) == 2 and d["page"] == 2


@pytest.mark.anyio
async def test_admin_safety_guards():
    a = make_user("admin")
    h = H(a["id"])
    async with client() as c:
        assert (await c.patch(f"/api/users/{a['id']}", json={"role": "user"}, headers=h)).status_code == 409
        assert (await c.patch(f"/api/users/{a['id']}", json={"active": False}, headers=h)).status_code == 409
        assert (await c.delete(f"/api/users/{a['id']}", headers=h)).status_code == 409
        # last-admin guard: a second admin cannot strip the only other admin once alone
        b = users.create("b@x.co", "admin")
        assert (await c.patch(f"/api/users/{b['id']}", json={"role": "user"}, headers=h)).status_code == 200
        # b is no longer admin; a is the sole admin, and a no-op patch on self is allowed
        assert (await c.patch(f"/api/users/{a['id']}", json={"role": "admin"}, headers=h)).status_code == 200
    # last-admin guard directly (actor differs from target)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        users.update(a["id"], actor_id=b["id"], role="vendor")
    assert e.value.status_code == 409


@pytest.mark.anyio
async def test_role_change_and_disable_apply_immediately():
    admin = make_user("admin")
    u = users.create("buyer@x.co", "admin")  # second admin
    async with client() as c:
        assert (await c.get("/api/users", headers=H(u["id"]))).status_code == 200
        users.update(u["id"], admin["id"], role="user")
        assert (await c.get("/api/users", headers=H(u["id"]))).status_code == 403
        users.update(u["id"], admin["id"], active=False)
        assert (await c.get("/api/rbac/me", headers=H(u["id"]))).status_code == 403
        users.delete(u["id"], admin["id"])
        assert (await c.get("/api/rbac/me", headers=H(u["id"]))).status_code == 401


@pytest.mark.anyio
async def test_token_with_role_claim_cannot_escalate():
    import jwt, time
    from tests.helpers import SECRET
    u = make_user("user")
    from tests.helpers import claims
    t = jwt.encode({**claims(u["id"]), "role": "admin"}, SECRET, algorithm="HS256")
    async with client() as c:
        assert (await c.get("/api/users", headers={"Authorization": f"Bearer {t}"})).status_code == 403


@pytest.mark.anyio
async def test_bad_subjects_rejected():
    import jwt, time
    from tests.helpers import SECRET
    async with client() as c:
        for sub in ("abc", "999", ""):
            t = jwt.encode({"sub": sub, "exp": int(time.time()) + 60}, SECRET, algorithm="HS256")
            assert (await c.get("/api/rbac/me", headers={"Authorization": f"Bearer {t}"})).status_code == 401
        t = jwt.encode({"sub": "1"}, SECRET, algorithm="HS256")  # no exp
        assert (await c.get("/api/rbac/me", headers={"Authorization": f"Bearer {t}"})).status_code == 401


@pytest.mark.anyio
async def test_audit_trail(monkeypatch):
    from app.services.wazuh_indexer import wazuh_indexer

    async def hits(query, size=50):
        return {"hits": {"total": {"value": 0}, "hits": []}}
    monkeypatch.setattr(wazuh_indexer, "search_alerts", hits)
    h = auth_headers()
    async with client() as c:
        await c.get("/api/wazuh/indexer/alerts", headers=h)                         # audited access
        await c.get("/api/wazuh/indexer/alerts", headers=auth_headers("vendor"))    # audited denial
        r = await c.post("/api/users", json={"email": "n@x.co", "role": "user"}, headers=h)
        await c.patch(f"/api/users/{r.json()['id']}", json={"role": "vendor"}, headers=h)
        await c.delete(f"/api/users/{r.json()['id']}", headers=h)
        await c.patch(f"/api/users/{make_user('admin')['id']}", json={"active": False}, headers=h)  # denied self-change
        logs = (await c.get("/api/audit/logs?limit=100", headers=h)).json()
        denied = (await c.get("/api/audit/logs?outcome=denied", headers=h)).json()
        assert (await c.get("/api/audit/logs?outcome=bogus", headers=h)).status_code == 422
        assert (await c.get("/api/audit/logs?limit=0", headers=h)).status_code == 422
    actions = [(i["action"], i["outcome"]) for i in logs["items"]]
    for a in [("access", "success"), ("access_denied", "denied"), ("user_create", "success"),
              ("user_update", "success"), ("user_delete", "success"), ("user_update", "denied")]:
        assert a in actions
    assert all(i["outcome"] == "denied" for i in denied["items"]) and denied["total"] >= 2
    assert logs["items"][0]["id"] > logs["items"][-1]["id"]  # newest first
    assert "token" not in str(logs).lower() and "password" not in str(logs).lower()


def test_audit_is_filterable_and_paged():
    for i in range(5):
        audit.record({"id": 1, "email": "a@x.co"}, "x", f"t{i}")
    items, total = audit.list_logs(2, 2, action="x")
    assert total == 5 and len(items) == 2


def test_cli_bootstrap_admin():
    from app.cli import create_admin
    u = create_admin("Root@Example.com")
    assert u["role"] == "admin" and u["email"] == "root@example.com"
    # The last active administrator cannot be disabled. Add a second admin first.
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        users.update(u["id"], None, active=False)
    assert exc.value.status_code == 409
    second = create_admin("backup@example.com")
    users.update(u["id"], None, active=False)
    again = create_admin("root@example.com")   # re-activates, no duplicate
    assert again["id"] == u["id"] and again["active"] is True
    assert second["role"] == "admin"
    assert audit.list_logs(10, 0, action="bootstrap_admin")[1] == 3
