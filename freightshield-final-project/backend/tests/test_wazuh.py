"""Wazuh tests use mocked services/transports only; no real Wazuh host is contacted."""
import httpx
import pytest

from app.core.errors import UpstreamError
from app.main import app
from app.services import wazuh_indexer as idx_mod
from app.services.wazuh_indexer import wazuh_indexer
from app.services.wazuh_manager import wazuh_manager
from tests.helpers import auth_headers, make_user, token


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
def fake_hits(monkeypatch):
    calls = []

    async def fake_search(query, size=50):
        calls.append((query, size))
        return {"hits": {"total": {"value": 120}, "hits": [
            {"_id": "a1", "_source": {"rule": {"level": 7}, "timestamp": "t1"}},
            {"_id": "a2", "_source": {"rule": {"level": 3}, "timestamp": "t2"}}]}}
    monkeypatch.setattr(wazuh_indexer, "search_alerts", fake_search)
    return calls


@pytest.mark.anyio
async def test_alerts_requires_auth():
    async with client() as c:
        assert (await c.get("/api/wazuh/indexer/alerts")).status_code == 401
        assert (await c.get("/api/wazuh/manager/agents")).status_code == 401
        r = await c.get("/api/wazuh/indexer/alerts", headers={"Authorization": "Bearer junk"})
        assert r.status_code == 401
        expired = token(make_user()["id"], exp_in=-10)
        r = await c.get("/api/wazuh/indexer/alerts", headers={"Authorization": f"Bearer {expired}"})
        assert r.status_code == 401
        forged = token(make_user()["id"], secret="x" * 40)
        r = await c.get("/api/wazuh/indexer/alerts", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401


@pytest.mark.anyio
async def test_rbac_non_admin_forbidden():
    async with client() as c:
        for role in ("user", "vendor"):
            for path in ("/indexer/alerts", "/manager/agents", "/manager/info", "/indexer/health"):
                assert (await c.get(f"/api/wazuh{path}", headers=auth_headers(role))).status_code == 403


@pytest.mark.anyio
async def test_auth_fails_closed_without_secret(monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "auth_jwt_secret", "")
    async with client() as c:
        r = await c.get("/api/wazuh/indexer/alerts", headers=auth_headers())
        assert r.status_code == 503


@pytest.mark.anyio
async def test_cookie_session_accepted(fake_hits):
    async with client() as c:
        c.cookies.set("fs_session", token(make_user()["id"]))
        assert (await c.get("/api/wazuh/indexer/alerts")).status_code == 200


@pytest.mark.anyio
async def test_alerts_pagination(fake_hits):
    async with client() as c:
        r = await c.get("/api/wazuh/indexer/alerts?limit=2&page=3&min_level=5", headers=auth_headers())
    assert r.status_code == 200
    d = r.json()
    assert d["hits"]["total"]["value"] == 120
    assert d["pagination"] == {"page": 3, "limit": 2, "count": 2, "has_more": True}
    first = d["hits"]["hits"][0]
    assert first["_id"] == "a1" and first["_source"]["rule"]["level"] == 7
    q, size = fake_hits[0]
    assert size == 2 and q["from"] == 4
    assert q["query"] == {"range": {"rule.level": {"gte": 5}}}
    assert q["sort"] == [{"timestamp": {"order": "desc"}}]


@pytest.mark.anyio
@pytest.mark.parametrize("qs", ["limit=0", "limit=101", "limit=abc", "page=0", "min_level=16", "min_level=-1"])
async def test_alerts_validation(qs, fake_hits):
    async with client() as c:
        r = await c.get(f"/api/wazuh/indexer/alerts?{qs}", headers=auth_headers())
    assert r.status_code == 422
    assert fake_hits == []


@pytest.mark.anyio
async def test_alerts_window_limit(fake_hits):
    async with client() as c:
        r = await c.get("/api/wazuh/indexer/alerts?limit=100&page=101", headers=auth_headers())
    assert r.status_code == 422


@pytest.mark.anyio
async def test_empty_result_is_not_fabricated(monkeypatch):
    async def empty(query, size=50):
        return {"hits": {"total": {"value": 0}, "hits": []}}
    monkeypatch.setattr(wazuh_indexer, "search_alerts", empty)
    async with client() as c:
        d = (await c.get("/api/wazuh/indexer/alerts", headers=auth_headers())).json()
    assert d["hits"]["hits"] == [] and d["hits"]["total"]["value"] == 0 and d["pagination"]["has_more"] is False


@pytest.mark.anyio
async def test_upstream_error_propagates(monkeypatch):
    async def boom(query, size=50):
        raise UpstreamError("wazuh_indexer", "Cannot reach Wazuh Indexer (ConnectError).", 503)
    monkeypatch.setattr(wazuh_indexer, "search_alerts", boom)
    async with client() as c:
        r = await c.get("/api/wazuh/indexer/alerts", headers=auth_headers())
    assert r.status_code == 503 and r.json()["error"] == "upstream_error"
    assert "192.168" not in r.text


@pytest.mark.anyio
async def test_agents_preserved_and_protected(monkeypatch):
    seen = {}

    async def agents(status=None, limit=500, offset=0):
        seen.update(status=status, limit=limit, offset=offset)
        return {"data": {"affected_items": [{"id": "000", "status": status or "active"}]}}
    monkeypatch.setattr(wazuh_manager, "list_agents", agents)
    async with client() as c:
        r = await c.get("/api/wazuh/manager/agents?status=active", headers=auth_headers())
        bad = await c.get("/api/wazuh/manager/agents?status=bogus", headers=auth_headers())
        bad2 = await c.get("/api/wazuh/manager/agents?limit=501", headers=auth_headers())
    assert r.status_code == 200 and r.json()["data"]["affected_items"][0]["status"] == "active"
    assert seen == {"status": "active", "limit": 500, "offset": 0}
    assert bad.status_code == 422 and bad2.status_code == 422


def _mgr_configure(monkeypatch):
    s = wazuh_manager.s
    monkeypatch.setattr(s, "wazuh_manager_url", "https://192.168.1.100:55000")
    monkeypatch.setattr(s, "wazuh_manager_user", "u")
    monkeypatch.setattr(s, "wazuh_manager_password", "p")
    monkeypatch.setattr(wazuh_manager, "_token", None)


def _mgr_transport(monkeypatch, handler):
    from app.services import wazuh_manager as mod
    real = httpx.AsyncClient
    monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.anyio
async def test_manager_real_flow_auth_then_agents(monkeypatch):
    _mgr_configure(monkeypatch)
    calls = []

    def h(request):
        calls.append(request.url.path)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="jwt-token")
        assert request.headers["authorization"] == "Bearer jwt-token"
        assert request.url.params["limit"] == "500"
        return httpx.Response(200, json={"data": {"affected_items": [{"id": "001", "name": "a", "status": "active"}]}})
    _mgr_transport(monkeypatch, h)
    d = await wazuh_manager.list_agents("active")
    assert d["data"]["affected_items"][0]["id"] == "001"
    assert calls == ["/security/user/authenticate", "/agents"]


@pytest.mark.anyio
@pytest.mark.parametrize("exc,status,needle", [
    (httpx.ConnectError("refused"), 503, "Cannot reach"),
    (httpx.ConnectTimeout("t"), 504, "timed out"),
    (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"), 502, "TLS verification"),
])
async def test_manager_connection_errors(monkeypatch, exc, status, needle):
    _mgr_configure(monkeypatch)

    def h(request):
        raise exc
    _mgr_transport(monkeypatch, h)
    with pytest.raises(UpstreamError) as e:
        await wazuh_manager.list_agents()
    assert e.value.status_code == status and needle in e.value.detail


@pytest.mark.anyio
async def test_manager_bad_credentials(monkeypatch):
    _mgr_configure(monkeypatch)
    _mgr_transport(monkeypatch, lambda r: httpx.Response(401, json={}))
    with pytest.raises(UpstreamError) as e:
        await wazuh_manager.list_agents()
    assert "credentials" in e.value.detail


def _configure(monkeypatch):
    s = wazuh_indexer.s
    monkeypatch.setattr(s, "wazuh_indexer_url", "https://192.168.1.100:9200")
    monkeypatch.setattr(s, "wazuh_indexer_user", "u")
    monkeypatch.setattr(s, "wazuh_indexer_password", "p")


def _patch_transport(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(idx_mod.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.anyio
@pytest.mark.parametrize("exc,status,needle", [
    (httpx.ConnectError("refused"), 503, "Cannot reach"),
    (httpx.ConnectTimeout("t"), 504, "timed out"),
    (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self signed"), 502, "TLS verification"),
])
async def test_indexer_connection_errors(monkeypatch, exc, status, needle):
    _configure(monkeypatch)

    def h(request):
        raise exc
    _patch_transport(monkeypatch, h)
    with pytest.raises(UpstreamError) as e:
        await wazuh_indexer.get_alerts(10, 0)
    assert e.value.status_code == status and needle in e.value.detail


@pytest.mark.anyio
async def test_indexer_auth_error_mapped(monkeypatch):
    _configure(monkeypatch)
    _patch_transport(monkeypatch, lambda r: httpx.Response(401, json={}))
    with pytest.raises(UpstreamError) as e:
        await wazuh_indexer.get_alerts(10, 0)
    assert "credentials" in e.value.detail and e.value.status_code == 502


@pytest.mark.anyio
async def test_indexer_parses_real_response(monkeypatch):
    _configure(monkeypatch)
    body = {"hits": {"total": {"value": 1}, "hits": [{"_id": "z", "_source": {"agent": {"name": "srv"}}}]}}
    _patch_transport(monkeypatch, lambda r: httpx.Response(200, json=body))
    r = await wazuh_indexer.get_alerts(10, 0)
    assert r == {"total": 1, "hits": [{"_id": "z", "_source": {"agent": {"name": "srv"}}}]}
