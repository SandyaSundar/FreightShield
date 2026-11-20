"""Vendor data isolation + admin assignment. Wazuh transport is faked here; this tests scoping, not connectivity."""
import httpx
import pytest

from app.main import app
from app.services import audit, users, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer
from app.services.wazuh_manager import wazuh_manager
from tests.helpers import auth_headers, make_user, token


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def H(uid):
    return {"Authorization": f"Bearer {token(uid)}"}


@pytest.fixture
def vendors():
    v1, v2 = make_user("vendor"), users.create("vendor2@test.local", "vendor")
    vendor_agents.assign(v1["id"], "001")
    vendor_agents.assign(v2["id"], "002")
    return v1, v2


@pytest.fixture
def wazuh(monkeypatch):
    calls = {"mgr": [], "idx": []}

    async def mgr(method, path, params=None):
        calls["mgr"].append(params)
        return {"data": {"affected_items": [{"id": i} for i in params["agents_list"].split(",")]}}

    async def idx(query, size=50):
        calls["idx"].append(query)
        return {"hits": {"total": {"value": 1}, "hits": [{"_id": "a", "_source": {"agent": {"id": "001"}}}]}}

    monkeypatch.setattr(wazuh_manager, "request", mgr)
    monkeypatch.setattr(wazuh_indexer, "search_alerts", idx)
    return calls


@pytest.mark.anyio
async def test_vendor_sees_only_own_agents_and_alerts(vendors, wazuh):
    v1, v2 = vendors
    async with client() as c:
        a1 = (await c.get("/api/vendor/agents", headers=H(v1["id"]))).json()
        a2 = (await c.get("/api/vendor/agents", headers=H(v2["id"]))).json()
        r = await c.get("/api/vendor/alerts?min_level=5", headers=H(v1["id"]))
        other = await c.get("/api/vendor/alerts?agent_id=002", headers=H(v1["id"]))
        own = await c.get("/api/vendor/alerts?agent_id=001", headers=H(v1["id"]))
        bad = await c.get("/api/vendor/alerts?agent_id=../x", headers=H(v1["id"]))
    assert [i["id"] for i in a1["data"]["affected_items"]] == ["001"]
    assert [i["id"] for i in a2["data"]["affected_items"]] == ["002"]
    assert r.status_code == 200 and own.status_code == 200
    assert wazuh["idx"][0]["query"] == {"bool": {"filter": [{"terms": {"agent.id": ["001"]}}, {"range": {"rule.level": {"gte": 5}}}]}}
    assert wazuh["idx"][1]["query"] == {"bool": {"filter": [{"terms": {"agent.id": ["001"]}}]}}
    assert other.status_code == 404 and bad.status_code == 422 and len(wazuh["idx"]) == 2


@pytest.mark.anyio
async def test_vendor_without_assignments_never_hits_wazuh(wazuh):
    v = make_user("vendor")
    async with client() as c:
        a = await c.get("/api/vendor/agents", headers=H(v["id"]))
        al = await c.get("/api/vendor/alerts", headers=H(v["id"]))
    assert a.json()["data"]["affected_items"] == [] and al.json()["hits"]["hits"] == []
    assert wazuh["mgr"] == [] and wazuh["idx"] == []


@pytest.mark.anyio
async def test_role_boundaries_for_vendor_endpoints():
    v, u, a = make_user("vendor"), make_user("user"), make_user("admin")
    async with client() as c:
        for who in (u, a):  # consumers and admins have no vendor self-service scope
            assert (await c.get("/api/vendor/agents", headers=H(who["id"]))).status_code == 403
            assert (await c.get("/api/vendor/alerts", headers=H(who["id"]))).status_code == 403
        for p in ("/wazuh/manager/agents", "/wazuh/indexer/alerts", f"/vendors/{v['id']}/agents", "/users"):
            assert (await c.get(f"/api{p}", headers=H(v["id"]))).status_code == 403, p
            assert (await c.get(f"/api{p}", headers=H(u["id"]))).status_code == 403, p
        assert (await c.get("/api/vendor/agents")).status_code == 401
    assert audit.list_logs(50, 0, action="access_denied")[1] >= 6


@pytest.mark.anyio
async def test_admin_assigns_and_unassigns_with_audit(wazuh):
    v, u = make_user("vendor"), make_user("user")
    h = auth_headers("admin")
    async with client() as c:
        assert (await c.put(f"/api/vendors/{v['id']}/agents/007", headers=h)).json()["agent_ids"] == ["007"]
        assert (await c.put(f"/api/vendors/{v['id']}/agents/007", headers=h)).json()["agent_ids"] == ["007"]  # idempotent
        assert (await c.put(f"/api/vendors/{v['id']}/agents/abc", headers=h)).status_code == 422
        assert (await c.put(f"/api/vendors/{u['id']}/agents/007", headers=h)).status_code == 404  # not a vendor
        assert (await c.get(f"/api/vendors/{v['id']}/agents", headers=h)).json()["agent_ids"] == ["007"]
        assert (await c.delete(f"/api/vendors/{v['id']}/agents/007", headers=h)).json()["agent_ids"] == []
        assert (await c.delete(f"/api/vendors/{v['id']}/agents/007", headers=h)).status_code == 404
    acts = {i["action"] for i in audit.list_logs(50, 0)[0]}
    assert {"vendor_agent_assign", "vendor_agent_unassign"} <= acts


@pytest.mark.anyio
async def test_changing_role_away_from_vendor_clears_scope(vendors):
    v1, _ = vendors
    async with client() as c:
        r = await c.patch(f"/api/users/{v1['id']}", json={"role": "user"}, headers=auth_headers("admin"))
    assert r.status_code == 200 and vendor_agents.agent_ids(v1["id"]) == []


def test_deleting_vendor_cascades_assignments(vendors):
    v1, v2 = vendors
    users.delete(v1["id"], None)
    assert vendor_agents.agent_ids(v1["id"]) == [] and vendor_agents.agent_ids(v2["id"]) == ["002"]
