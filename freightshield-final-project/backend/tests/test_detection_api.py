"""HTTP-level detection tests. SIMULATED: the Wazuh Indexer is replaced by a fake returning synthetic hits.
Live behaviour is checked separately by scripts/verify_integration.py against a real Wazuh."""
import httpx
import pytest

from app.main import app
from app.services import audit, users, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer
from tests.helpers import auth_headers, make_user, token
from tests.test_detection_engine import fails, hit


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def H(uid):
    return {"Authorization": f"Bearer {token(uid)}"}


@pytest.fixture
def indexer(monkeypatch):
    docs = fails(6, "001") + fails(6, "002", "198.51.100.7") + [hit(90, 5, level=3)]
    queries = []

    async def search(query, size=50):
        queries.append(query)
        return {"hits": {"total": {"value": len(docs)}, "hits": docs}}

    monkeypatch.setattr(wazuh_indexer, "search_alerts", search)
    return queries


@pytest.mark.anyio
async def test_all_detection_routes_require_auth():
    async with client() as c:
        for p in ("/detections/summary", "/detections/alerts", "/detections/alerts/1", "/detections/incidents", "/detections/rules",
                  "/notifications", "/vendor/detections/alerts", "/vendor/detections/incidents"):
            assert (await c.get(f"/api{p}")).status_code == 401, p
        assert (await c.post("/api/detections/run")).status_code == 401
        assert (await c.patch("/api/detections/alerts/1", json={"status": "resolved"})).status_code == 401


@pytest.mark.anyio
@pytest.mark.parametrize("role", ["user", "vendor"])
async def test_non_admins_cannot_use_admin_detection_routes(role):
    h = auth_headers(role)
    async with client() as c:
        for p in ("/detections/summary", "/detections/alerts", "/detections/incidents", "/detections/rules", "/notifications"):
            assert (await c.get(f"/api{p}", headers=h)).status_code == 403, p
        assert (await c.post("/api/detections/run", headers=h)).status_code == 403
        assert (await c.patch("/api/detections/alerts/1", json={"status": "resolved"}, headers=h)).status_code == 403
        assert (await c.put("/api/detections/rules/auth_bruteforce", json={"threshold": 1}, headers=h)).status_code == 403


@pytest.mark.anyio
async def test_user_role_has_no_vendor_detection_access():
    async with client() as c:
        assert (await c.get("/api/vendor/detections/alerts", headers=auth_headers("user"))).status_code == 403
        assert (await c.get("/api/vendor/detections/alerts", headers=auth_headers("admin"))).status_code == 403


@pytest.mark.anyio
async def test_run_generates_alerts_without_duplicates_and_audits(indexer):
    h = auth_headers("admin")
    async with client() as c:
        r1 = (await c.post("/api/detections/run", headers=h)).json()
        r2 = (await c.post("/api/detections/run", headers=h)).json()
        al = (await c.get("/api/detections/alerts", headers=h)).json()
        inc = (await c.get("/api/detections/incidents", headers=h)).json()
        n = (await c.get("/api/notifications", headers=h)).json()
        s = (await c.get("/api/detections/summary", headers=h)).json()
    assert len(r1["created"]) == 2 and r2["created"] == [] and r2["updated"] == []
    assert al["total"] == 2 and inc["total"] == 2 and n["total"] == 2 and s["unread_notifications"] == 2
    assert indexer[0]["query"]["range"]["timestamp"]["gte"].startswith("now-")
    assert {i["action"] for i in audit.list_logs(50, 0)[0]} >= {"detection_scan", "alert_create"}


@pytest.mark.anyio
async def test_run_reports_wazuh_unavailable_instead_of_faking():
    async with client() as c:  # conftest blanks the Wazuh settings -> not configured
        r = await c.post("/api/detections/run", headers=auth_headers("admin"))
    assert r.status_code == 503 and r.json()["error"] == "not_configured"
    assert (await _count_alerts()) == 0


async def _count_alerts():
    from app.services import detection
    return detection.list_alerts(10, 0)[1]


@pytest.mark.anyio
async def test_status_changes_are_validated_and_audited(indexer):
    h = auth_headers("admin")
    async with client() as c:
        await c.post("/api/detections/run", headers=h)
        aid = (await c.get("/api/detections/alerts", headers=h)).json()["items"][0]["id"]
        ok = await c.patch(f"/api/detections/alerts/{aid}", json={"status": "investigating"}, headers=h)
        bad = await c.patch(f"/api/detections/alerts/{aid}", json={"status": "new"}, headers=h)
        gone = await c.patch("/api/detections/alerts/9999", json={"status": "resolved"}, headers=h)
        filt = (await c.get("/api/detections/alerts?status=investigating&severity=high", headers=h)).json()
        badq = await c.get("/api/detections/alerts?status=bogus", headers=h)
    assert ok.status_code == 200 and ok.json()["status"] == "investigating"
    assert (bad.status_code, gone.status_code, badq.status_code) == (422, 404, 422) and filt["total"] == 1
    assert "alert_status" in {i["action"] for i in audit.list_logs(50, 0)[0]}


@pytest.mark.anyio
async def test_rule_configuration_bounds_and_audit():
    h = auth_headers("admin")
    async with client() as c:
        ok = await c.put("/api/detections/rules/auth_bruteforce", json={"threshold": 3, "severity": "critical"}, headers=h)
        assert ok.status_code == 200 and ok.json()["threshold"] == 3 and ok.json()["severity"] == "critical"
        assert (await c.put("/api/detections/rules/auth_bruteforce", json={"threshold": 0}, headers=h)).status_code == 422
        assert (await c.put("/api/detections/rules/auth_bruteforce", json={"severity": "urgent"}, headers=h)).status_code == 422
        assert (await c.put("/api/detections/rules/auth_bruteforce", json={}, headers=h)).status_code == 422
        assert (await c.put("/api/detections/rules/nope", json={"threshold": 3}, headers=h)).status_code == 404
        rules = (await c.get("/api/detections/rules", headers=h)).json()["items"]
    assert {r["rule_key"] for r in rules} == {"auth_bruteforce", "high_level_event", "fim_burst"}
    assert "rule_update" in {i["action"] for i in audit.list_logs(50, 0)[0]}


@pytest.mark.anyio
async def test_vendor_sees_only_own_detections(indexer):
    v1, v2 = make_user("vendor"), users.create("vendor2@test.local", "vendor")
    vendor_agents.assign(v1["id"], "001"); vendor_agents.assign(v2["id"], "002")
    async with client() as c:
        await c.post("/api/detections/run", headers=auth_headers("admin"))
        a1 = (await c.get("/api/vendor/detections/alerts", headers=H(v1["id"]))).json()
        i1 = (await c.get("/api/vendor/detections/incidents", headers=H(v1["id"]))).json()
        a2 = (await c.get("/api/vendor/detections/alerts", headers=H(v2["id"]))).json()
        own = await c.get(f"/api/vendor/detections/alerts/{a1['items'][0]['id']}", headers=H(v1["id"]))
        foreign = await c.get(f"/api/vendor/detections/alerts/{a2['items'][0]['id']}", headers=H(v1["id"]))
        none = users.create("v3@test.local", "vendor")
        empty = (await c.get("/api/vendor/detections/alerts", headers=H(none["id"]))).json()
        patch = await c.patch(f"/api/detections/alerts/{a1['items'][0]['id']}", json={"status": "resolved"}, headers=H(v1["id"]))
    assert a1["total"] == 1 and {i["agent_id"] for i in a1["items"]} == {"001"} and i1["total"] == 1
    assert a2["total"] == 1 and a2["items"][0]["agent_id"] == "002"
    assert own.status_code == 200 and foreign.status_code == 404 and empty["total"] == 0 and patch.status_code == 403


@pytest.mark.anyio
async def test_notifications_mark_read(indexer):
    h = auth_headers("admin")
    async with client() as c:
        await c.post("/api/detections/run", headers=h)
        nid = (await c.get("/api/notifications?unread=true", headers=h)).json()["items"][0]["id"]
        assert (await c.post(f"/api/notifications/{nid}/read", headers=h)).status_code == 200
        assert (await c.post("/api/notifications/9999/read", headers=h)).status_code == 404
        assert (await c.get("/api/notifications?unread=true", headers=h)).json()["total"] == 1
