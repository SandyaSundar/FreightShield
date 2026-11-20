"""Integration + end-to-end (SIMULATED): fake Wazuh Indexer + fake feeds, real FastAPI app, real SQLite, real RBAC.
E2E flow: Wazuh alerts -> /ti/scan -> IOCs/enrichment/MITRE -> correlation -> vendor-scoped view -> SOC AI context -> audit.
Live feeds / live Wazuh are covered separately by scripts/verify_threat_intel.py."""
import httpx
import pytest

from app.core.config import get_settings
from app.main import app
from app.services import ai_agents, audit, ti_providers, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer
from tests.helpers import auth_headers, make_user
from tests.test_detection_engine import hit

BAD, OTHER = "45.33.32.156", "91.92.109.43"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def alerts():
    a = [hit(i, i * 10, "001", 5, ("syslog", "authentication_failed"), "5710", BAD) for i in range(4)]
    b = [hit(10 + i, 100 + i, "002", 5, ("syslog", "authentication_failed"), "5710", BAD, name="db-01") for i in range(2)]
    c = hit(20, 200, "002", 7, ("web", "attack"), "31103", OTHER, name="db-01")
    c["_source"]["syscheck"] = {"md5_after": MD5}
    return a + b + [c, hit(30, 300, "003", 3, srcip="10.0.0.5", name="priv")]


@pytest.fixture
def world(monkeypatch):
    calls = {"feeds": 0}

    async def search(q, size=50):
        d = alerts()
        return {"hits": {"total": {"value": len(d)}, "hits": d if q.get("from", 0) == 0 else []}}

    async def lookup(kind, value):
        calls["feeds"] += 1
        bad = value in (BAD, MD5)
        return {"virustotal": {"status": "ok", "summary": {"malicious": 9 if bad else 0, "suspicious": 0}},
                "abuseipdb": {"status": "ok", "summary": {"abuse_confidence": 88}} if kind == "ip" and bad else {"status": "not_found", "summary": {}},
                "otx": {"status": "timeout", "summary": {}}}
    monkeypatch.setattr(wazuh_indexer, "search_alerts", search)
    monkeypatch.setattr(ti_providers, "lookup", lookup)
    return calls


TI_ADMIN = ["/summary", "/status", "/iocs", "/iocs/1", "/correlations"]


@pytest.mark.anyio
async def test_unauthenticated_and_wrong_roles_are_refused():
    async with client() as c:
        for p in TI_ADMIN + ["/vendor/ti/iocs", "/vendor/ti/correlations"]:
            assert (await c.get(f"/api{'/ti' + p if p in TI_ADMIN else p}")).status_code == 401, p
        assert (await c.post("/api/ti/scan")).status_code == 401
        for role in ("user", "vendor"):
            h = auth_headers(role)
            for p in TI_ADMIN:
                assert (await c.get(f"/api/ti{p}", headers=h)).status_code == 403, (role, p)
            assert (await c.post("/api/ti/scan", headers=h)).status_code == 403
            assert (await c.post("/api/ti/lookup", json={"value": BAD}, headers=h)).status_code == 403
        for role in ("admin", "user"):
            assert (await c.get("/api/vendor/ti/iocs", headers=auth_headers(role))).status_code == 403


@pytest.mark.anyio
async def test_scan_extracts_enriches_scores_and_maps_mitre(world):
    h = auth_headers("admin")
    async with client() as c:
        r = await c.post("/api/ti/scan", headers=h)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["alerts_read"] == 8 and body["new_iocs"] == 3 and body["enriched"] == 3   # BAD, OTHER, MD5; private 10.0.0.5 ignored
        assert body["feed_problems"] == {"otx": {"timeout": 3}}
        items = (await c.get("/api/ti/iocs", headers=h)).json()["items"]
        bad = next(i for i in items if i["value"] == BAD)
        assert bad["score"] == 100 and bad["classification"] == "malicious" and bad["risk"] == "critical" and bad["sighting_count"] == 6
        assert "T1110" in {m["id"] for m in bad["mitre"]}
        assert all(i["value"] != "10.0.0.5" for i in items)
        d = (await c.get(f"/api/ti/iocs/{bad['id']}", headers=h)).json()
        assert {e["provider"]: e["status"] for e in d["enrichments"]} == {"virustotal": "ok", "abuseipdb": "ok", "otx": "timeout"}


@pytest.mark.anyio
async def test_rescan_dedupes_iocs_and_uses_cache(world):
    h = auth_headers("admin")
    async with client() as c:
        await c.post("/api/ti/scan", headers=h)
        first = world["feeds"]
        r = (await c.post("/api/ti/scan", headers=h)).json()
        assert r["new_iocs"] == 0 and r["new_sightings"] == 0 and r["enriched"] == 0 and world["feeds"] == first
        assert (await c.get("/api/ti/iocs", headers=h)).json()["total"] == 3
        forced = await c.post(f"/api/ti/iocs/1/refresh", headers=h)
        assert forced.status_code == 200 and world["feeds"] == first + 1


@pytest.mark.anyio
async def test_all_feeds_down_gives_unknown_not_a_fake_score(world, monkeypatch):
    async def down(kind, value):
        return {p: {"status": s, "summary": {}} for p, s in (("virustotal", "rate_limited"), ("abuseipdb", "unavailable"), ("otx", "timeout"))}
    monkeypatch.setattr(ti_providers, "lookup", down)
    async with client() as c:
        h = auth_headers("admin")
        assert (await c.post("/api/ti/scan", headers=h)).status_code == 200
        items = (await c.get("/api/ti/iocs", headers=h)).json()["items"]
        assert items and all(i["score"] is None and i["classification"] == "unknown" and i["enriched_at"] is None for i in items)  # retried next scan


@pytest.mark.anyio
async def test_wazuh_unavailable_returns_503_not_fake_data():
    async with client() as c:
        assert (await c.post("/api/ti/scan", headers=auth_headers("admin"))).status_code == 503


@pytest.mark.anyio
async def test_manual_lookup_validates_input(world):
    async with client() as c:
        h = auth_headers("admin")
        assert (await c.post("/api/ti/lookup", json={"value": "10.1.2.3"}, headers=h)).status_code == 422
        assert (await c.post("/api/ti/lookup", json={"value": "not an ioc"}, headers=h)).status_code == 422
        ok = await c.post("/api/ti/lookup", json={"value": "evil-example.com"}, headers=h)
        assert ok.status_code == 200 and ok.json()["type"] == "domain"


@pytest.mark.anyio
async def test_correlation_finds_multi_host_and_linked_iocs(world):
    async with client() as c:
        h = auth_headers("admin")
        await c.post("/api/ti/scan", headers=h)
        pats = (await c.get("/api/ti/correlations", headers=h)).json()["items"]
        assert {"multi_host", "linked_iocs"} <= {p["pattern"] for p in pats}
        assert next(p for p in pats if p["pattern"] == "multi_host")["agents"] == ["001", "002"]


@pytest.mark.anyio
async def test_vendor_isolation_scopes_iocs_counts_and_correlations(world):
    admin, v1, v2 = auth_headers("admin"), None, None
    vend = make_user("vendor")
    vendor_agents.assign(vend["id"], "001")          # vendor sees only agent 001
    async with client() as c:
        await c.post("/api/ti/scan", headers=admin)
        vh = auth_headers("vendor")
        items = (await c.get("/api/vendor/ti/iocs", headers=vh)).json()["items"]
        assert [i["value"] for i in items] == [BAD] and items[0]["sighting_count"] == 4 and items[0]["agents"] == ["001"]  # not 6 / not 002
        other = next(i for i in (await c.get("/api/ti/iocs", headers=admin)).json()["items"] if i["value"] == OTHER)
        assert (await c.get(f"/api/vendor/ti/iocs/{other['id']}", headers=vh)).status_code == 404
        d = (await c.get(f"/api/vendor/ti/iocs/{items[0]['id']}", headers=vh)).json()
        assert {s["agent_id"] for s in d["sightings"]} == {"001"}
        assert (await c.get("/api/vendor/ti/correlations", headers=vh)).json()["items"] == []   # multi-host needs agent 002, which is hidden
    vendor_agents.unassign(vend["id"], "001")
    async with client() as c:
        assert (await c.get("/api/vendor/ti/iocs", headers=auth_headers("vendor"))).json()["items"] == []


@pytest.mark.anyio
async def test_soc_ai_receives_threat_intel_context(world, monkeypatch):
    got = {}

    async def fake(req, rng):
        got["req"] = req
        return {"report": "ok", "tasks": [], "duration_ms": 1}
    monkeypatch.setattr(ai_agents, "run_soc", fake)
    async with client() as c:
        h = auth_headers("admin")
        await c.post("/api/ti/scan", headers=h)
        r = await c.post("/api/ai/soc/ask", json={"kind": "threat_analysis", "question": f"Is {BAD} dangerous?"}, headers=h)
        assert r.status_code == 200 and "Threat-intelligence context" in got["req"] and BAD in got["req"] and "class=malicious" in got["req"]
        await c.post("/api/ai/soc/ask", json={"kind": "chat", "question": "summarize", "include_threat_intel": False}, headers=h)
        assert "Threat-intelligence context" not in got["req"]


@pytest.mark.anyio
async def test_audit_trail_and_secrets_never_leak(world, monkeypatch):
    s = get_settings()
    for k in ("virustotal_api_key", "abuseipdb_api_key", "otx_api_key"):
        monkeypatch.setattr(s, k, "TOPSECRETKEY123")
    async with client() as c:
        h = auth_headers("admin")
        await c.post("/api/ti/scan", headers=h)
        await c.post("/api/ti/lookup", json={"value": BAD}, headers=h)
        await c.get("/api/ti/iocs", headers=auth_headers("vendor"))
        st = (await c.get("/api/ti/status", headers=h)).text
        assert "TOPSECRETKEY123" not in st and "TOPSECRETKEY123" not in (await c.get("/api/ti/iocs", headers=h)).text
        logs, _ = audit.list_logs(100, 0)
        actions = {(l["action"], l["outcome"]) for l in logs}
        assert ("ti_scan", "success") in actions and ("ti_lookup", "success") in actions and ("access_denied", "denied") in actions
        assert "TOPSECRETKEY123" not in str(logs)
