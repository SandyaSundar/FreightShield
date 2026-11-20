"""Phase 8 HTTP tests: real FastAPI app, real SQLite, real RBAC. SIMULATED: the Wazuh Indexer is a fake returning synthetic hits and
SMTP is a recording fake. They prove API behaviour, permissions, vendor isolation and auditing - not live connectivity."""
import json
import smtplib

import httpx
import pytest

from app.core.config import get_settings
from app.main import app
from app.services import audit, ir, notifications as nt, users, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer
from tests.helpers import auth_headers, make_user, token
from tests.test_detection_engine import fails, hit
from tests.test_notifications_service import FakeSMTP, SECRET, PUBLIC


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def H(uid):
    return {"Authorization": f"Bearer {token(uid)}"}


@pytest.fixture
def indexer(monkeypatch):
    docs = fails(6, "001", PUBLIC) + fails(6, "002", "198.51.100.7")

    async def search(query, size=50):
        return {"hits": {"total": {"value": len(docs)}, "hits": docs}}

    monkeypatch.setattr(wazuh_indexer, "search_alerts", search)


@pytest.fixture
def smtp(monkeypatch):
    s = get_settings()
    for k, v in (("notify_email_enabled", True), ("smtp_host", "smtp.test"), ("smtp_from", "soc@freightshield.test"), ("smtp_user", "mailer"),
                 ("smtp_password", SECRET), ("smtp_starttls", True), ("smtp_ssl", False)):
        monkeypatch.setattr(s, k, v)
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    FakeSMTP.sent, FakeSMTP.calls, FakeSMTP.fail_for = [], [], set()
    return FakeSMTP


ADMIN_ROUTES = ("/notifications", "/notifications/summary", "/notifications/status", "/notifications/rules", "/notifications/deliveries",
                "/notifications/preferences", "/notifications/1")
VENDOR_ROUTES = ("/vendor/notifications", "/vendor/notifications/summary", "/vendor/notifications/preferences", "/vendor/notifications/1")


@pytest.mark.anyio
async def test_every_notification_route_requires_authentication():
    async with client() as c:
        for p in (*ADMIN_ROUTES, *VENDOR_ROUTES):
            assert (await c.get(f"/api{p}")).status_code == 401, p
        for m, p in (("post", "/notifications/1/read"), ("post", "/notifications/read-all"), ("post", "/notifications/evaluate"),
                     ("post", "/notifications/test-email"), ("put", "/notifications/rules/high"), ("put", "/notifications/preferences"),
                     ("post", "/vendor/notifications/read-all")):
            assert (await getattr(c, m)(f"/api{p}", **({"json": {"email": False}} if m == "put" else {}))).status_code == 401, p


@pytest.mark.anyio
async def test_plain_user_has_no_notification_access():
    h = auth_headers("user")
    async with client() as c:
        for p in (*ADMIN_ROUTES, *VENDOR_ROUTES):
            assert (await c.get(f"/api{p}", headers=h)).status_code == 403, p
        assert (await c.post("/api/notifications/read-all", headers=h)).status_code == 403


@pytest.mark.anyio
async def test_vendor_cannot_use_admin_routes_and_admin_cannot_use_vendor_routes():
    v, a = auth_headers("vendor"), auth_headers("admin")
    async with client() as c:
        for p in ADMIN_ROUTES:
            assert (await c.get(f"/api{p}", headers=v)).status_code == 403, p
        for m, p in (("post", "/notifications/evaluate"), ("post", "/notifications/test-email"), ("post", "/notifications/read-all")):
            assert (await getattr(c, m)(f"/api{p}", headers=v)).status_code == 403, p
        assert (await c.put("/api/notifications/rules/high", json={"email": False}, headers=v)).status_code == 403
        for p in VENDOR_ROUTES:
            assert (await c.get(f"/api{p}", headers=a)).status_code == 403, p
    denied = [x for x in audit.list_logs(200, 0, "access_denied")[0]]
    assert len(denied) >= len(ADMIN_ROUTES) + 3  # every refusal is audited


@pytest.mark.anyio
async def test_admin_feed_filters_read_state_and_audit(indexer):
    h = auth_headers("admin")
    async with client() as c:
        await c.post("/api/detections/run", headers=h)
        al = (await c.get("/api/notifications", headers=h)).json()
        assert al["total"] == 2 and all(i["category"] == "new_incident" and not i["is_read"] for i in al["items"])
        assert (await c.get("/api/notifications?category=critical_alert", headers=h)).json()["total"] == 0
        assert (await c.get("/api/notifications?severity=high&unread=true", headers=h)).json()["total"] == 2
        assert (await c.get("/api/notifications?category=bogus", headers=h)).status_code == 422
        nid = al["items"][0]["id"]
        assert (await c.post(f"/api/notifications/{nid}/read", headers=h)).json() == {"read": nid}
        assert (await c.get("/api/notifications/summary", headers=h)).json()["unread"] == 1
        assert (await c.get("/api/notifications?read=true", headers=h)).json()["total"] == 1
        assert (await c.post(f"/api/notifications/{nid}/unread", headers=h)).status_code == 200
        assert (await c.post("/api/notifications/read-all", headers=h)).json() == {"marked_read": 2}
        d = (await c.get(f"/api/notifications/{nid}", headers=h)).json()
        assert d["is_read"] and d["agent_ids"] and d["deliveries"] == []
        assert (await c.get("/api/notifications/9999", headers=h)).status_code == 404
        assert (await c.get("/api/detections/summary", headers=h)).json()["unread_notifications"] == 0
    acts = {x["action"] for x in audit.list_logs(100, 0)[0]}
    assert {"notification_create", "notification_read", "notification_unread", "notification_read_all"} <= acts


@pytest.mark.anyio
async def test_two_admins_have_independent_read_state(indexer):
    h1, a2 = auth_headers("admin"), users.create("second@test.local", "admin")
    async with client() as c:
        await c.post("/api/detections/run", headers=h1)
        await c.post("/api/notifications/read-all", headers=h1)
        assert (await c.get("/api/notifications/summary", headers=h1)).json()["unread"] == 0
        assert (await c.get("/api/notifications/summary", headers=H(a2["id"]))).json()["unread"] == 2


@pytest.mark.anyio
async def test_vendor_isolation_over_http(indexer):
    va, vb, vn = (users.create(f"{n}@test.local", "vendor") for n in ("va", "vb", "vn"))
    vendor_agents.assign(va["id"], "001"), vendor_agents.assign(vb["id"], "002")
    async with client() as c:
        await c.post("/api/detections/run", headers=auth_headers("admin"))
        mine = (await c.get("/api/vendor/notifications", headers=H(va["id"]))).json()
        theirs = (await c.get("/api/vendor/notifications", headers=H(vb["id"]))).json()
        none = (await c.get("/api/vendor/notifications", headers=H(vn["id"]))).json()
        assert mine["total"] == 1 and theirs["total"] == 1 and none["total"] == 0 and mine["items"][0]["id"] != theirs["items"][0]["id"]
        assert "email_state" not in mine["items"][0] and "198.51.100.7" not in json.dumps(mine)  # agent 002's source IP never leaks
        foreign = theirs["items"][0]["id"]
        assert (await c.get(f"/api/vendor/notifications/{foreign}", headers=H(va["id"]))).status_code == 404
        assert (await c.post(f"/api/vendor/notifications/{foreign}/read", headers=H(va["id"]))).status_code == 404
        assert (await c.post(f"/api/vendor/notifications/{foreign}/unread", headers=H(va["id"]))).status_code == 404
        assert (await c.get("/api/vendor/notifications?category=pending_approval", headers=H(va["id"]))).status_code == 422  # admin-only category
        assert (await c.post("/api/vendor/notifications/read-all", headers=H(va["id"]))).json() == {"marked_read": 1}
        assert (await c.get("/api/vendor/notifications/summary", headers=H(va["id"]))).json()["unread"] == 0
        assert (await c.get("/api/vendor/notifications/summary", headers=H(vb["id"]))).json()["unread"] == 1  # vb's state untouched
        # an admin-only notification on the vendor's own agent stays invisible to the vendor
        aid = (await c.get("/api/detections/alerts?agent_id=001", headers=auth_headers("admin"))).json()["items"][0]["id"]
        assert (await c.post(f"/api/ir/recommend/{aid}", headers=auth_headers("admin"))).status_code == 200
        assert (await c.get("/api/notifications?category=pending_approval", headers=auth_headers("admin"))).json()["total"] >= 1
        assert (await c.get("/api/vendor/notifications", headers=H(va["id"]))).json()["total"] == 1
    assert any(x["action"] == "access" and x["actor_id"] == va["id"] for x in audit.list_logs(200, 0)[0])  # vendor reads are audited


@pytest.mark.anyio
async def test_rules_are_admin_managed_validated_and_audited():
    h = auth_headers("admin")
    async with client() as c:
        items = (await c.get("/api/notifications/rules", headers=h)).json()["items"]
        assert [r["severity"] for r in items] == ["critical", "high", "medium", "low"]
        r = (await c.put("/api/notifications/rules/medium", json={"email": True, "sla_minutes": 120}, headers=h)).json()
        assert r["email"] is True and r["sla_minutes"] == 120
        assert (await c.put("/api/notifications/rules/medium", json={}, headers=h)).status_code == 422
        assert (await c.put("/api/notifications/rules/medium", json={"sla_minutes": 1}, headers=h)).status_code == 422
        assert (await c.put("/api/notifications/rules/urgent", json={"email": True}, headers=h)).status_code == 422
    e = [x for x in audit.list_logs(50, 0, "escalation_rule_update")[0]]
    assert len(e) == 1 and "sla_minutes=1440->120" in e[0]["detail"]


@pytest.mark.anyio
async def test_preferences_for_admin_and_vendor_are_self_service_and_audited():
    v = make_user("vendor")
    async with client() as c:
        a = auth_headers("admin")
        assert (await c.get("/api/notifications/preferences", headers=a)).json()["email_enabled"] is True
        r = await c.put("/api/notifications/preferences", json={"email_enabled": False, "min_severity": "critical"}, headers=a)
        assert r.json()["email_enabled"] is False and r.json()["min_severity"] == "critical"
        assert (await c.put("/api/notifications/preferences", json={"min_severity": "urgent"}, headers=a)).status_code == 422
        assert (await c.put("/api/notifications/preferences", json={}, headers=a)).status_code == 422
        vh = auth_headers("vendor")
        assert (await c.get("/api/vendor/notifications/preferences", headers=vh)).json()["email_enabled"] is False
        assert (await c.put("/api/vendor/notifications/preferences", json={"email_enabled": True}, headers=vh)).json()["email_enabled"] is True
    assert len(audit.list_logs(50, 0, "notification_prefs_update")[0]) == 2 and nt.get_prefs(v)["email_enabled"] is True


@pytest.mark.anyio
async def test_status_never_returns_secrets(smtp):
    async with client() as c:
        r = await c.get("/api/notifications/status", headers=auth_headers("admin"))
    body = r.text
    assert r.json()["email_ready"] is True and r.json()["tls"] == "starttls"
    assert SECRET not in body and "smtp.test" not in body and "mailer" not in body and "freightshield.test" not in body


@pytest.mark.anyio
async def test_email_flow_end_to_end_and_test_email_goes_to_caller_only(indexer, smtp):
    admin = make_user("admin")
    h = auth_headers("admin")
    async with client() as c:
        assert (await c.post("/api/notifications/test-email", headers=h)).json() == {"sent": True}
        assert [m["To"] for m in smtp.sent] == [admin["email"]]
        smtp.sent.clear()
        await c.post("/api/detections/run", headers=h)  # scan -> notifications -> outbox dispatched after the scan
        assert len(smtp.sent) == 2 and all(m["Subject"].startswith("[FreightShield][HIGH]") for m in smtp.sent)
        d = (await c.get("/api/notifications/deliveries", headers=h)).json()
        assert d["total"] == 2 and {x["status"] for x in d["items"]} == {"sent"}
        smtp.fail_for = {admin["email"]}
        assert (await c.post("/api/notifications/test-email", headers=h)).status_code == 502
    acts = {x["action"] for x in audit.list_logs(100, 0)[0]}
    assert {"notification_test_email", "notification_email_sent"} <= acts
    assert all(SECRET not in (x["detail"] or "") for x in audit.list_logs(200, 0)[0])


@pytest.mark.anyio
async def test_test_email_refuses_when_email_is_not_configured():
    async with client() as c:
        r = await c.post("/api/notifications/test-email", headers=auth_headers("admin"))
    assert r.status_code == 409 and "not ready" in r.json()["detail"]
    assert audit.list_logs(10, 0, "notification_test_email")[0][0]["outcome"] == "failure"


@pytest.mark.anyio
async def test_evaluate_runs_overdue_pending_and_threat_intel_checks(indexer):
    h = auth_headers("admin")
    async with client() as c:
        await c.post("/api/detections/run", headers=h)
        aid = (await c.get("/api/detections/alerts?agent_id=001", headers=h)).json()["items"][0]["id"]
        await c.post(f"/api/ir/recommend/{aid}", headers=h)
        nt.update_rule("high", sla_minutes=5)
        from app.core.db import connect
        with connect() as conn:
            conn.execute("UPDATE incidents SET created_at='2020-01-01T00:00:00+00:00'")
        r = (await c.post("/api/notifications/evaluate", headers=h)).json()
        assert r["overdue"] >= 2 and r["email"]["skipped_reason"]
        assert (await c.get("/api/notifications?category=overdue_incident", headers=h)).json()["total"] >= 2
        assert (await c.post("/api/notifications/evaluate", headers=h)).json()["overdue"] == 0  # idempotent
    assert "notification_evaluate" in {x["action"] for x in audit.list_logs(100, 0)[0]}
