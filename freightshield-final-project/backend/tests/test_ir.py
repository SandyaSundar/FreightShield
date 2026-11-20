"""Incident-response tests. Wazuh Active Response is mocked at wazuh_manager.active_response; no real host is contacted."""
import json
import sqlite3

import httpx
import pytest

from app.core.config import get_settings
from app.core.db import connect
from app.main import app
from app.services import audit, ir, users, vendor_agents
from app.services.wazuh_manager import wazuh_manager
from tests.helpers import auth_headers, make_user, token

OK = {"data": {"total_affected_items": 1, "total_failed_items": 0}}
FAIL = {"data": {"total_affected_items": 0, "total_failed_items": 1}}


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
def ar(monkeypatch):
    """Execution on, block + unblock commands configured, Wazuh AR mocked. `calls` records every AR request."""
    s = get_settings()
    for k, v in (("ir_execution_enabled", True), ("ir_ar_block_command", "firewall-drop"), ("ir_ar_unblock_command", "firewall-undrop"),
                 ("ir_ar_isolate_command", ""), ("ir_ar_unisolate_command", ""), ("ir_protected_ips", [])):
        monkeypatch.setattr(s, k, v)
    state = {"calls": [], "reply": OK}

    async def fake(agent_id, command, arguments, alert=None):
        state["calls"].append((agent_id, command, arguments, alert))
        r = state["reply"]
        if isinstance(r, Exception):
            raise r
        return r
    monkeypatch.setattr(wazuh_manager, "active_response", fake)
    return state


def make_alert(rule_key="auth_bruteforce", severity="high", src_ip="45.155.205.9", agent_id="001", status="new"):
    with connect() as c:
        cur = c.execute("INSERT INTO detection_alerts (dedupe_key,rule_key,title,severity,status,agent_id,src_ip,event_count,first_seen,last_seen,created_at,updated_at)"
                        " VALUES (?,?,?,?,?,?,?,?,'t','t','t','t')", (f"k{src_ip}{agent_id}{rule_key}", rule_key, "t", severity, status, agent_id, src_ip, 5))
        return cur.lastrowid


async def rec(c, alert_id, role="admin"):
    return await c.post(f"/api/ir/recommend/{alert_id}", headers=auth_headers(role))


async def pending_action(c, **kw):
    r = await rec(c, make_alert(**kw))
    assert r.status_code == 200, r.text
    return r.json()["actions"][0]["id"]


# ---- recommendation
@pytest.mark.anyio
async def test_recommend_creates_pending_and_never_executes(ar):
    async with client() as c:
        r = await rec(c, make_alert())
        a = r.json()["actions"][0]
        assert a["status"] == "pending" and a["action"] == "block_ip" and a["target"] == "45.155.205.9"
        assert ar["calls"] == []
        assert r.json()["advisories"]
        again = (await rec(c, a["alert_id"])).json()          # dedupe
        assert again["actions"] == [] and again["skipped"]


@pytest.mark.anyio
async def test_recommendation_respects_severity_and_unsafe_targets(ar):
    async with client() as c:
        assert (await rec(c, make_alert(severity="low"))).json()["actions"] == []
        a = (await rec(c, make_alert(src_ip="10.0.0.5"))).json()["actions"][0]
        assert a["status"] == "unsupported" and "private" in a["detail"]
        a = (await rec(c, make_alert(src_ip="185.220.101.7", agent_id="000"))).json()["actions"][0]
        assert a["status"] == "unsupported"
        assert (await rec(c, make_alert(status="resolved", src_ip="185.220.101.8"))).status_code == 409
        assert (await c.post("/api/ir/recommend/99999", headers=auth_headers())).status_code == 404


@pytest.mark.anyio
async def test_isolation_unsupported_unless_command_configured(ar, monkeypatch):
    async with client() as c:
        a = (await rec(c, make_alert("high_level_event", "critical", None))).json()["actions"][0]
        assert a["action"] == "isolate_agent" and a["status"] == "unsupported"
        monkeypatch.setattr(get_settings(), "ir_ar_isolate_command", "isolate-host")
        a = (await rec(c, make_alert("high_level_event", "critical", None, agent_id="002"))).json()["actions"][0]
        assert a["status"] == "pending"


# ---- RBAC / vendor isolation
@pytest.mark.anyio
async def test_rbac_and_vendor_isolation(ar):
    async with client() as c:
        aid = await pending_action(c)
        for path, m in (("/api/ir/summary", "get"), ("/api/ir/actions", "get"), ("/api/ir/playbooks", "get"), ("/api/ir/audit", "get"),
                        (f"/api/ir/actions/{aid}/approve", "post"), (f"/api/ir/actions/{aid}/reject", "post"),
                        (f"/api/ir/actions/{aid}/rollback", "post"), ("/api/ir/recommend/1", "post")):
            assert (await c.request(m, path)).status_code == 401
            for role in ("user", "vendor"):
                assert (await c.request(m, path, headers=auth_headers(role), json={"reason": "nope nope"})).status_code == 403
        assert ar["calls"] == []
        assert ir.get_action(aid)["status"] == "pending"
        # vendor sees only assigned agents, and no approver/error fields
        v = make_user("vendor")
        await pending_action(c, src_ip="185.220.101.20", agent_id="002")
        vendor_agents.assign(v["id"], "001")
        items = (await c.get("/api/vendor/ir/actions", headers=auth_headers("vendor"))).json()["items"]
        assert {i["agent_id"] for i in items} == {"001"} and all("approved_by" not in i and "error" not in i for i in items)
        assert (await c.get("/api/vendor/ir/actions", headers=auth_headers("admin"))).status_code == 403


# ---- approval + execution
@pytest.mark.anyio
async def test_approve_executes_once_via_wazuh_ar(ar):
    async with client() as c:
        aid = await pending_action(c)
        r = await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())
        a = r.json()
        assert r.status_code == 200 and a["status"] == "executed" and a["approved_by"] == "admin@test.local" and a["executed_at"]
        assert ar["calls"] == [("001", "firewall-drop", ["45.155.205.9"], {"data": {"srcip": "45.155.205.9"}})]
        assert (await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())).status_code == 409
        assert len(ar["calls"]) == 1
        events = [e["event"] for e in ir.audit_list(50, 0)[0]][::-1]
        assert events == ["recommended", "approved", "execute_started", "execute_succeeded"]
        assert any(x["action"] == "ir_approved" for x in audit.list_logs(50, 0)[0])


@pytest.mark.anyio
async def test_execution_disabled_changes_nothing(ar, monkeypatch):
    async with client() as c:
        aid = await pending_action(c)
        monkeypatch.setattr(get_settings(), "ir_execution_enabled", False)
        assert (await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())).status_code == 409
        assert ir.get_action(aid)["status"] == "pending" and ar["calls"] == []


@pytest.mark.anyio
async def test_failure_then_retry(ar):
    async with client() as c:
        aid = await pending_action(c)
        ar["reply"] = FAIL
        a = (await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())).json()
        assert a["status"] == "failed" and "did not confirm" in a["error"]
        ar["reply"] = OK
        a = (await c.post(f"/api/ir/actions/{aid}/retry", headers=auth_headers())).json()
        assert a["status"] == "executed" and a["attempts"] == 2 and a["error"] is None
        assert (await c.post(f"/api/ir/actions/{aid}/retry", headers=auth_headers())).status_code == 409


@pytest.mark.anyio
async def test_upstream_error_is_recorded_not_raised(ar):
    from app.core.errors import UpstreamError
    async with client() as c:
        aid = await pending_action(c)
        ar["reply"] = UpstreamError("wazuh_manager", "Wazuh Manager timed out.", 504)
        a = (await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())).json()
        assert a["status"] == "failed" and a["error"] == "Wazuh Manager timed out."


@pytest.mark.anyio
async def test_protected_ip_blocked_at_execution_time(ar, monkeypatch):
    async with client() as c:
        aid = await pending_action(c)
        monkeypatch.setattr(get_settings(), "ir_protected_ips", ["45.155.205.9"])
        a = (await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())).json()
        assert a["status"] == "failed" and "protected" in a["error"] and ar["calls"] == []


@pytest.mark.anyio
async def test_reject(ar):
    async with client() as c:
        aid = await pending_action(c)
        assert (await c.post(f"/api/ir/actions/{aid}/reject", headers=auth_headers(), json={"reason": "x"})).status_code == 422
        a = (await c.post(f"/api/ir/actions/{aid}/reject", headers=auth_headers(), json={"reason": "false positive"})).json()
        assert a["status"] == "rejected" and ar["calls"] == []
        assert (await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())).status_code == 409


# ---- rollback
@pytest.mark.anyio
async def test_rollback_success_failure_and_unsupported(ar, monkeypatch):
    async with client() as c:
        aid = await pending_action(c)
        assert (await c.post(f"/api/ir/actions/{aid}/rollback", headers=auth_headers())).status_code == 409   # not executed yet
        await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())
        ar["reply"] = FAIL
        assert (await c.post(f"/api/ir/actions/{aid}/rollback", headers=auth_headers())).json()["status"] == "rollback_failed"
        ar["reply"] = OK
        a = (await c.post(f"/api/ir/actions/{aid}/rollback", headers=auth_headers())).json()
        assert a["status"] == "rolled_back" and a["rolled_back_by"] == "admin@test.local"
        assert ar["calls"][-1][1] == "firewall-undrop"
        # unsupported: no unblock command -> 409, action stays executed, attempt is audited
        bid = await pending_action(c, src_ip="185.220.101.30")
        await c.post(f"/api/ir/actions/{bid}/approve", headers=auth_headers())
        monkeypatch.setattr(get_settings(), "ir_ar_unblock_command", "")
        n = len(ar["calls"])
        assert (await c.post(f"/api/ir/actions/{bid}/rollback", headers=auth_headers())).status_code == 409
        assert ir.get_action(bid)["status"] == "executed" and len(ar["calls"]) == n
        assert "rollback_unsupported" in [e["event"] for e in ir.audit_list(100, 0)[0]]


# ---- immutable-style audit
@pytest.mark.anyio
async def test_audit_chain_is_append_only_and_tamper_evident(ar):
    async with client() as c:
        aid = await pending_action(c)
        await c.post(f"/api/ir/actions/{aid}/approve", headers=auth_headers())
        assert (await c.get("/api/ir/audit/verify", headers=auth_headers())).json() == {"valid": True, "entries": 4, "first_bad_id": None}
    with pytest.raises(sqlite3.DatabaseError):
        with connect() as db:
            db.execute("UPDATE ir_audit SET detail='x' WHERE id=1")
    with pytest.raises(sqlite3.DatabaseError):
        with connect() as db:
            db.execute("DELETE FROM ir_audit")
    with connect() as db:       # a privileged attacker who drops the trigger is still detected by the hash chain
        db.execute("DROP TRIGGER ir_audit_no_update")
        db.execute("UPDATE ir_audit SET detail='forged' WHERE id=2")
    assert ir.verify_chain()["valid"] is False and ir.verify_chain()["first_bad_id"] == 2


# ---- playbooks
@pytest.mark.anyio
async def test_playbook_config_and_validation(ar):
    async with client() as c:
        h = auth_headers()
        assert any(p["key"] == "bruteforce_block_ip" for p in (await c.get("/api/ir/playbooks", headers=h)).json()["items"])
        assert (await c.put("/api/ir/playbooks/bruteforce_block_ip", headers=h, json={})).status_code == 422
        assert (await c.put("/api/ir/playbooks/bruteforce_block_ip", headers=h, json={"steps": [{"type": "rm_rf"}]})).status_code == 422
        assert (await c.put("/api/ir/playbooks/nope", headers=h, json={"enabled": False})).status_code == 404
        assert (await c.put("/api/ir/playbooks/bruteforce_block_ip", headers=h, json={"enabled": False})).json()["enabled"] is False
        assert (await rec(c, make_alert())).json()["actions"] == []
        s = (await c.get("/api/ir/summary", headers=h)).json()
        assert s["audit_chain"]["valid"] and "pending_approvals" in s and s["capabilities"]["execution_enabled"]
