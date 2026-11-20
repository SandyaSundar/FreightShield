"""Phase 8 notification logic (service level). SIMULATED inputs: Wazuh-shaped events, IOC risk set directly, SMTP replaced by a
recording fake (smtplib.SMTP). These prove routing, scoping, escalation, outbox and audit logic - not live Wazuh/SMTP connectivity
(see scripts/verify_notifications.py for the live SMTP check)."""
import json
import smtplib
import sqlite3
from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.core.config import get_settings
from app.core.db import connect
from app.services import audit, ir, notifications as nt, threat_intel, users, vendor_agents
from tests.test_detection_engine import T0, fails, hit, run

SECRET = "S3cretPw!"
PUBLIC = "45.33.32.156"  # block_ip refuses documentation/private ranges, so response tests need a public source IP
INC_AT = T0 + timedelta(minutes=10)  # run() default `now` = incident created_at


def admin(email="admin@test.local"):
    return users.get_by_email(email) or users.create(email, "admin")


def vendor(email, *agents):
    v = users.get_by_email(email) or users.create(email, "vendor")
    for a in agents:
        vendor_agents.assign(v["id"], a)
    return v


def cats(**kw):
    return [(i["category"], i["severity"]) for i in nt.list_notifications(50, 0, **kw)[0]]


class FakeSMTP:
    sent, calls, fail_for = [], [], set()

    def __init__(self, host, port, timeout=None, context=None):
        FakeSMTP.calls.append(("connect", host, port))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        FakeSMTP.calls.append(("starttls", context is not None))

    def login(self, user, pw):
        FakeSMTP.calls.append(("login", user, pw))

    def send_message(self, msg):
        if msg["To"] in FakeSMTP.fail_for:
            raise smtplib.SMTPAuthenticationError(535, f"bad credentials {SECRET}".encode())
        FakeSMTP.sent.append(msg)


@pytest.fixture
def smtp(monkeypatch):
    s = get_settings()
    for k, v in (("notify_email_enabled", True), ("smtp_host", "smtp.test"), ("smtp_from", "FreightShield <soc@freightshield.test>"),
                 ("smtp_user", "mailer"), ("smtp_password", SECRET), ("smtp_starttls", True), ("smtp_ssl", False), ("notify_email_max_attempts", 3)):
        monkeypatch.setattr(s, k, v)
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    FakeSMTP.sent, FakeSMTP.calls, FakeSMTP.fail_for = [], [], set()
    return FakeSMTP


# ------------------------------------------------------------------ categories from real detection output
def test_one_notification_per_detection_event_with_category_priority():
    run(fails(6))  # brand-new incident
    run([hit(50, 100, level=12, rule="5402")], now=INC_AT)  # joins the open incident -> plain alert
    nt_ = nt.list_notifications(10, 0)[0]
    assert [n["category"] for n in reversed(nt_)] == ["new_incident", "alert"]
    assert all(n["incident_id"] and n["alert_id"] and n["message"] for n in nt_)
    nt.update_rule("high", enabled=True)
    from app.services import detection
    detection.update_rule("high_level_event", severity="critical")
    run([hit(60, 0, agent="002", level=13, rule="5403", name="db-01")], now=INC_AT)
    assert nt.list_notifications(1, 0)[0][0]["category"] == "critical_alert"  # critical beats new_incident


def test_disabled_severity_rule_creates_no_notification():
    nt.update_rule("high", enabled=False)
    run(fails(6))
    assert nt.list_notifications(10, 0)[1] == 0
    assert nt.summary()["unread"] == 0


def test_creation_is_audited():
    run(fails(6))
    assert "notification_create" in {x["action"] for x in audit.list_logs(50, 0)[0]}


# ------------------------------------------------------------------ read / unread is per user
def test_read_state_is_per_user():
    a1, a2 = admin(), admin("second@test.local")
    run(fails(6))
    nid = nt.list_notifications(10, 0, user_id=a1["id"])[0][0]["id"]
    nt.mark_read(nid, a1["id"])
    assert nt.summary(a1["id"])["unread"] == 0 and nt.summary(a2["id"])["unread"] == 1
    assert nt.list_notifications(10, 0, True, a1["id"])[1] == 0 and nt.list_notifications(10, 0, True, a2["id"])[1] == 1
    nt.mark_read(nid, a1["id"], read=False)
    assert nt.summary(a1["id"])["unread"] == 1
    assert nt.mark_all_read(a2["id"]) == 1 and nt.summary(a2["id"])["unread"] == 0 and nt.summary(a1["id"])["unread"] == 1
    with pytest.raises(HTTPException) as e:
        nt.mark_read(9999, a1["id"])
    assert e.value.status_code == 404


# ------------------------------------------------------------------ vendor isolation
def test_vendor_only_sees_own_agents_and_vendor_categories():
    va, vb, vn = vendor("va@test.local", "001"), vendor("vb@test.local", "002"), vendor("vn@test.local")
    run(fails(6, "001") + fails(6, "002", "198.51.100.7"), now=INC_AT)
    own = lambda v: nt.list_notifications(50, 0, user_id=v["id"], agent_ids=vendor_agents.agent_ids(v["id"]))
    (a_items, a_total), (b_items, _), (n_items, n_total) = own(va), own(vb), own(vn)
    assert a_total == 1 and "web-01" in a_items[0]["title"]
    assert len(b_items) == 1 and b_items[0]["id"] != a_items[0]["id"] and n_total == 0
    assert "email_state" not in a_items[0]  # internal delivery state is admin-only
    with pytest.raises(HTTPException) as e:
        nt.get_notification(b_items[0]["id"], va["id"], vendor_agents.agent_ids(va["id"]))
    assert e.value.status_code == 404
    with pytest.raises(HTTPException):
        nt.mark_read(b_items[0]["id"], va["id"], vendor_agents.agent_ids(va["id"]))
    assert nt.mark_all_read(va["id"], vendor_agents.agent_ids(va["id"])) == 1 and nt.summary(vb["id"], ["002"])["unread"] == 1


def test_admin_only_categories_are_hidden_from_vendors():
    ad, va = admin(), vendor("va@test.local", "001")
    r = run(fails(6, "001", PUBLIC))
    assert ir.recommend(r["created"][0], ad)["actions"]                       # pending approval
    nt.check_overdue(now=INC_AT + timedelta(minutes=300))                      # overdue
    assert {c for c, _ in cats()} >= {"pending_approval", "overdue_incident", "new_incident"}
    assert {c for c, _ in cats(user_id=va["id"], agent_ids=["001"])} == {"new_incident"}
    assert nt.summary(va["id"], ["001"])["unread"] == 1


# ------------------------------------------------------------------ pending approvals / threat intel
def test_pending_response_approval_notifies_once():
    ad = admin()
    aid = run(fails(6, "001", PUBLIC))["created"][0]
    acts = ir.recommend(aid, ad)["actions"]
    pend = [a for a in acts if a["status"] == "pending"]
    assert pend
    items = [i for i in nt.list_notifications(20, 0)[0] if i["category"] == "pending_approval"]
    assert len(items) == len(pend) and f"agent {pend[0]['agent_id']}" in items[0]["title"] and items[0]["severity"] == "high"
    assert nt.sync_pending_approvals() == [] and ir.recommend(aid, ad)["actions"] == []  # idempotent
    assert any(x["action"] == "notification_create" for x in audit.list_logs(100, 0)[0])


def _ioc_world():
    threat_intel.ingest([hit(1, 0, "001", 5, srcip="45.33.32.156"), hit(2, 5, "002", 5, srcip="45.33.32.156", name="db-01")])
    with connect() as c:
        return c.execute("SELECT id FROM iocs WHERE value='45.33.32.156'").fetchone()[0]


def test_threat_intel_notifications_only_for_high_risk_and_real_sightings():
    iid = _ioc_world()
    assert nt.sync_threat_intel() == []  # unscored IOC: nothing is invented
    with connect() as c:
        c.execute("UPDATE iocs SET risk='high', score=75, classification='suspicious' WHERE id=?", (iid,))
    assert len(nt.sync_threat_intel()) == 2 and nt.sync_threat_intel() == []  # one per agent, idempotent
    with connect() as c:
        c.execute("UPDATE iocs SET risk='critical', score=95, classification='malicious' WHERE id=?", (iid,))
    assert len(nt.sync_threat_intel()) == 2  # a higher risk re-notifies
    va = vendor("va@test.local", "001")
    mine = nt.list_notifications(50, 0, user_id=va["id"], agent_ids=["001"])[0]
    assert len(mine) == 2 and all(i["category"] == "threat_intel" and "agent 001" in i["title"] for i in mine)
    assert "agent 002" not in json.dumps(mine)  # no other agent leaks into a vendor's feed


# ------------------------------------------------------------------ overdue + escalation
def test_overdue_then_escalated_by_severity_rules():
    run(fails(6))  # high: SLA 240 min, escalates 240 min later
    assert nt.check_overdue(now=INC_AT + timedelta(minutes=239)) == []
    assert len(nt.check_overdue(now=INC_AT + timedelta(minutes=241))) == 1
    assert nt.check_overdue(now=INC_AT + timedelta(minutes=300)) == []  # idempotent
    assert len(nt.check_overdue(now=INC_AT + timedelta(minutes=481))) == 1
    over = [i for i in nt.list_notifications(10, 0)[0] if i["category"] == "overdue_incident"]
    assert sorted(i["escalation_level"] for i in over) == [1, 2] and any(i["title"].startswith("ESCALATED") for i in over)


def test_escalation_can_be_disabled_and_resolved_incidents_are_ignored():
    from app.services import detection
    nt.update_rule("high", escalate_after_minutes=0)
    run(fails(6))
    nt.check_overdue(now=INC_AT + timedelta(days=3))
    assert [i["escalation_level"] for i in nt.list_notifications(10, 0)[0] if i["category"] == "overdue_incident"] == [1]
    iid = detection.list_incidents(1, 0)[0][0]["id"]
    detection.set_incident_status(iid, "resolved")
    nt.update_rule("high", sla_minutes=5)
    assert nt.check_overdue(now=INC_AT + timedelta(days=9)) == []


# ------------------------------------------------------------------ email
def test_email_not_ready_never_sends_and_does_not_backfill(smtp):
    s = get_settings()
    s.notify_email_enabled = False
    run(fails(6))
    assert nt.list_notifications(10, 0)[0][0]["email_state"] == "unconfigured"
    s.notify_email_enabled = True
    r = nt.dispatch_emails()
    assert r["sent"] == 0 and smtp.sent == []  # history is not mass-mailed when SMTP is switched on later


def test_smtp_credentials_require_tls_and_status_hides_secrets(smtp):
    s = get_settings()
    assert nt.email_problem() is None
    s.smtp_starttls = False
    assert "TLS" in nt.email_problem()
    dumped = json.dumps(nt.status())
    assert SECRET not in dumped and "smtp.test" not in dumped and "mailer" not in dumped


def test_email_recipients_follow_role_scope_and_preferences(smtp):
    a1, a2 = admin(), admin("second@test.local")
    va, vb = vendor("va@test.local", "001"), vendor("vb@test.local", "002")
    nt.set_prefs(a2, False, None)             # a2 opted out
    nt.set_prefs(va, True, "medium")          # vendors are opt-in; va opted in
    nt.set_prefs(vb, True, "medium")          # vb opted in but owns another agent
    run(fails(6, "001"))
    assert nt.dispatch_emails()["sent"] == 2
    assert sorted(m["To"] for m in smtp.sent) == sorted([a1["email"], va["email"]])
    assert ("starttls", True) in smtp.calls and ("login", "mailer", SECRET) in smtp.calls
    m = smtp.sent[0]
    assert m["Subject"].startswith("[FreightShield][HIGH]") and SECRET not in m.as_string()
    assert nt.dispatch_emails()["sent"] == 0  # outbox finished: no duplicates
    assert nt.list_notifications(1, 0)[0][0]["email_state"] == "done"
    assert {"notification_email_sent"} <= {x["action"] for x in audit.list_logs(50, 0)[0]}


def test_min_severity_preference_and_admin_only_categories_in_email(smtp):
    ad, va = admin(), vendor("va@test.local", "001")
    nt.set_prefs(va, True, "low")
    aid = run(fails(6, "001", PUBLIC))["created"][0]
    nt.dispatch_emails()
    smtp.sent.clear()
    ir.recommend(aid, ad)
    nt.dispatch_emails()
    assert [m["To"] for m in smtp.sent] == [ad["email"]]  # approval emails never reach a vendor, even a scoped, opted-in one
    nt.set_prefs(ad, True, "critical")
    smtp.sent.clear()
    run(fails(6, "002", "198.51.100.9"), now=INC_AT)
    nt.dispatch_emails()
    assert ad["email"] not in [m["To"] for m in smtp.sent]


def test_escalation_contacts_only_get_level_two(smtp):
    ad = admin()
    get_settings().notify_escalation_emails = ["oncall@corp.test", "not-an-address"]
    run(fails(6))
    nt.dispatch_emails()
    nt.check_overdue(now=INC_AT + timedelta(minutes=241))
    nt.dispatch_emails()
    assert "oncall@corp.test" not in [m["To"] for m in smtp.sent]
    nt.check_overdue(now=INC_AT + timedelta(minutes=500))
    nt.dispatch_emails()
    lvl2 = [m for m in smtp.sent if m["Subject"].startswith("[FreightShield][HIGH] ESCALATED")]
    assert sorted(m["To"] for m in lvl2) == sorted([ad["email"], "oncall@corp.test"]) and "ESCALATED" in lvl2[0].get_content()


def test_failed_email_is_retried_then_given_up_without_leaking_the_password(smtp):
    admin()
    smtp.fail_for = {"admin@test.local"}
    run(fails(6))
    assert [nt.dispatch_emails()["failed"] for _ in range(4)] == [1, 1, 1, 0]  # 3 attempts (NOTIFY_EMAIL_MAX_ATTEMPTS), then it gives up
    d = nt.list_deliveries(10, 0)[0][0]
    assert d["status"] == "failed" and d["attempts"] == 3 and SECRET not in (d["error"] or "") and "***" in d["error"]
    assert nt.list_notifications(1, 0)[0][0]["email_state"] == "done"  # gave up after NOTIFY_EMAIL_MAX_ATTEMPTS
    assert all(SECRET not in (x["detail"] or "") for x in audit.list_logs(100, 0)[0])
    assert "notification_email_failed" in {x["action"] for x in audit.list_logs(100, 0)[0]}


def test_email_headers_cannot_be_injected(smtp):
    row = {"severity": "high", "title": "x\r\nBcc: evil@x.test", "category": "alert", "ts": "t", "escalation_level": 0, "message": None}
    m = nt._build(row, "admin@test.local")
    assert "\n" not in m["Subject"] and "\r" not in m["Subject"] and m["Bcc"] is None


def test_test_email_goes_only_to_the_caller(smtp):
    ad = admin()
    nt.send_test_email(ad)
    assert [m["To"] for m in smtp.sent] == [ad["email"]]
    get_settings().notify_email_enabled = False
    with pytest.raises(HTTPException) as e:
        nt.send_test_email(ad)
    assert e.value.status_code == 409


# ------------------------------------------------------------------ preferences, rules, evaluator, migration
def test_preference_defaults_and_validation():
    ad, v = admin(), vendor("va@test.local", "001")
    assert nt.get_prefs(ad)["email_enabled"] is True and nt.get_prefs(v)["email_enabled"] is False
    old, new = nt.set_prefs(v, True, "critical")
    assert old["email_enabled"] is False and new == nt.get_prefs(v) and new["min_severity"] == "critical"
    with pytest.raises(HTTPException):
        nt.set_prefs(v, None, "urgent")


def test_rules_seed_and_update():
    r = {x["severity"]: x for x in nt.load_rules()}
    assert r["critical"]["email"] is True and r["critical"]["sla_minutes"] < r["high"]["sla_minutes"] < r["medium"]["sla_minutes"]
    old, new = nt.update_rule("medium", email=True, sla_minutes=90)
    assert old["email"] is False and new["email"] is True and new["sla_minutes"] == 90
    with pytest.raises(HTTPException):
        nt.update_rule("urgent", email=True)


def test_run_cycle_is_audited_and_idempotent():
    ad = admin()
    run(fails(6))
    r1 = nt.run_cycle(ad)
    assert r1["overdue"] == 0 and r1["email"]["skipped_reason"]
    assert "notification_evaluate" in {x["action"] for x in audit.list_logs(50, 0)[0]}


def test_phase3_database_is_migrated_in_place(tmp_path, monkeypatch):
    path = str(tmp_path / "old.db")
    monkeypatch.setattr(get_settings(), "database_path", path)
    old = sqlite3.connect(path)
    old.executescript("CREATE TABLE notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_id INTEGER, severity TEXT NOT NULL,"
                      " title TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0);"
                      "INSERT INTO notifications (ts, alert_id, severity, title) VALUES ('2026-01-01T00:00:00+00:00', 7, 'high', 'legacy alert');")
    old.commit(); old.close()
    items, total = nt.list_notifications(10, 0)
    assert total == 1 and items[0]["title"] == "legacy alert" and items[0]["category"] == "alert" and not items[0]["is_read"]
    run(fails(6))
    assert nt.list_notifications(10, 0)[1] == 2
