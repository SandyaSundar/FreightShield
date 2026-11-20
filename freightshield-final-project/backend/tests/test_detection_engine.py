"""Detection engine + DB logic. SIMULATED: events are synthetic, Wazuh-shaped documents fed straight to the engine.
These prove rule logic, dedupe, correlation, statuses and scoping. They do NOT prove live Wazuh connectivity."""
from datetime import datetime, timedelta, timezone

from app.services import audit, detection, vendor_agents, users

T0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)


def hit(i, secs, agent="001", level=5, groups=("syslog",), rule="5700", srcip=None, name="web-01", mitre=None):
    src = {"timestamp": (T0 + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
           "agent": {"id": agent, "name": name}, "data": {}, "rule": {"id": rule, "level": level, "groups": list(groups), "description": f"rule {rule}"}}
    if srcip:
        src["data"]["srcip"] = srcip
    if mitre:
        src["rule"]["mitre"] = mitre
    return {"_id": f"e{i}", "_source": src}


def run(hits, now=T0 + timedelta(minutes=10)):
    return detection.process([e for e in (detection.normalize(h) for h in hits) if e], now=now)


def fails(n, agent="001", ip="203.0.113.9", start=0, step=10):
    return [hit(start + i, start + i * step, agent, 5, ("syslog", "authentication_failed"), "5710", ip) for i in range(n)]


def test_normalize_handles_wazuh_timestamp_and_mitre():
    e = detection.normalize(hit(1, 0, level=10, srcip="1.2.3.4", mitre={"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}))
    assert e["ts"] == T0 and e["agent_id"] == "001" and e["level"] == 10 and e["src_ip"] == "1.2.3.4"
    assert e["mitre"] == [{"id": "T1110", "tactic": "Credential Access", "technique": "Brute Force"}]
    assert detection.normalize({"_id": "x", "_source": {"rule": {"id": "1"}}}) is None  # no timestamp/agent -> dropped


def test_normal_events_raise_nothing():
    r = run([hit(i, i * 60, level=3) for i in range(30)] + fails(2))
    assert r["created"] == [] and detection.list_alerts(10, 0)[1] == 0


def test_bruteforce_triggers_with_mitre_incident_and_notification():
    r = run(fails(6))
    assert len(r["created"]) == 1
    a = detection.get_alert(r["created"][0])
    assert a["rule_key"] == "auth_bruteforce" and a["severity"] == "high" and a["status"] == "new"
    assert a["event_count"] == 6 and a["src_ip"] == "203.0.113.9" and a["incident_id"]
    assert a["mitre"][0]["id"] == "T1110" and len(a["evidence"]) == 6
    n, _ = detection.list_notifications(10, 0)
    assert len(n) == 1 and n[0]["alert_id"] == a["id"] and not n[0]["is_read"]
    assert ("alert_create", "success") in [(x["action"], x["outcome"]) for x in audit.list_logs(10, 0)[0]]


def test_wazuh_supplied_mitre_is_used_for_high_level_events():
    m = {"id": ["T1059"], "tactic": ["Execution"], "technique": ["Command and Scripting Interpreter"]}
    r = run([hit(1, 0, level=12, rule="100100", mitre=m)])
    a = detection.get_alert(r["created"][0])
    assert a["rule_key"] == "high_level_event" and a["mitre"][0]["id"] == "T1059"


def test_rescan_does_not_duplicate_and_new_events_update_existing():
    first = fails(6)
    assert len(run(first)["created"]) == 1
    again = run(first)
    assert again["created"] == [] and again["updated"] == []
    more = run(first + fails(4, start=70))
    assert more["created"] == [] and len(more["updated"]) == 1
    items, total = detection.list_alerts(10, 0)
    assert total == 1 and items[0]["event_count"] == 10
    assert detection.list_notifications(10, 0)[1] == 1  # no second notification


def test_events_outside_window_do_not_trigger_and_threshold_is_configurable():
    spread = fails(6, step=120)  # 1 failure / 2 min: never 5 within 300s
    assert run(spread)["created"] == []
    detection.update_rule("auth_bruteforce", threshold=3, window_seconds=600)
    assert len(run(spread)["created"]) == 1
    detection.update_rule("auth_bruteforce", enabled=False)
    assert run(fails(8, agent="002", ip="198.51.100.1"))["created"] == []


def test_severity_and_notification_threshold():
    detection.update_rule("auth_bruteforce", severity="low")
    run(fails(5))
    assert detection.list_alerts(10, 0)[0][0]["severity"] == "low"
    assert detection.list_notifications(10, 0)[1] == 0  # below DETECTION_NOTIFY_MIN_SEVERITY (medium)


def test_related_alerts_on_same_agent_correlate_into_one_incident():
    r = run(fails(6) + [hit(50, 100, level=12, rule="5402")], now=T0 + timedelta(minutes=5))
    assert len(r["created"]) == 2
    incs, total = detection.list_incidents(10, 0)
    assert total == 1 and incs[0]["alert_count"] == 2 and incs[0]["severity"] == "high"
    assert len(detection.get_incident(incs[0]["id"])["alerts"]) == 2


def test_other_agent_gets_its_own_incident():
    run(fails(6, agent="001") + fails(6, agent="002", ip="198.51.100.7", start=0))
    assert detection.list_incidents(10, 0)[1] == 2


def test_status_workflow_and_retrigger_only_on_newer_events():
    a_id = run(fails(6))["created"][0]
    a, old = detection.set_alert_status(a_id, "acknowledged")
    assert old == "new" and a["status"] == "acknowledged" and a["resolved_at"] is None
    a, _ = detection.set_alert_status(a_id, "resolved")
    assert a["resolved_at"]
    assert run(fails(6))["created"] == []                      # same old events: stays resolved
    again = run(fails(6) + fails(5, start=400))                # five genuinely newer failures
    assert len(again["created"]) == 1 and detection.list_alerts(10, 0)[1] == 2


def test_vendor_scope_filters_alerts_and_incidents():
    v1, v2 = users.create("v1@t.co", "vendor"), users.create("v2@t.co", "vendor")
    vendor_agents.assign(v1["id"], "001"); vendor_agents.assign(v2["id"], "002")
    run(fails(6, agent="001") + fails(6, agent="002", ip="198.51.100.7"))
    ids1 = vendor_agents.agent_ids(v1["id"])
    a1, t1 = detection.list_alerts(10, 0, agent_ids=ids1)
    assert t1 == 1 and a1[0]["agent_id"] == "001"
    assert detection.list_incidents(10, 0, agent_ids=ids1)[1] == 1
    assert detection.list_alerts(10, 0, agent_ids=[])[1] == 0
    other = detection.list_alerts(10, 0, agent_ids=["002"])[0][0]["id"]
    try:
        detection.get_alert(other, agent_ids=ids1); raise AssertionError("vendor read another vendor's alert")
    except Exception as e:
        assert getattr(e, "status_code", None) == 404


def test_summary_counts():
    run(fails(6))
    s = detection.summary()
    assert s["open_alerts_by_severity"] == {"high": 1} and s["open_incidents"] == 1 and s["unread_notifications"] == 1
