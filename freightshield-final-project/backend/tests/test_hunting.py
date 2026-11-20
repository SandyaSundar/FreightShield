"""Phase 9 threat hunting. SIMULATED: the Wazuh Indexer is replaced by a fake returning synthetic Wazuh-shaped hits.
These prove filter->query translation, behaviour logic, correlation, MITRE mapping, RBAC and vendor isolation.
Live behaviour against a real Wazuh is checked by scripts/verify_integration.py (Phase 9 section)."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException

from app.main import app
from app.services import audit, detection, hunting, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer
from tests.helpers import auth_headers, make_user, token

T0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
_n = [0]


def doc(secs, agent="001", level=5, groups=("syslog",), rule="5700", srcip=None, user=None, path=None, mitre=None, name=None):
    _n[0] += 1
    src = {"timestamp": (T0 + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
           "agent": {"id": agent, "name": name or f"host-{agent}"}, "data": {},
           "rule": {"id": rule, "level": level, "groups": list(groups), "description": f"rule {rule}"}}
    if srcip:
        src["data"]["srcip"] = srcip
    if user:
        src["data"]["dstuser"] = user
    if path:
        src["syscheck"] = {"path": path}
    if mitre:
        src["rule"]["mitre"] = {"id": [m[0] for m in mitre], "tactic": [m[1] for m in mitre], "technique": [m[2] for m in mitre]}
    return {"_id": f"h{_n[0]}", "_source": src}


FAIL = ("syslog", "sshd", "authentication_failed")
OK = ("syslog", "sshd", "authentication_success")


def evs(docs):
    return [e for e in (hunting.to_event(d) for d in docs) if e]


def kinds(findings):
    return sorted(f["behaviour"] for f in findings)


# ---------------------------------------------------------------- filters -> OpenSearch query
def test_filters_are_validated():
    for bad in ({"hours": 0}, {"hours": 721}, {"agent_id": "1;drop"}, {"rule_id": "abc"}, {"technique": "X1"}, {"tactic": "Hacking"},
                {"src_ip": "999.1.1.1"}, {"user": "a b"}, {"group": "a/b"}, {"start": "yesterday"}, {"q": "x" * 201},
                {"start": "2026-11-20T10:00:00Z", "end": "2026-11-19T10:00:00Z"}):
        with pytest.raises(HTTPException) as e:
            hunting.clean_filters(bad)
        assert e.value.status_code == 422, bad
    f = hunting.clean_filters({"technique": "t1110.003", "tactic": "credential access", "src_ip": "203.0.113.9"})
    assert f == {"hours": 24, "technique": "T1110.003", "tactic": "Credential Access", "src_ip": "203.0.113.9"}


def test_build_query_maps_every_filter_and_vendor_scope():
    f = hunting.clean_filters({"hours": 6, "agent_id": "001", "min_level": 7, "max_level": 12, "rule_id": "5710", "group": "sshd",
                               "technique": "T1110", "tactic": "Credential Access", "src_ip": "203.0.113.9", "user": "root", "q": "ssh"})
    q = hunting.build_query(f, ["001", "002"])["bool"]
    flt = q["filter"]
    assert {"range": {"timestamp": {"gte": "now-6h"}}} in flt
    assert {"terms": {"agent.id": ["001", "002"]}} in flt
    assert {"term": {"agent.id": "001"}} in flt
    assert {"range": {"rule.level": {"gte": 7, "lte": 12}}} in flt
    for t in ({"term": {"rule.id": "5710"}}, {"term": {"rule.groups": "sshd"}}, {"term": {"rule.mitre.id": "T1110"}},
              {"term": {"rule.mitre.tactic": "Credential Access"}}):
        assert t in flt
    assert q["must"][0]["simple_query_string"]["query"] == "ssh"
    unscoped = hunting.build_query(hunting.clean_filters({}), None)["bool"]["filter"]
    assert not any("terms" in x for x in unscoped)  # admin = no agent restriction


# ---------------------------------------------------------------- behaviours (pure)
def test_quiet_activity_raises_no_behaviour():
    docs = [doc(i * 60, level=3) for i in range(30)] + [doc(i, groups=FAIL, srcip="203.0.113.9", user="bob") for i in range(2)]
    assert hunting.detect_behaviours(evs(docs)) == []


def test_password_spray_needs_five_distinct_accounts():
    four = [doc(i * 10, groups=FAIL, srcip="203.0.113.9", user=f"u{i % 4}") for i in range(12)]
    assert "password_spray" not in kinds(hunting.detect_behaviours(evs(four)))
    five = [doc(i * 10, groups=FAIL, srcip="203.0.113.9", user=f"u{i}") for i in range(5)]
    f = next(x for x in hunting.detect_behaviours(evs(five)) if x["behaviour"] == "password_spray")
    assert f["severity"] == "high" and f["mitre"][0]["id"] == "T1110.003" and len(f["accounts"]) == 5 and f["src_ip"] == "203.0.113.9"


def test_password_spray_respects_15_minute_window():
    spread = [doc(i * 300, groups=FAIL, srcip="203.0.113.9", user=f"u{i}") for i in range(5)]  # 20 min span
    assert "password_spray" not in kinds(hunting.detect_behaviours(evs(spread)))


def test_bruteforce_followed_by_success():
    two = [doc(i, groups=FAIL, srcip="198.51.100.7", user="root") for i in range(2)] + [doc(30, groups=OK, srcip="198.51.100.7", user="root")]
    assert "bruteforce_success" not in kinds(hunting.detect_behaviours(evs(two)))
    three = [doc(i, groups=FAIL, srcip="198.51.100.7", user="root") for i in range(3)] + [doc(30, groups=OK, srcip="198.51.100.7", user="root")]
    f = next(x for x in hunting.detect_behaviours(evs(three)) if x["behaviour"] == "bruteforce_success")
    assert f["severity"] == "critical" and [m["id"] for m in f["mitre"]] == ["T1110", "T1078"] and f["account"] == "root"
    late = [doc(i, groups=FAIL, srcip="198.51.100.7") for i in range(3)] + [doc(20 * 60, groups=OK, srcip="198.51.100.7")]
    assert "bruteforce_success" not in kinds(hunting.detect_behaviours(evs(late)))


def test_lateral_movement_three_agents():
    two = [doc(i * 60, agent=a, groups=OK, srcip="10.0.0.5") for i, a in enumerate(("001", "002"))]
    assert "lateral_movement" not in kinds(hunting.detect_behaviours(evs(two)))
    three = [doc(i * 60, agent=a, groups=OK, srcip="10.0.0.5") for i, a in enumerate(("001", "002", "003"))]
    f = next(x for x in hunting.detect_behaviours(evs(three)) if x["behaviour"] == "lateral_movement")
    assert f["agents"] == ["001", "002", "003"] and f["mitre"][0]["tactic"] == "Lateral Movement"


def test_privilege_escalation_sudo_failures_and_wazuh_tag():
    sudo = [doc(i * 60, groups=("syslog", "sudo", "authentication_failed"), user="alice") for i in range(3)]
    f = next(x for x in hunting.detect_behaviours(evs(sudo)) if x["behaviour"] == "privilege_escalation")
    assert f["account"] == "alice" and f["mitre"][0]["id"] == "T1548"
    low = [doc(0, level=5, mitre=[("T1548.003", "Privilege Escalation", "Sudo and Sudo Caching")])]
    assert hunting.detect_behaviours(evs(low)) == []  # tagged but below level 7
    tagged = [doc(0, level=8, mitre=[("T1548.003", "Privilege Escalation", "Sudo and Sudo Caching")])]
    f = next(x for x in hunting.detect_behaviours(evs(tagged)) if x["behaviour"] == "privilege_escalation")
    assert f["mitre"][0]["id"] == "T1548.003"  # Wazuh's own mapping wins


def test_sensitive_file_change_maps_paths_to_techniques():
    docs = [doc(0, groups=("ossec", "syscheck"), path="/etc/shadow"), doc(5, groups=("ossec", "syscheck"), path="/etc/crontab"),
            doc(9, groups=("ossec", "syscheck"), path="/var/www/index.html")]
    fs = [x for x in hunting.detect_behaviours(evs(docs)) if x["behaviour"] == "sensitive_file_change"]
    assert sorted(m["id"] for f in fs for m in f["mitre"]) == ["T1053", "T1098"]
    assert all("/var/www/index.html" not in f["paths"] for f in fs)


def test_multi_tactic_chain_on_one_agent():
    docs = [doc(0, level=6, mitre=[("T1595", "Reconnaissance", "Active Scanning")]),
            doc(600, level=6, mitre=[("T1110", "Credential Access", "Brute Force")]),
            doc(1200, level=8, mitre=[("T1059", "Execution", "Command and Scripting Interpreter")])]
    f = next(x for x in hunting.detect_behaviours(evs(docs)) if x["behaviour"] == "multi_tactic_chain")
    assert f["tactics"] == ["Reconnaissance", "Execution", "Credential Access"] and f["severity"] == "critical"
    spread = [docs[0], doc(5000, level=6, mitre=[("T1110", "Credential Access", "Brute Force")])]
    assert "multi_tactic_chain" not in kinds(hunting.detect_behaviours(evs(spread)))
    other_agent = docs[:2] + [doc(1200, agent="002", level=8, mitre=[("T1059", "Execution", "x")])]
    assert "multi_tactic_chain" not in kinds(hunting.detect_behaviours(evs(other_agent)))


# ---------------------------------------------------------------- correlation + MITRE matrix
def test_correlation_chains_split_by_gap_and_link_detection_alerts():
    det = [doc(i * 10, groups=("syslog", "authentication_failed"), rule="5710", srcip="203.0.113.9") for i in range(6)]
    detection.process([detection.normalize(d) for d in det], now=T0 + timedelta(minutes=5))
    a_id = detection.list_alerts(10, 0)[0][0]["id"]
    docs = det + [doc(100, level=12, rule="100200")] + [doc(4 * 3600, level=3)]  # last one is a separate, quiet chain
    e = evs(docs)
    chains = hunting.correlate(e, hunting.detect_behaviours(e), None)
    assert len(chains) == 1
    c = chains[0]
    assert c["agent_id"] == "001" and c["max_level"] == 12 and c["event_count"] == 7 and c["detection_alert_ids"] == [a_id]
    assert c["src_ips"] == ["203.0.113.9"] and 0 < c["score"] <= 100
    assert hunting.correlate(e, [], ["999"])[0]["detection_alert_ids"] == []  # out-of-scope agent links nothing


def test_mitre_matrix_merges_wazuh_tags_and_behaviours_in_attack_order():
    aggs = {"techniques": {"buckets": [
        {"key": "T1110", "doc_count": 40, "n": {"buckets": [{"key": "Brute Force"}]}, "tac": {"buckets": [{"key": "Credential Access"}]}},
        {"key": "T1595", "doc_count": 3, "n": {"buckets": [{"key": "Active Scanning"}]}, "tac": {"buckets": [{"key": "Reconnaissance"}]}}]}}
    findings = [{"mitre": hunting._m("T1110", "T1078")}]
    m = hunting.mitre_matrix(aggs, findings)
    assert [c["tactic"] for c in m] == ["Reconnaissance", "Initial Access", "Credential Access"]
    ca = next(c for c in m if c["tactic"] == "Credential Access")
    assert ca["techniques"][0] == {"id": "T1110", "name": "Brute Force", "wazuh_alerts": 40, "behaviour_findings": 1} and ca["count"] == 41


def test_parse_stats_reads_aggregations():
    s = hunting.parse_stats({"rules": {"buckets": [{"key": "5710", "doc_count": 9, "d": {"buckets": [{"key": "sshd fail"}]}, "lv": {"value": 5}}]},
                             "levels": {"buckets": [{"key": 3, "doc_count": 1}, {"key": 10, "doc_count": 2}]},
                             "timeline": {"buckets": [{"key": 1, "key_as_string": "2026-11-20T10:00:00.000Z", "doc_count": 4}]}})
    assert s["top_rules"] == [{"rule_id": "5710", "description": "sshd fail", "max_level": 5, "count": 9}]
    assert s["levels"] == [[10, 2], [3, 1]] and s["timeline"] == [{"t": "2026-11-20T10:00:00.000Z", "count": 4}]


# ---------------------------------------------------------------- API: RBAC, vendor isolation, audit
def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
def indexer(monkeypatch):
    docs = ([doc(i * 10, agent="001", groups=FAIL, srcip="203.0.113.9", user=f"u{i}") for i in range(6)]
            + [doc(i * 10, agent="002", groups=FAIL, srcip="198.51.100.7", user=f"v{i}") for i in range(6)])
    queries = []

    async def search(query, size=50):
        queries.append(query)
        if size == 0:
            return {"hits": {"total": {"value": len(docs)}, "hits": []}, "aggregations": {"agents": {"buckets": [{"key": "001", "doc_count": 6}]}}}
        frm = query.get("from", 0)
        return {"hits": {"total": {"value": len(docs)}, "hits": docs[frm:frm + size]}}  # ignores the scope on purpose

    monkeypatch.setattr(wazuh_indexer, "search_alerts", search)
    return queries


PATHS = ("/api/hunting/events", "/api/hunting/analysis", "/api/hunting/catalog",
         "/api/vendor/hunting/events", "/api/vendor/hunting/analysis", "/api/vendor/hunting/catalog")


@pytest.mark.anyio
async def test_hunting_requires_auth_and_role(indexer):
    async with client() as c:
        for p in PATHS:
            assert (await c.get(p)).status_code == 401, p
        for p in PATHS:
            assert (await c.get(p, headers=auth_headers("user"))).status_code == 403, p
        for p in PATHS[3:]:
            assert (await c.get(p, headers=auth_headers("admin"))).status_code == 403, p  # admin uses the admin routes
        for p in PATHS[:3]:
            assert (await c.get(p, headers=auth_headers("vendor"))).status_code == 403, p  # vendor cannot reach unscoped hunting
    assert indexer == []  # no denied request ever reached Wazuh
    denials = [r for r in audit.list_logs(100, 0, action="access_denied")[0]]
    assert len(denials) == 12


@pytest.mark.anyio
async def test_admin_analysis_finds_behaviours_and_is_audited(indexer):
    async with client() as c:
        r = await c.get("/api/hunting/analysis?hours=48&technique=T1110", headers=auth_headers("admin"))
    assert r.status_code == 200
    d = r.json()
    assert d["total_events"] == 12 and d["analyzed_events"] == 12 and d["truncated"] is False
    assert sorted(f["group"] for f in d["behaviours"] if f["behaviour"] == "password_spray") == ["198.51.100.7", "203.0.113.9"]
    assert any(c["tactic"] == "Credential Access" for c in d["mitre"])
    assert {"term": {"rule.mitre.id": "T1110"}} in indexer[0]["query"]["bool"]["filter"] and "aggs" in indexer[0]
    log = audit.list_logs(10, 0, action="hunt_analysis")[0]
    assert log and '"technique":"T1110"' in log[0]["detail"]


@pytest.mark.anyio
async def test_admin_events_paginates_and_validates(indexer):
    async with client() as c:
        r = await c.get("/api/hunting/events?limit=5&page=2", headers=auth_headers("admin"))
        bad = await c.get("/api/hunting/events?src_ip=not-an-ip", headers=auth_headers("admin"))
        window = await c.get("/api/hunting/events?limit=100&page=101", headers=auth_headers("admin"))
    assert r.status_code == 200 and r.json()["total"] == 12 and len(r.json()["items"]) == 5 and r.json()["has_more"] is True
    assert indexer[0]["from"] == 5
    assert bad.status_code == 422 and window.status_code == 422


@pytest.mark.anyio
async def test_vendor_hunting_is_scoped_to_own_agents(indexer):
    v = make_user("vendor")
    vendor_agents.assign(v["id"], "001")
    H = {"Authorization": f"Bearer {token(v['id'])}"}
    async with client() as c:
        a = await c.get("/api/vendor/hunting/analysis?hours=48", headers=H)
        ev = await c.get("/api/vendor/hunting/events?limit=100", headers=H)
        other = await c.get("/api/vendor/hunting/events?agent_id=002", headers=H)
    assert a.status_code == 200 and ev.status_code == 200
    for q in indexer:
        assert {"terms": {"agent.id": ["001"]}} in q["query"]["bool"]["filter"]
    d = a.json()
    assert d["analyzed_events"] == 6  # agent 002's events dropped even though the fake upstream returned them
    assert all(set(f["agents"]) <= {"001"} for f in d["behaviours"]) and all(c["agent_id"] == "001" for c in d["correlations"])
    assert other.status_code == 404  # another vendor's / unassigned agent


@pytest.mark.anyio
async def test_unassigned_vendor_never_calls_wazuh(indexer):
    async with client() as c:
        a = await c.get("/api/vendor/hunting/analysis", headers=auth_headers("vendor"))
        e = await c.get("/api/vendor/hunting/events", headers=auth_headers("vendor"))
    assert a.status_code == 200 and a.json()["total_events"] == 0 and a.json()["behaviours"] == []
    assert e.status_code == 200 and e.json()["items"] == []
    assert indexer == []


@pytest.mark.anyio
async def test_unconfigured_wazuh_returns_503_not_fake_data():
    async with client() as c:
        r = await c.get("/api/hunting/analysis", headers=auth_headers("admin"))
    assert r.status_code == 503 and r.json()["error"] == "not_configured"


def test_new_permissions_exist_only_on_the_right_roles():
    from app.core.roles import ROLE_PERMISSIONS
    assert "hunt:read" in ROLE_PERMISSIONS["admin"] and "vendor:hunt" in ROLE_PERMISSIONS["vendor"]
    assert not ROLE_PERMISSIONS["user"] and "hunt:read" not in ROLE_PERMISSIONS["vendor"]
