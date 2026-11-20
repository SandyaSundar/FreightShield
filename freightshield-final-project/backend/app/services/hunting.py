"""Phase 9 - Advanced threat hunting over REAL Wazuh alerts (wazuh-alerts-* in the Indexer). Nothing is synthesized.

- Filters  -> one OpenSearch bool query (build_query). Vendor scope is a `terms agent.id` filter taken from
  vendor_agents by the caller's own user id; an empty scope never reaches Wazuh (callers return an empty result).
- Stats    -> OpenSearch aggregations over the whole filtered range (exact counts, not a sample).
- Behaviours -> pure functions over the normalized events of the range (bounded by HUNT_MAX_EVENTS):
  password spray, brute force followed by success, lateral movement, privilege escalation, sensitive file change,
  multi-tactic chain. Each finding carries its MITRE ATT&CK mapping and the evidence event ids.
- Correlation -> per-agent activity chains (gap <= CHAIN_GAP) scored by tactics/levels/behaviours and linked to the
  Phase 3 detection alerts of the same agent and time span.
- MITRE matrix -> Wazuh's own rule.mitre tags (aggregated) + techniques inferred by the behaviours, in ATT&CK order.
"""
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app.core.config import get_settings
from app.core.db import connect
from app.services import detection

PAGE = 500
MAX_WINDOW = 10000
CHAIN_GAP = timedelta(minutes=30)

TACTICS = ("Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
           "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
           "Exfiltration", "Impact")
TACTIC_RANK = {t.lower(): i for i, t in enumerate(TACTICS)}

AUTH_FAIL = {"authentication_failed", "authentication_failures", "invalid_login", "win_authentication_failed"}
AUTH_OK = {"authentication_success"}
PRIV_GROUPS = {"sudo", "su"}

# Static MITRE ATT&CK mapping for the behaviours below (Wazuh's own rule.mitre tags are used as-is elsewhere).
T = {
    "T1110.003": ("Password Spraying", "Credential Access"), "T1110": ("Brute Force", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"), "T1021": ("Remote Services", "Lateral Movement"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1098": ("Account Manipulation", "Persistence"), "T1053": ("Scheduled Task/Job", "Persistence"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"), "T1543": ("Create or Modify System Process", "Persistence"),
}


def _m(*ids):
    return [{"id": i, "technique": T[i][0], "tactic": T[i][1]} for i in ids]


SENSITIVE_PATHS = [  # (regex on syscheck.path, techniques)
    (re.compile(r"^/etc/(passwd|shadow|group|gshadow)$"), ("T1098",)),
    (re.compile(r"^/etc/sudoers(\.d/.*)?$"), ("T1548", "T1098")),
    (re.compile(r"/\.ssh/authorized_keys2?$"), ("T1098",)),
    (re.compile(r"^/(etc/cron|var/spool/cron)"), ("T1053",)),
    (re.compile(r"^/etc/systemd/system/|^/lib/systemd/system/"), ("T1543",)),
    (re.compile(r"(?i)\\(software\\microsoft\\windows\\currentversion\\run(once)?)"), ("T1547",)),
    (re.compile(r"(?i)\\start menu\\programs\\startup\\"), ("T1547",)),
]

BEHAVIOURS = {  # thresholds are code defaults; documented in README
    "password_spray": {"name": "Password spraying", "severity": "high", "mitre": _m("T1110.003"),
                       "desc": "One source failed authentication against >= 5 distinct accounts within 15 min."},
    "bruteforce_success": {"name": "Brute force followed by success", "severity": "critical", "mitre": _m("T1110", "T1078"),
                           "desc": ">= 3 failed logins then a successful login from the same source on the same agent within 15 min."},
    "lateral_movement": {"name": "Possible lateral movement", "severity": "high", "mitre": _m("T1021"),
                         "desc": "One source produced authentication events on >= 3 distinct agents within 30 min."},
    "privilege_escalation": {"name": "Privilege escalation activity", "severity": "medium", "mitre": _m("T1548"),
                             "desc": ">= 3 sudo/su failures by one account in 10 min, or a Wazuh-tagged Privilege Escalation event at level >= 7."},
    "sensitive_file_change": {"name": "Sensitive file / autostart change", "severity": "high", "mitre": [],
                              "desc": "File integrity change on account, sudoers, SSH key, cron, service or autostart locations."},
    "multi_tactic_chain": {"name": "Multi-stage attack chain", "severity": "critical", "mitre": [],
                           "desc": ">= 3 distinct MITRE tactics on one agent within 60 min (Wazuh tags + behaviours)."},
}

# ---------------------------------------------------------------- filters / query
IDENT = re.compile(r"^[\w.@$\\-]{1,64}$")
GROUP = re.compile(r"^[\w.-]{1,64}$")
TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
FILTER_KEYS = ("hours", "start", "end", "agent_id", "min_level", "max_level", "rule_id", "group", "technique", "tactic", "src_ip", "user", "q")


def _ts(v: str, name: str) -> str:
    d = detection._ts(v)
    if not d:
        raise HTTPException(422, f"Invalid {name} timestamp.")
    return detection._iso(d)


def clean_filters(f: dict) -> dict:
    """Validates/normalizes user filters. Raises 422 on bad input. Unknown keys are ignored."""
    out = {k: f[k] for k in FILTER_KEYS if f.get(k) not in (None, "")}
    out["hours"] = int(out.get("hours", 24))
    if not 1 <= out["hours"] <= 720:
        raise HTTPException(422, "hours must be between 1 and 720.")
    for k in ("start", "end"):
        if k in out:
            out[k] = _ts(out[k], k)
    if "start" in out and "end" in out and out["start"] > out["end"]:
        raise HTTPException(422, "start must be before end.")
    for k in ("min_level", "max_level"):
        if k in out and not 0 <= int(out[k]) <= 15:
            raise HTTPException(422, f"{k} must be 0-15.")
    if "agent_id" in out and not re.fullmatch(r"\d{3,10}", str(out["agent_id"])):
        raise HTTPException(422, "Invalid agent_id.")
    if "rule_id" in out and not re.fullmatch(r"\d{1,8}", str(out["rule_id"])):
        raise HTTPException(422, "Invalid rule_id.")
    if "group" in out and not GROUP.fullmatch(out["group"]):
        raise HTTPException(422, "Invalid group.")
    if "technique" in out:
        out["technique"] = out["technique"].upper()
        if not TECH.fullmatch(out["technique"]):
            raise HTTPException(422, "technique must look like T1110 or T1110.003.")
    if "tactic" in out:
        match = next((t for t in TACTICS if t.lower() == out["tactic"].strip().lower()), None)
        if not match:
            raise HTTPException(422, "Unknown MITRE tactic.")
        out["tactic"] = match
    if "src_ip" in out:
        try:
            out["src_ip"] = str(ipaddress.ip_address(out["src_ip"]))
        except ValueError:
            raise HTTPException(422, "Invalid src_ip.")
    if "user" in out and not IDENT.fullmatch(out["user"]):
        raise HTTPException(422, "Invalid user.")
    if "q" in out and len(out["q"]) > 200:
        raise HTTPException(422, "q is limited to 200 characters.")
    return out


def build_query(f: dict, agent_ids: list[str] | None) -> dict:
    """OpenSearch query for cleaned filters. agent_ids=None = unscoped (admin); a list = vendor scope (never empty here)."""
    rng = {"gte": f["start"]} if "start" in f else {"gte": f"now-{f['hours']}h"}
    if "end" in f:
        rng["lte"] = f["end"]
    flt: list = [{"range": {"timestamp": rng}}]
    if agent_ids is not None:
        flt.append({"terms": {"agent.id": list(agent_ids)}})
    if "agent_id" in f:
        flt.append({"term": {"agent.id": f["agent_id"]}})
    lv = {k2: int(f[k]) for k, k2 in (("min_level", "gte"), ("max_level", "lte")) if k in f}
    if lv:
        flt.append({"range": {"rule.level": lv}})
    for k, field in (("rule_id", "rule.id"), ("group", "rule.groups"), ("technique", "rule.mitre.id"), ("tactic", "rule.mitre.tactic")):
        if k in f:
            flt.append({"term": {field: str(f[k])}})
    if "src_ip" in f:
        flt.append({"bool": {"should": [{"term": {"data.srcip": f["src_ip"]}}, {"term": {"data.src_ip": f["src_ip"]}}], "minimum_should_match": 1}})
    if "user" in f:
        flt.append({"bool": {"should": [{"term": {k: f["user"]}} for k in ("data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName")],
                             "minimum_should_match": 1}})
    must = [{"simple_query_string": {"query": f["q"], "fields": ["rule.description", "full_log"], "default_operator": "and"}}] if "q" in f else []
    return {"bool": {"filter": flt, "must": must}}


# ---------------------------------------------------------------- normalization
def to_event(hit: dict) -> dict | None:
    e = detection.normalize(hit)
    if not e:
        return None
    src = hit.get("_source") or {}
    data = src.get("data") or {}
    win = ((data.get("win") or {}).get("eventdata") or {})
    e["user"] = data.get("dstuser") or win.get("targetUserName") or data.get("srcuser")
    e["src_user"] = data.get("srcuser")
    e["src_ip"] = e["src_ip"] or data.get("src_ip") or win.get("ipAddress")
    e["path"] = (src.get("syscheck") or {}).get("path")
    return e


def public_event(e: dict) -> dict:
    return {"id": e["id"], "timestamp": detection._iso(e["ts"]), "agent_id": e["agent_id"], "agent_name": e["agent_name"],
            "rule_id": e["wazuh_rule_id"], "level": e["level"], "description": e["description"], "groups": e["groups"],
            "src_ip": e["src_ip"], "user": e["user"], "path": e.get("path"), "mitre": e["mitre"]}


# ---------------------------------------------------------------- behaviour detection (pure)
def _windows(evs, win, key_fn, need):
    """Sliding window over time-sorted evs; yields the latest window where len(set(key_fn)) >= need."""
    lo, best = 0, None
    for hi in range(len(evs)):
        while evs[hi]["ts"] - evs[lo]["ts"] > win:
            lo += 1
        if len({key_fn(e) for e in evs[lo:hi + 1]} - {None, ""}) >= need:
            best = evs[lo:hi + 1]
    return best


def _finding(key, group, evs, extra=None, mitre=None):
    b = BEHAVIOURS[key]
    agents = sorted({e["agent_id"] for e in evs})
    return {"behaviour": key, "name": b["name"], "severity": b["severity"], "description": b["desc"], "group": group,
            "mitre": mitre if mitre is not None else b["mitre"], "agents": agents, "event_count": len(evs),
            "first_seen": detection._iso(evs[0]["ts"]), "last_seen": detection._iso(evs[-1]["ts"]),
            "evidence": [e["id"] for e in evs[-20:]], **(extra or {})}


def detect_behaviours(events: list[dict]) -> list[dict]:
    evs = sorted(events, key=lambda e: e["ts"])
    is_fail = lambda e: bool(AUTH_FAIL & set(e["groups"]))
    is_ok = lambda e: bool(AUTH_OK & set(e["groups"]))
    out = []
    by_ip = defaultdict(list)
    for e in evs:
        if e["src_ip"] and (is_fail(e) or is_ok(e)):
            by_ip[e["src_ip"]].append(e)
    for ip, lst in by_ip.items():
        fails = [e for e in lst if is_fail(e)]
        w = _windows(fails, timedelta(minutes=15), lambda e: e["user"], 5)
        if w:
            out.append(_finding("password_spray", ip, w, {"src_ip": ip, "accounts": sorted({e["user"] for e in w if e["user"]})}))
        w = _windows(lst, timedelta(minutes=30), lambda e: e["agent_id"], 3)
        if w:
            out.append(_finding("lateral_movement", ip, w, {"src_ip": ip}))
        per_agent = defaultdict(list)
        for e in lst:
            per_agent[e["agent_id"]].append(e)
        for agent, ae in per_agent.items():
            hit = None
            for i, e in enumerate(ae):
                if is_ok(e):
                    prior = [x for x in ae[:i] if is_fail(x) and e["ts"] - x["ts"] <= timedelta(minutes=15)]
                    if len(prior) >= 3:
                        hit = prior + [e]
            if hit:
                out.append(_finding("bruteforce_success", f"{agent}|{ip}", hit, {"src_ip": ip, "account": hit[-1]["user"]}))
    priv = defaultdict(list)
    for e in evs:
        if PRIV_GROUPS & set(e["groups"]) and is_fail(e):
            priv[(e["agent_id"], e["user"] or e["src_user"] or "")].append(e)
    for (agent, user), lst in priv.items():
        w = next((lst[i:i + 3] for i in range(len(lst) - 2) if lst[i + 2]["ts"] - lst[i]["ts"] <= timedelta(minutes=10)), None)
        if w:
            out.append(_finding("privilege_escalation", f"{agent}|{user}", w, {"account": user or None}))
    tagged = defaultdict(list)
    for e in evs:
        if e["level"] >= 7 and any((m.get("tactic") or "").lower() == "privilege escalation" for m in e["mitre"]):
            tagged[e["agent_id"]].append(e)
    for agent, lst in tagged.items():
        out.append(_finding("privilege_escalation", f"{agent}|wazuh", lst, mitre=[m for m in lst[-1]["mitre"]] or None))
    fim = defaultdict(list)
    for e in evs:
        p = e.get("path")
        if p and "syscheck" in e["groups"]:
            techs = next((t for rx, t in SENSITIVE_PATHS if rx.search(p)), None)
            if techs:
                fim[(e["agent_id"], techs)].append(e)
    for (agent, techs), lst in fim.items():
        out.append(_finding("sensitive_file_change", agent, lst, {"paths": sorted({e["path"] for e in lst})[:20]}, mitre=_m(*techs)))
    # multi-tactic chain: Wazuh MITRE tags + the tactics of the findings above, per agent, 60 min window
    marks = defaultdict(list)  # agent -> [(ts, tactic, event_id)]
    for e in evs:
        for m in e["mitre"]:
            if m.get("tactic"):
                marks[e["agent_id"]].append((e["ts"], m["tactic"], e))
    ev_by_id = {e["id"]: e for e in evs}
    for f in out:
        for m in f["mitre"]:
            for a in f["agents"]:
                for eid in f["evidence"]:
                    if eid in ev_by_id and ev_by_id[eid]["agent_id"] == a:
                        marks[a].append((ev_by_id[eid]["ts"], m["tactic"], ev_by_id[eid]))
    for agent, ms in marks.items():
        ms.sort(key=lambda x: x[0])
        lo, best = 0, None
        for hi in range(len(ms)):
            while ms[hi][0] - ms[lo][0] > timedelta(minutes=60):
                lo += 1
            tac = {m[1] for m in ms[lo:hi + 1]}
            if len(tac) >= 3:
                best = (ms[lo:hi + 1], tac)
        if best:
            chain_evs = sorted({id(m[2]): m[2] for m in best[0]}.values(), key=lambda e: e["ts"])
            out.append(_finding("multi_tactic_chain", agent, chain_evs, {"tactics": sorted(best[1], key=lambda t: TACTIC_RANK.get(t.lower(), 99))},
                                mitre=[]))
    out.sort(key=lambda f: (detection.RANK[f["severity"]], f["last_seen"]), reverse=True)
    return out


# ---------------------------------------------------------------- correlation
def correlate(events: list[dict], findings: list[dict], agent_ids: list[str] | None) -> list[dict]:
    """Per-agent activity chains: consecutive events with gaps <= CHAIN_GAP. Kept when they show >= 2 tactics,
    a Wazuh level >= 10, or a behaviour finding. Linked to Phase 3 detection alerts of the same agent/time span."""
    per = defaultdict(list)
    for e in sorted(events, key=lambda e: e["ts"]):
        per[e["agent_id"]].append(e)
    chains = []
    for agent, evs in per.items():
        cur = [evs[0]]
        for e in evs[1:] + [None]:
            if e is not None and e["ts"] - cur[-1]["ts"] <= CHAIN_GAP:
                cur.append(e)
                continue
            first, last = detection._iso(cur[0]["ts"]), detection._iso(cur[-1]["ts"])
            ids = {x["id"] for x in cur}
            fs = [f for f in findings if agent in f["agents"] and ids & set(f["evidence"])]
            tactics = {m["tactic"] for x in cur for m in x["mitre"] if m.get("tactic")} | {m["tactic"] for f in fs for m in f["mitre"]}
            max_level = max(x["level"] for x in cur)
            if len(tactics) >= 2 or max_level >= 10 or fs:
                score = min(100, 12 * len(tactics) + 3 * max_level + 15 * len(fs) + min(len(cur), 20))
                chains.append({"agent_id": agent, "agent_name": cur[-1]["agent_name"], "first_seen": first, "last_seen": last,
                               "event_count": len(cur), "max_level": max_level, "score": score,
                               "risk": "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low",
                               "tactics": sorted(tactics, key=lambda t: TACTIC_RANK.get(t.lower(), 99)),
                               "rules": sorted({x["wazuh_rule_id"] for x in cur})[:20],
                               "src_ips": sorted({x["src_ip"] for x in cur if x["src_ip"]})[:20],
                               "users": sorted({x["user"] for x in cur if x["user"]})[:20],
                               "behaviours": sorted({f["behaviour"] for f in fs}),
                               "detection_alert_ids": _linked_alerts(agent, first, last, agent_ids)})
            cur = [e] if e is not None else []
    chains.sort(key=lambda c: (-c["score"], c["last_seen"]))
    return chains


def _linked_alerts(agent, first, last, agent_ids) -> list[int]:
    if agent_ids is not None and agent not in agent_ids:
        return []
    with connect() as c:
        return [r[0] for r in c.execute("SELECT id FROM detection_alerts WHERE agent_id=? AND last_seen>=? AND first_seen<=? ORDER BY id",
                                        (agent, first, last))][:50]


# ---------------------------------------------------------------- MITRE matrix + stats
def _buckets(aggs, name):
    return (aggs.get(name) or {}).get("buckets", [])


def stats_aggs(hours: int) -> dict:
    interval = "1h" if hours <= 48 else "6h" if hours <= 168 else "1d"
    t = lambda field, n=10: {"terms": {"field": field, "size": n}}
    return {"rules": {**t("rule.id"), "aggs": {"d": t("rule.description", 1), "lv": {"max": {"field": "rule.level"}}}},
            "agents": {**t("agent.id"), "aggs": {"n": t("agent.name", 1)}},
            "src_ips": t("data.srcip"), "users": t("data.dstuser"), "levels": t("rule.level", 16), "groups": t("rule.groups", 15),
            "tactics": t("rule.mitre.tactic", 20),
            "techniques": {**t("rule.mitre.id", 50), "aggs": {"n": t("rule.mitre.technique", 1), "tac": t("rule.mitre.tactic", 5)}},
            "timeline": {"date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0}}}


def parse_stats(aggs: dict) -> dict:
    first = lambda b, k: (_buckets(b, k) or [{}])[0].get("key")
    return {"top_rules": [{"rule_id": b["key"], "description": first(b, "d"), "max_level": (b.get("lv") or {}).get("value"), "count": b["doc_count"]} for b in _buckets(aggs, "rules")],
            "top_agents": [{"agent_id": b["key"], "agent_name": first(b, "n"), "count": b["doc_count"]} for b in _buckets(aggs, "agents")],
            "top_src_ips": [{"value": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "src_ips")],
            "top_users": [{"value": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "users")],
            "levels": sorted(([int(b["key"]), b["doc_count"]] for b in _buckets(aggs, "levels")), reverse=True),
            "groups": [{"value": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "groups")],
            "timeline": [{"t": b.get("key_as_string") or b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "timeline")]}


def mitre_matrix(aggs: dict, findings: list[dict]) -> list[dict]:
    cols: dict[str, dict] = {}

    def add(tactic, tid, name, n, source):
        col = cols.setdefault(tactic, {"tactic": tactic, "count": 0, "techniques": {}})
        tech = col["techniques"].setdefault(tid, {"id": tid, "name": name, "wazuh_alerts": 0, "behaviour_findings": 0})
        tech["name"] = tech["name"] or name
        tech["wazuh_alerts" if source == "wazuh" else "behaviour_findings"] += n
        col["count"] += n

    for b in _buckets(aggs, "techniques"):
        name = (_buckets(b, "n") or [{}])[0].get("key")
        for tb in _buckets(b, "tac") or [{"key": "Unknown"}]:
            add(tb["key"], b["key"], name, b["doc_count"], "wazuh")
    for f in findings:
        for m in f["mitre"]:
            add(m["tactic"], m["id"], m["technique"], 1, "behaviour")
    out = [{**c, "techniques": sorted(c["techniques"].values(), key=lambda x: -(x["wazuh_alerts"] + x["behaviour_findings"]))} for c in cols.values()]
    return sorted(out, key=lambda c: TACTIC_RANK.get(c["tactic"].lower(), 99))


# ---------------------------------------------------------------- Wazuh calls
def _total(data) -> int:
    t = data.get("hits", {}).get("total", {})
    return t.get("value", 0) if isinstance(t, dict) else int(t or 0)


async def events(search, f: dict, agent_ids, limit: int, page: int) -> dict:
    offset = (page - 1) * limit
    if offset + limit > MAX_WINDOW:
        raise HTTPException(422, f"page*limit exceeds the {MAX_WINDOW} result window.")
    data = await search({"query": build_query(f, agent_ids), "from": offset, "track_total_hits": True,
                         "sort": [{"timestamp": {"order": "desc"}}]}, size=limit)
    evs = [e for e in (to_event(h) for h in data.get("hits", {}).get("hits", [])) if e]
    total = _total(data)
    return {"items": [public_event(e) for e in evs], "total": total, "page": page, "limit": limit,
            "has_more": offset + len(evs) < total}


async def analysis(search, f: dict, agent_ids) -> dict:
    """Aggregations over the full filtered range + behaviour/correlation analysis over up to HUNT_MAX_EVENTS events."""
    cap = min(get_settings().hunt_max_events, MAX_WINDOW)
    q = build_query(f, agent_ids)
    agg = await search({"query": q, "track_total_hits": True, "aggs": stats_aggs(f["hours"])}, size=0)
    total, evs, frm = _total(agg), [], 0
    while frm < min(total, cap):
        data = await search({"query": q, "from": frm, "sort": [{"timestamp": {"order": "desc"}}]}, size=min(PAGE, cap - frm))
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break
        evs += [e for e in (to_event(h) for h in hits) if e]
        frm += len(hits)
    if agent_ids is not None:  # defence in depth: drop anything outside the vendor scope even if the upstream misbehaved
        evs = [e for e in evs if e["agent_id"] in agent_ids]
    findings = detect_behaviours(evs)
    aggs = agg.get("aggregations") or {}
    return {"filters": f, "total_events": total, "analyzed_events": len(evs), "truncated": total > len(evs),
            "stats": parse_stats(aggs), "mitre": mitre_matrix(aggs, findings), "behaviours": findings,
            "correlations": correlate(evs, findings, agent_ids)[:50]}


def empty_analysis(f: dict) -> dict:
    return {"filters": f, "total_events": 0, "analyzed_events": 0, "truncated": False,
            "stats": parse_stats({}), "mitre": [], "behaviours": [], "correlations": []}


def catalog() -> dict:
    return {"tactics": list(TACTICS), "behaviours": [{"key": k, "name": b["name"], "severity": b["severity"], "description": b["desc"],
                                                       "mitre": b["mitre"]} for k, b in BEHAVIOURS.items()],
            "filters": list(FILTER_KEYS)}


def audit_detail(f: dict) -> str:
    return json.dumps({k: v for k, v in f.items()}, separators=(",", ":"))[:400]
