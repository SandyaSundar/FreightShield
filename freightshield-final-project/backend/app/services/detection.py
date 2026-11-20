"""Rule-based detection over REAL Wazuh alerts (read from the Indexer). Nothing here invents events.

Pipeline: fetch (scan) -> normalize -> evaluate rules (threshold within a sliding window, grouped) -> upsert alerts
(dedupe by rule+group key) -> correlate into incidents (same agent within CORRELATION_WINDOW) -> notify admins -> audit.
Thresholds/severity/window/enabled live in SQLite (detection_rules) and are admin-configurable.
Scope: alerts and incidents are keyed by Wazuh agent_id so vendor isolation (vendor_agents) is a simple filter.
"""
import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app.core.config import get_settings
from app.core.db import connect
from app.services import audit, notifications

SEVERITIES = ("low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
ALERT_STATUSES = ("new", "acknowledged", "investigating", "resolved", "false_positive")
CLOSED = ("resolved", "false_positive")
INCIDENT_STATUSES = ("open", "investigating", "resolved")
CORRELATION_WINDOW = timedelta(minutes=30)
SYSTEM = {"id": None, "email": "system"}
PAGE = 500
T1110 = {"id": "T1110", "tactic": "Credential Access", "technique": "Brute Force"}

# Code-defined rule logic; the numbers below are only DEFAULTS (seeded into SQLite, then admin-editable).
RULES = {
    "auth_bruteforce": {
        "name": "Repeated authentication failures", "group_by": ("agent_id", "src_ip"), "mitre": [T1110],
        "match": lambda e: bool({"authentication_failed", "authentication_failures"} & set(e["groups"])),
        "defaults": {"threshold": 5, "window_seconds": 300, "severity": "high", "min_level": 0}},
    "high_level_event": {
        "name": "High-severity Wazuh event", "group_by": ("agent_id", "wazuh_rule_id"), "mitre": [],
        "match": lambda e: True,  # threshold = count, min_level = minimum Wazuh rule.level
        "defaults": {"threshold": 1, "window_seconds": 300, "severity": "high", "min_level": 10}},
    "fim_burst": {
        "name": "Burst of file integrity changes", "group_by": ("agent_id",), "mitre": [],
        "match": lambda e: "syscheck" in e["groups"],
        "defaults": {"threshold": 10, "window_seconds": 300, "severity": "medium", "min_level": 0}},
}


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _ts(v) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _list(v) -> list[str]:
    return [] if v is None else [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]


# ---------------------------------------------------------------- normalization
def normalize(hit: dict) -> dict | None:
    """Wazuh alert document ({_id,_source}) -> flat event. Returns None if it lacks a timestamp or rule id."""
    src = hit.get("_source") or {}
    ts = _ts(src.get("timestamp") or src.get("@timestamp"))
    rule, agent, data = src.get("rule") or {}, src.get("agent") or {}, src.get("data") or {}
    if not ts or not rule.get("id") or not agent.get("id"):
        return None
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    m = rule.get("mitre") or {}
    ids, tac, tech = _list(m.get("id")), _list(m.get("tactic")), _list(m.get("technique"))
    return {"id": hit.get("_id"), "ts": ts.astimezone(timezone.utc), "agent_id": str(agent["id"]),
            "agent_name": agent.get("name"), "level": level, "wazuh_rule_id": str(rule["id"]),
            "description": rule.get("description"), "groups": _list(rule.get("groups")),
            "src_ip": data.get("srcip") or (src.get("srcip")), "user": data.get("dstuser"),
            "mitre": [{"id": i, "tactic": tac[j] if j < len(tac) else None, "technique": tech[j] if j < len(tech) else None}
                      for j, i in enumerate(ids)]}


def _evidence(e: dict) -> dict:
    return {"id": e["id"], "timestamp": _iso(e["ts"]), "wazuh_rule_id": e["wazuh_rule_id"], "level": e["level"],
            "description": e["description"], "src_ip": e["src_ip"], "user": e["user"], "agent_id": e["agent_id"]}


# ---------------------------------------------------------------- rule configuration
def load_rules() -> list[dict]:
    with connect() as c:
        for k, r in RULES.items():
            d = r["defaults"]
            c.execute("INSERT OR IGNORE INTO detection_rules (rule_key, enabled, threshold, window_seconds, severity, min_level)"
                      " VALUES (?,1,?,?,?,?)", (k, d["threshold"], d["window_seconds"], d["severity"], d["min_level"]))
        rows = c.execute("SELECT * FROM detection_rules ORDER BY rule_key").fetchall()
    return [{**dict(r), "enabled": bool(r["enabled"]), "name": RULES[r["rule_key"]]["name"],
             "mitre": RULES[r["rule_key"]]["mitre"]} for r in rows if r["rule_key"] in RULES]


def update_rule(rule_key: str, **changes) -> dict:
    load_rules()
    changes = {k: v for k, v in changes.items() if v is not None}
    with connect() as c:
        if not c.execute("SELECT 1 FROM detection_rules WHERE rule_key=?", (rule_key,)).fetchone():
            raise HTTPException(404, "Unknown detection rule.")
        if changes:
            if "enabled" in changes:
                changes["enabled"] = int(changes["enabled"])
            c.execute(f"UPDATE detection_rules SET {', '.join(k + '=?' for k in changes)} WHERE rule_key=?",
                      [*changes.values(), rule_key])
    return next(r for r in load_rules() if r["rule_key"] == rule_key)


# ---------------------------------------------------------------- evaluation (pure)
def evaluate(events: list[dict], rules: dict[str, dict]) -> list[dict]:
    """Sliding-window threshold per group. Returns one trigger per (rule, group) that meets its threshold."""
    out = []
    for rk, r in rules.items():
        if not r["enabled"] or rk not in RULES:
            continue
        meta, groups = RULES[rk], defaultdict(list)
        for e in events:
            if e["level"] >= r["min_level"] and meta["match"](e):
                groups[tuple(e.get(f) or "" for f in meta["group_by"])].append(e)
        win = timedelta(seconds=r["window_seconds"])
        for key, evs in groups.items():
            evs.sort(key=lambda e: e["ts"])
            lo, hit = 0, None
            for hi in range(len(evs)):
                while evs[hi]["ts"] - evs[lo]["ts"] > win:
                    lo += 1
                if hi - lo + 1 >= r["threshold"]:
                    hit = (lo, hi)  # keep the latest qualifying window
            if hit:
                out.append({"rule_key": rk, "rule": r, "key": "|".join(key), "events": evs[hit[0]:hit[1] + 1]})
    return out


# ---------------------------------------------------------------- alert generation / dedupe / correlation
def _attach_incident(c, aid, agent_id, agent_name, severity, mitre, title, first, last, now) -> int:
    inc = c.execute("SELECT * FROM incidents WHERE agent_id=? AND status IN ('open','investigating') AND last_activity>=?"
                    " ORDER BY id DESC LIMIT 1", (agent_id, _iso(first - CORRELATION_WINDOW))).fetchone()
    if not inc:
        cur = c.execute("INSERT INTO incidents (title, severity, agent_id, alert_count, mitre, created_at, last_activity, updated_at)"
                        " VALUES (?,?,?,1,?,?,?,?)", (title, severity, agent_id, json.dumps(mitre), _iso(now), _iso(last), _iso(now)))
        return cur.lastrowid
    merged = {m["id"]: m for m in [*json.loads(inc["mitre"]), *mitre]}
    n = c.execute("SELECT COUNT(*) FROM detection_alerts WHERE incident_id=?", (inc["id"],)).fetchone()[0] + 1
    sev = max(inc["severity"], severity, key=RANK.get)
    c.execute("UPDATE incidents SET title=?, severity=?, alert_count=?, mitre=?, last_activity=?, updated_at=? WHERE id=?",
              (f"Related detections on {agent_name or agent_id}", sev, n, json.dumps(list(merged.values())),
               max(inc["last_activity"], _iso(last)), _iso(now), inc["id"]))
    return inc["id"]


def process(events: list[dict], now: datetime | None = None) -> dict:
    """Evaluate rules over normalized events and persist alerts/incidents/notifications. Idempotent on re-scan."""
    now = now or datetime.now(timezone.utc)
    rules = {r["rule_key"]: r for r in load_rules()}
    notify_min = RANK.get(get_settings().detection_notify_min_severity, 1)
    created, updated, audits = [], [], []
    with connect() as c:
        for t in evaluate(events, rules):
            key, rk, r = f"{t['rule_key']}|{t['key']}", t["rule_key"], t["rule"]
            evs = t["events"]
            row = c.execute("SELECT * FROM detection_alerts WHERE dedupe_key=? ORDER BY id DESC LIMIT 1", (key,)).fetchone()
            if row and row["status"] not in CLOSED:  # duplicate: refresh the open alert instead of creating another
                last = evs[-1]["ts"]
                if _iso(last) > row["last_seen"] or len(evs) > row["event_count"]:
                    c.execute("UPDATE detection_alerts SET event_count=?, last_seen=?, evidence=?, updated_at=? WHERE id=?",
                              (max(row["event_count"], len(evs)), max(row["last_seen"], _iso(last)),
                               json.dumps([_evidence(e) for e in evs[-10:]]), _iso(now), row["id"]))
                    c.execute("UPDATE incidents SET last_activity=MAX(last_activity,?), updated_at=? WHERE id=?",
                              (_iso(last), _iso(now), row["incident_id"]))
                    updated.append(row["id"])
                continue
            if row:  # closed before: only events newer than the closed alert can re-trigger it
                evs = [e for e in evs if _iso(e["ts"]) > row["last_seen"]]
                if len(evs) < r["threshold"]:
                    continue
            last, first, tail = evs[-1], evs[0], evs[-1]
            mitre = list({m["id"]: m for e in evs for m in e["mitre"]}.values()) or RULES[rk]["mitre"]
            title = f"{r['name']} on {tail['agent_name'] or tail['agent_id']}" + (f" from {tail['src_ip']}" if tail["src_ip"] and rk == "auth_bruteforce" else "")
            iid = _attach_incident(c, None, tail["agent_id"], tail["agent_name"], r["severity"], mitre, title, first["ts"], last["ts"], now)
            cur = c.execute("INSERT INTO detection_alerts (dedupe_key, rule_key, title, severity, agent_id, agent_name, src_ip,"
                            " event_count, first_seen, last_seen, mitre, evidence, incident_id, created_at, updated_at)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (key, rk, title, r["severity"], tail["agent_id"], tail["agent_name"], tail["src_ip"], len(evs),
                             _iso(first["ts"]), _iso(last["ts"]), json.dumps(mitre), json.dumps([_evidence(e) for e in evs[-10:]]),
                             iid, _iso(now), _iso(now)))
            aid = cur.lastrowid
            created.append(aid)
            if RANK[r["severity"]] >= notify_min:
                # one notification per detection event: critical > brand-new incident > plain alert (Phase 8 categories)
                new_inc = c.execute("SELECT alert_count FROM incidents WHERE id=?", (iid,)).fetchone()[0] == 1
                cat = "critical_alert" if r["severity"] == "critical" else "new_incident" if new_inc else "alert"
                msg = f"{'Opened new incident' if new_inc else 'Added to incident'} #{iid} on agent {tail['agent_name'] or tail['agent_id']}; {len(evs)} matching event(s)."
                nid = notifications.emit(c, category=cat, severity=r["severity"], title=title, message=msg, dedupe_key=f"alert:{aid}",
                                         alert_id=aid, incident_id=iid, agent_ids=[tail["agent_id"]], now=_iso(now))
                if nid:
                    audits.append(("notification_create", f"notification:{nid}", f"category={cat} severity={r['severity']} level=0"))
            audits.append(("alert_create", f"alert:{aid}", f"rule={rk} severity={r['severity']} agent={tail['agent_id']} events={len(evs)} incident={iid}"))
    for action, target, detail in audits:  # after the transaction: audit.record opens its own connection
        audit.record(SYSTEM, action, target, detail=detail)
    return {"events": len(events), "triggers": len(created) + len(updated), "created": created, "updated": updated}


async def scan(search, actor: dict | None = None) -> dict:
    """Pull recent REAL alerts from the Indexer (`search` = wazuh_indexer.search_alerts) and run detection."""
    s, rules = get_settings(), load_rules()
    lookback = max([s.detection_lookback_seconds] + [r["window_seconds"] for r in rules if r["enabled"]])
    events, frm, truncated = [], 0, False
    while True:
        data = await search({"query": {"range": {"timestamp": {"gte": f"now-{lookback}s"}}}, "from": frm, "track_total_hits": True,
                             "sort": [{"timestamp": {"order": "asc"}}]}, size=PAGE)
        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {})
        total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        events += [e for e in (normalize(h) for h in hits) if e]
        frm += len(hits)
        if not hits or frm >= total:
            break
        if frm >= min(s.detection_max_events, 10000 - PAGE):
            truncated = True
            break
    res = {**process(events), "lookback_seconds": lookback, "truncated": truncated}
    audit.record(actor or SYSTEM, "detection_scan", "wazuh-alerts-*", detail=f"events={res['events']} created={len(res['created'])} updated={len(res['updated'])} truncated={truncated}")
    try:  # Phase 8: overdue/escalation checks + email outbox after every scan; never lets a notification problem fail the scan
        await asyncio.to_thread(notifications.run_cycle)
    except Exception as e:  # noqa: BLE001
        logging.getLogger("freightshield.notify").warning("post-scan notification cycle failed: %s", type(e).__name__)
    return res


# ---------------------------------------------------------------- queries (agent_ids != None => vendor scope)
def _a(row, full=False) -> dict:
    d = {**dict(row), "mitre": json.loads(row["mitre"])}
    d["evidence"] = json.loads(row["evidence"]) if full else None
    if not full:
        del d["evidence"]
    return d


def _scope(where: list, args: list, agent_ids) -> bool:
    if agent_ids is None:
        return True
    if not agent_ids:
        return False
    where.append(f"agent_id IN ({','.join('?' * len(agent_ids))})")
    args.extend(agent_ids)
    return True


def list_alerts(limit, offset, status=None, severity=None, agent_id=None, agent_ids=None):
    where, args = [], []
    if not _scope(where, args, agent_ids):
        return [], 0
    for col, val in (("status", status), ("severity", severity), ("agent_id", agent_id)):
        if val:
            where.append(f"{col}=?"), args.append(val)
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM detection_alerts{w}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM detection_alerts{w} ORDER BY id DESC LIMIT ? OFFSET ?", [*args, limit, offset])
        return [_a(r) for r in rows], total


def get_alert(alert_id: int, agent_ids=None) -> dict:
    with connect() as c:
        row = c.execute("SELECT * FROM detection_alerts WHERE id=?", (alert_id,)).fetchone()
    if not row or (agent_ids is not None and row["agent_id"] not in agent_ids):
        raise HTTPException(404, "Alert not found.")
    return _a(row, full=True)


def set_alert_status(alert_id: int, status: str) -> tuple[dict, str]:
    if status not in ALERT_STATUSES or status == "new":
        raise HTTPException(422, "Invalid status.")
    with connect() as c:
        row = c.execute("SELECT * FROM detection_alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Alert not found.")
        now = _iso(datetime.now(timezone.utc))
        # acknowledged_at = first analyst action on the alert (any status change) -> MTTA; kept even if status changes again
        c.execute("UPDATE detection_alerts SET status=?, updated_at=?, resolved_at=?, acknowledged_at=COALESCE(acknowledged_at, ?) WHERE id=?",
                  (status, now, now if status in CLOSED else None, now, alert_id))
    return get_alert(alert_id), row["status"]


def list_incidents(limit, offset, status=None, agent_ids=None):
    where, args = [], []
    if not _scope(where, args, agent_ids):
        return [], 0
    if status:
        where.append("status=?"), args.append(status)
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM incidents{w}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM incidents{w} ORDER BY last_activity DESC LIMIT ? OFFSET ?", [*args, limit, offset])
        return [{**dict(r), "mitre": json.loads(r["mitre"])} for r in rows], total


def get_incident(incident_id: int, agent_ids=None) -> dict:
    with connect() as c:
        row = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row or (agent_ids is not None and row["agent_id"] not in agent_ids):
            raise HTTPException(404, "Incident not found.")
        alerts = [_a(r) for r in c.execute("SELECT * FROM detection_alerts WHERE incident_id=? ORDER BY id", (incident_id,))]
    return {**dict(row), "mitre": json.loads(row["mitre"]), "alerts": alerts}


def set_incident_status(incident_id: int, status: str) -> tuple[dict, str]:
    if status not in INCIDENT_STATUSES:
        raise HTTPException(422, "Invalid status.")
    old = get_incident(incident_id)["status"]
    with connect() as c:
        now = _iso(datetime.now(timezone.utc))
        c.execute("UPDATE incidents SET status=?, updated_at=?, resolved_at=? WHERE id=?",
                  (status, now, now if status == "resolved" else None, incident_id))
    return get_incident(incident_id), old


def summary(user_id: int | None = None) -> dict:
    unread = notifications.summary(user_id)["unread"]
    with connect() as c:
        q = lambda sql: {r[0]: r[1] for r in c.execute(sql)}
        return {"open_alerts_by_severity": q("SELECT severity, COUNT(*) FROM detection_alerts WHERE status NOT IN ('resolved','false_positive') GROUP BY severity"),
                "alerts_by_status": q("SELECT status, COUNT(*) FROM detection_alerts GROUP BY status"),
                "open_incidents": c.execute("SELECT COUNT(*) FROM incidents WHERE status!='resolved'").fetchone()[0],
                "unread_notifications": unread}


def list_notifications(limit, offset, unread_only=False):
    """Phase 3 entry point (shared/global read state). Phase 8 per-user views live in app/services/notifications.py."""
    return notifications.list_notifications(limit, offset, unread_only)


def mark_read(nid: int) -> None:
    notifications.mark_read(nid)
