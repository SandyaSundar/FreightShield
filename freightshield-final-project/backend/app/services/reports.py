"""Phase 7 SOC reports & analytics. Everything is computed from the real tables of Phases 1-6 (detection_alerts, incidents,
ir_actions, iocs); nothing is sampled, estimated or invented. Scope: agent_ids=None -> admin (all data); a list -> vendor
(only rows on those agents; an empty list yields an empty report, never everything).
MTTA = mean(first analyst action - alert created); MTTR = mean(resolved - created) for resolved alerts / incidents.
Rows that predate the timestamps (acknowledged_at / incident resolved_at) are counted in `data_quality`, never guessed."""
import csv
import io
import json
from datetime import datetime, timedelta, timezone

from app.core.db import connect
from app.services import audit, pdf_min, threat_intel

SEVERITIES = ("low", "medium", "high", "critical")
MAX_ROWS = 10000
DATASETS = ("summary", "alerts", "incidents")


# ---------------------------------------------------------------- pure helpers
def parse(v) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def duration_stats(pairs: list[tuple]) -> dict:
    """pairs of (start, end) ISO strings -> {count, mean_seconds, median_seconds, max_seconds}; negative/invalid pairs are dropped."""
    ds = sorted(s for s in ((parse(b) - parse(a)).total_seconds() if parse(a) and parse(b) else None for a, b in pairs) if s is not None and s >= 0)
    if not ds:
        return {"count": 0, "mean_seconds": None, "median_seconds": None, "max_seconds": None}
    mid = len(ds) // 2
    med = ds[mid] if len(ds) % 2 else (ds[mid - 1] + ds[mid]) / 2
    return {"count": len(ds), "mean_seconds": round(sum(ds) / len(ds), 1), "median_seconds": round(med, 1), "max_seconds": round(ds[-1], 1)}


def trend(rows: list[dict], since: datetime, until: datetime, field: str = "created_at") -> list[dict]:
    """Daily UTC buckets (zero-filled) of counts by severity."""
    days, d = [], since.astimezone(timezone.utc).date()
    while d <= until.astimezone(timezone.utc).date():
        days.append(d)
        d += timedelta(days=1)
    b = {x.isoformat(): {"date": x.isoformat(), "total": 0, **{s: 0 for s in SEVERITIES}} for x in days}
    for r in rows:
        t = parse(r[field])
        k = t.astimezone(timezone.utc).date().isoformat() if t else None
        if k in b:
            b[k]["total"] += 1
            if r["severity"] in SEVERITIES:
                b[k][r["severity"]] += 1
    return list(b.values())


def count_by(rows: list[dict], key: str, order=None) -> dict:
    out: dict = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return {k: out[k] for k in (order or sorted(out)) if k in out} if order else dict(sorted(out.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------- data access
def _scoped(table: str, since: str, agent_ids) -> list[dict]:
    if agent_ids is not None and not agent_ids:
        return []
    q, a = f"SELECT * FROM {table} WHERE created_at>=?", [since]
    if agent_ids is not None:
        q += f" AND agent_id IN ({','.join('?' * len(agent_ids))})"
        a += list(agent_ids)
    with connect() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY created_at DESC LIMIT ?", [*a, MAX_ROWS])]


def build(days: int = 30, agent_ids=None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    alerts, incidents = _scoped("detection_alerts", since.isoformat(), agent_ids), _scoped("incidents", since.isoformat(), agent_ids)
    ir = _scoped("ir_actions", since.isoformat(), agent_ids)
    resolved_a = [a for a in alerts if a["status"] == "resolved" and a["resolved_at"]]
    acked = [a for a in alerts if a["acknowledged_at"]]
    resolved_i = [i for i in incidents if i["status"] == "resolved" and i["resolved_at"]]
    legacy_a = sum(1 for a in alerts if a["status"] != "new" and not a["acknowledged_at"])
    legacy_i = sum(1 for i in incidents if i["status"] == "resolved" and not i["resolved_at"])
    iocs, ioc_total = threat_intel.list_iocs(10000, 0, agent_ids=agent_ids)
    agents: dict = {}
    for a in alerts:
        k = a["agent_name"] or a["agent_id"]
        agents[k] = agents.get(k, 0) + 1
    return {
        "generated_at": now.isoformat(timespec="seconds"), "window": {"days": days, "from": since.isoformat(timespec="seconds"), "to": now.isoformat(timespec="seconds")},
        "scope": "all agents" if agent_ids is None else f"{len(agent_ids)} assigned agent(s)",
        "totals": {"alerts": len(alerts), "incidents": len(incidents),
                   "open_alerts": sum(1 for a in alerts if a["status"] not in ("resolved", "false_positive")),
                   "open_incidents": sum(1 for i in incidents if i["status"] != "resolved"),
                   "critical_high_alerts": sum(1 for a in alerts if a["severity"] in ("critical", "high")), "false_positives": sum(1 for a in alerts if a["status"] == "false_positive")},
        "alerts_by_severity": count_by(alerts, "severity", SEVERITIES), "incidents_by_severity": count_by(incidents, "severity", SEVERITIES),
        "alerts_by_status": count_by(alerts, "status"), "incidents_by_status": count_by(incidents, "status"),
        "alert_trend": trend(alerts, since, now), "incident_trend": trend(incidents, since, now),
        "metrics": {"mtta": duration_stats([(a["created_at"], a["acknowledged_at"]) for a in acked]),
                    "mttr_alerts": duration_stats([(a["created_at"], a["resolved_at"]) for a in resolved_a]),
                    "mttr_incidents": duration_stats([(i["created_at"], i["resolved_at"]) for i in resolved_i])},
        "data_quality": {"alerts_without_ack_time": legacy_a, "resolved_incidents_without_time": legacy_i,
                         "note": "Alerts/incidents actioned before Phase 7 have no timestamp and are excluded from MTTA/MTTR, not estimated."},
        "top_agents": [{"agent": k, "alerts": v} for k, v in sorted(agents.items(), key=lambda kv: -kv[1])[:10]],
        "top_rules": [{"rule": k, "alerts": v} for k, v in count_by(alerts, "rule_key").items()][:10],
        "response_actions": count_by(ir, "status"),
        "threat_intel": {"iocs": ioc_total, "by_classification": count_by(iocs, "classification"), "by_risk": count_by(iocs, "risk"),
                         "top": [{k: i[k] for k in ("type", "value", "score", "risk")} for i in iocs[:5]]},
    }


# ---------------------------------------------------------------- exports
def _safe(v):
    """CSV/formula-injection guard: cells starting with = + - @ (or tab/CR) are prefixed so spreadsheets never evaluate them."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _csv(rows: list[list], heads: list[str]) -> bytes:
    f = io.StringIO()
    w = csv.writer(f)
    w.writerow(heads)
    for r in rows:
        w.writerow([_safe(x) for x in r])
    return ("\ufeff" + f.getvalue()).encode("utf-8")


def _fmt_s(s) -> str:
    return "n/a" if s is None else f"{s / 3600:.2f} h" if s >= 3600 else f"{s / 60:.1f} min"


def summary_rows(r: dict) -> list[list]:
    rows = [["window", "days", r["window"]["days"]], ["scope", "", r["scope"]]]
    rows += [["totals", k, v] for k, v in r["totals"].items()]
    for sec in ("alerts_by_severity", "incidents_by_severity", "alerts_by_status", "incidents_by_status", "response_actions"):
        rows += [[sec, k, v] for k, v in r[sec].items()]
    for name, m in r["metrics"].items():
        rows += [[name, k, "" if v is None else v] for k, v in m.items()]
    rows += [["threat_intel", "iocs", r["threat_intel"]["iocs"]]] + [["threat_intel_class", k, v] for k, v in r["threat_intel"]["by_classification"].items()]
    rows += [["alert_trend", t["date"], t["total"]] for t in r["alert_trend"]] + [["incident_trend", t["date"], t["total"]] for t in r["incident_trend"]]
    return rows


def export(fmt: str, dataset: str, days: int, agent_ids=None, now: datetime | None = None) -> tuple[bytes, str, str, int]:
    """-> (body, media_type, filename, row_count). Same scoping as build(): vendors can only export their own agents' data."""
    r = build(days, agent_ids, now)
    stamp = datetime.fromisoformat(r["generated_at"]).strftime("%Y%m%d")
    if dataset == "summary":
        rows, heads = summary_rows(r), ["section", "key", "value"]
    else:
        table = "detection_alerts" if dataset == "alerts" else "incidents"
        data = _scoped(table, r["window"]["from"], agent_ids)
        if dataset == "alerts":
            heads = ["id", "created_at", "last_seen", "severity", "status", "title", "agent_id", "agent_name", "src_ip", "event_count", "mitre", "acknowledged_at", "resolved_at"]
            rows = [[a["id"], a["created_at"], a["last_seen"], a["severity"], a["status"], a["title"], a["agent_id"], a["agent_name"], a["src_ip"], a["event_count"],
                     " ".join(m["id"] for m in json.loads(a["mitre"])), a["acknowledged_at"], a["resolved_at"]] for a in data]
        else:
            heads = ["id", "created_at", "last_activity", "severity", "status", "title", "agent_id", "alert_count", "mitre", "resolved_at"]
            rows = [[i["id"], i["created_at"], i["last_activity"], i["severity"], i["status"], i["title"], i["agent_id"], i["alert_count"],
                     " ".join(m["id"] for m in json.loads(i["mitre"])), i["resolved_at"]] for i in data]
    name = f"freightshield-{dataset}-{days}d-{stamp}.{fmt}"
    if fmt == "csv":
        return _csv(rows, heads), "text/csv; charset=utf-8", name, len(rows)
    return _pdf(r, dataset, rows, heads), "application/pdf", name, len(rows)


def _pdf(r: dict, dataset: str, rows: list[list], heads: list[str]) -> bytes:
    p = pdf_min.Pdf("FreightShield SOC Report")
    p.text("FreightShield SOC Report", 20, True)
    p.para(f"Dataset: {dataset} | Period: last {r['window']['days']} days ({r['window']['from'][:10]} to {r['window']['to'][:10]} UTC) | Scope: {r['scope']}")
    p.para(f"Generated {r['generated_at']} UTC. Source: live FreightShield data (Wazuh detections, incidents, response actions, threat intelligence).", 8)
    if dataset == "summary":
        t, m = r["totals"], r["metrics"]
        p.heading("Key figures")
        p.table(["Alerts", "Incidents", "Open alerts", "Open incidents", "Critical/High", "False positives"],
                [[t["alerts"], t["incidents"], t["open_alerts"], t["open_incidents"], t["critical_high_alerts"], t["false_positives"]]])
        p.heading("Response metrics")
        p.table(["Metric", "Samples", "Mean", "Median", "Max"],
                [[n, m[k]["count"], _fmt_s(m[k]["mean_seconds"]), _fmt_s(m[k]["median_seconds"]), _fmt_s(m[k]["max_seconds"])]
                 for n, k in (("MTTA (alerts)", "mtta"), ("MTTR (alerts)", "mttr_alerts"), ("MTTR (incidents)", "mttr_incidents"))], [150, 70, 100, 100, 95])
        p.para(r["data_quality"]["note"] + f" Excluded: {r['data_quality']['alerts_without_ack_time']} alerts, {r['data_quality']['resolved_incidents_without_time']} incidents.", 8)
        p.heading("Severity breakdown")
        p.bars("Alerts by severity", list(r["alerts_by_severity"].items()))
        p.bars("Incidents by severity", list(r["incidents_by_severity"].items()))
        p.heading("Alert trend (daily)")
        p.bars("Alerts per day", [(d["date"], d["total"]) for d in r["alert_trend"][-31:]], 31)
        p.heading("Incident trend (daily)")
        p.bars("Incidents per day", [(d["date"], d["total"]) for d in r["incident_trend"][-31:]], 31)
        p.heading("Top agents and rules")
        p.bars("Alerts by agent", [(x["agent"], x["alerts"]) for x in r["top_agents"]])
        p.bars("Alerts by rule", [(x["rule"], x["alerts"]) for x in r["top_rules"]])
        p.heading("Response actions and threat intelligence")
        p.bars("Response actions by status", list(r["response_actions"].items()))
        p.bars(f"IOCs by classification (total {r['threat_intel']['iocs']})", list(r["threat_intel"]["by_classification"].items()))
    else:
        p.heading(f"{dataset.title()} ({len(rows)} rows{', truncated' if len(rows) >= MAX_ROWS else ''})")
        keep = [i for i, h in enumerate(heads) if h in ("id", "created_at", "severity", "status", "title", "agent_id", "event_count", "alert_count", "mitre")]
        p.table([heads[i] for i in keep], [[str(row[i])[:19] if heads[i] == "created_at" else row[i] for i in keep] for row in rows[:500]])
        if len(rows) > 500:
            p.para("PDF shows the first 500 rows; export CSV for the complete data set.", 8)
    return p.render()


def audit_export(actor: dict, fmt: str, dataset: str, days: int, rows: int, scope: str, ip: str | None) -> None:
    audit.record(actor, "report_export", f"report:{dataset}", ip=ip, detail=f"format={fmt} days={days} rows={rows} scope={scope}")
