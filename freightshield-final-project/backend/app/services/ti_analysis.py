"""Reputation scoring, risk classification, evidence-based MITRE mapping and correlation (pure, stdlib only)."""
from collections import defaultdict

OK_STATUSES = ("ok",)  # providers that returned a verdict; not_found / unavailable / rate_limited / timeout / error add no score


def provider_score(provider: str, s: dict) -> int | None:
    """Normalize one provider's parsed summary to 0-100, or None if it carries no signal."""
    if provider == "virustotal":
        mal, sus = int(s.get("malicious", 0)), int(s.get("suspicious", 0))
        return min(100, mal * 12 + sus * 4)
    if provider == "abuseipdb":
        return max(0, min(100, int(s.get("abuse_confidence", 0))))
    if provider == "otx":
        return min(100, int(s.get("pulse_count", 0)) * 20)
    return None


def aggregate(results: dict[str, dict]) -> dict:
    """results: {provider: {status, score}}. Score = strongest provider signal, +5 when >=2 providers independently >=50."""
    scored = [r["score"] for r in results.values() if r.get("status") in OK_STATUSES and r.get("score") is not None]
    if not scored:
        answered = any(r.get("status") == "not_found" for r in results.values())
        return {"score": None, "classification": "unknown", "risk": "unknown",
                "reason": "no provider has reported on this indicator" if answered else "no provider returned a verdict"}
    score = min(100, max(scored) + (5 if sum(1 for x in scored if x >= 50) >= 2 else 0))
    cls = "malicious" if score >= 70 else "suspicious" if score >= 35 else "benign"
    risk = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 35 else "low"
    return {"score": score, "classification": cls, "risk": risk, "reason": f"{len(scored)} provider(s) answered"}


# ---- MITRE ATT&CK: only techniques the evidence supports. Each entry carries its evidence string.
T = {"T1110": ("Credential Access", "Brute Force"), "T1190": ("Initial Access", "Exploit Public-Facing Application")}
WEB_GROUPS = {"web_attack", "attack", "sql_injection", "web", "accesslog"}


def map_mitre(ioc: dict, sightings: list[dict]) -> list[dict]:
    """ioc: {type, classification}; sightings: [{groups[], mitre[{id,tactic,technique}], level, agent_id, src_is_ioc}]."""
    out: dict[str, dict] = {}
    for s in sightings:  # (a) techniques Wazuh itself attached to the alerts where the IOC was seen
        for m in s.get("mitre") or []:
            if m.get("id"):
                out.setdefault(m["id"], {"id": m["id"], "tactic": m.get("tactic"), "technique": m.get("technique"),
                                         "source": "wazuh", "evidence": "technique attached by Wazuh rule to an alert containing this IOC"})
    flagged = ioc.get("classification") in ("malicious", "suspicious")
    fails = [s for s in sightings if "authentication_failed" in s.get("groups", ()) or "authentication_failures" in s.get("groups", ())]
    if ioc["type"] == "ip" and flagged and len(fails) >= 3 and any(s.get("src_is_ioc") for s in fails):  # (b)
        out.setdefault("T1110", {"id": "T1110", "tactic": T["T1110"][0], "technique": T["T1110"][1], "source": "ti",
                                 "evidence": f"{len(fails)} authentication-failure alerts with this reputation-flagged IP as source"})
    web = [s for s in sightings if WEB_GROUPS & set(s.get("groups", ())) and s.get("level", 0) >= 6]
    if ioc["type"] in ("ip", "url", "domain") and flagged and web:  # (c)
        out.setdefault("T1190", {"id": "T1190", "tactic": T["T1190"][0], "technique": T["T1190"][1], "source": "ti",
                                 "evidence": f"{len(web)} web-attack alerts (level>=6) involving this reputation-flagged indicator"})
    return list(out.values())


def correlate(iocs: list[dict], sightings: list[dict]) -> list[dict]:
    """Patterns across sightings. iocs: [{id,type,value,risk,score}]; sightings: [{ioc_id, alert_id, agent_id, ts}]."""
    by_ioc, by_alert = defaultdict(list), defaultdict(set)
    for s in sightings:
        by_ioc[s["ioc_id"]].append(s)
        by_alert[s["alert_id"]].add(s["ioc_id"])
    meta, out = {i["id"]: i for i in iocs}, []
    for iid, ss in by_ioc.items():
        agents = sorted({s["agent_id"] for s in ss})
        i = meta.get(iid)
        if not i:
            continue
        base = {"iocs": [iid], "agents": agents, "alerts": len({s["alert_id"] for s in ss}),
                "first_seen": min(s["ts"] for s in ss), "last_seen": max(s["ts"] for s in ss), "risk": i["risk"]}
        if len(agents) >= 2:
            out.append({**base, "pattern": "multi_host", "summary": f"{i['type']} {i['value']} seen on {len(agents)} agents"})
        if base["alerts"] >= 5:
            out.append({**base, "pattern": "repeated_activity", "summary": f"{i['type']} {i['value']} in {base['alerts']} alerts"})
    seen = set()
    for aid, ids in by_alert.items():  # alerts that carry several IOCs link them into one campaign cluster
        if len(ids) >= 2:
            key = tuple(sorted(ids))
            if key in seen:
                continue
            seen.add(key)
            ss = [s for s in sightings if s["ioc_id"] in ids]
            risks = [meta[i]["risk"] for i in ids if i in meta]
            order = ["unknown", "low", "medium", "high", "critical"]
            out.append({"pattern": "linked_iocs", "iocs": list(key), "agents": sorted({s["agent_id"] for s in ss}),
                        "alerts": len({s["alert_id"] for s in ss}), "first_seen": min(s["ts"] for s in ss),
                        "last_seen": max(s["ts"] for s in ss), "risk": max(risks, key=order.index),
                        "summary": f"{len(key)} indicators co-occur in the same alert(s)"})
    return sorted(out, key=lambda p: (["unknown", "low", "medium", "high", "critical"].index(p["risk"]), p["alerts"]), reverse=True)
