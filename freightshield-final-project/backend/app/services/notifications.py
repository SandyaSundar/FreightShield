"""Phase 8 SOC notifications & escalation. Everything is derived from REAL rows of Phases 3-6 (alerts, incidents, IR actions, IOCs);
nothing is sampled or invented.

Categories: critical_alert, alert, new_incident (one notification per detection event; critical > new incident > plain alert),
pending_approval (IR action awaiting an admin), threat_intel (high/critical IOC seen on an agent), overdue_incident (SLA breach,
level 1; level 2 = escalation).

Isolation: admins see everything. A vendor sees a notification only if it is vendor_visible AND scoped to one of the vendor's own
assigned agents (scope comes from vendor_agents by the authenticated id, never from client input). pending_approval and
overdue_incident are admin-only. Plain `user` accounts have no notification access.

Email uses an outbox: emit() only writes rows (so it can run inside another transaction); dispatch_emails() sends AFTER commit,
records every attempt in notification_deliveries and never raises into the detection / response paths.
SMTP credentials come from environment variables, are sent only over TLS, and are never logged or returned.
"""
import json
import logging
import re
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parseaddr

from fastapi import HTTPException

from app.core.config import get_settings
from app.core.db import connect
from app.services import audit

log = logging.getLogger("freightshield.notify")
SEVERITIES = ("low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
CATEGORIES = ("critical_alert", "alert", "new_incident", "pending_approval", "threat_intel", "overdue_incident")
VENDOR_CATEGORIES = frozenset({"critical_alert", "alert", "new_incident", "threat_intel"})
SYSTEM = {"id": None, "email": "system"}
EMAIL_RE = re.compile(r"^[^@\s,;<>\"]+@[^@\s,;<>\"]+\.[^@\s,;<>\"]+$")

# Defaults seeded into SQLite on first use; admins edit them afterwards (PUT /notifications/rules/{severity}).
DEFAULT_RULES = {
    "critical": {"enabled": 1, "email": 1, "sla_minutes": 60, "escalate_after_minutes": 60},
    "high": {"enabled": 1, "email": 1, "sla_minutes": 240, "escalate_after_minutes": 240},
    "medium": {"enabled": 1, "email": 0, "sla_minutes": 1440, "escalate_after_minutes": 0},
    "low": {"enabled": 1, "email": 0, "sla_minutes": 4320, "escalate_after_minutes": 0},
}
# Email opt-in defaults by role when a user has not saved preferences yet.
DEFAULT_PREFS = {"admin": {"email_enabled": True, "min_severity": "high"}, "vendor": {"email_enabled": False, "min_severity": "high"}}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _parse(v) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- escalation rules
def _seed_rules(c) -> None:
    for sev, d in DEFAULT_RULES.items():
        c.execute("INSERT OR IGNORE INTO escalation_rules (severity, enabled, email, sla_minutes, escalate_after_minutes, updated_at) VALUES (?,?,?,?,?,?)",
                  (sev, d["enabled"], d["email"], d["sla_minutes"], d["escalate_after_minutes"], _now()))


def _rule_row(r) -> dict:
    return {**dict(r), "enabled": bool(r["enabled"]), "email": bool(r["email"])}


def load_rules() -> list[dict]:
    with connect() as c:
        _seed_rules(c)
        rows = c.execute("SELECT * FROM escalation_rules").fetchall()
    return sorted((_rule_row(r) for r in rows), key=lambda r: RANK[r["severity"]], reverse=True)


def update_rule(severity: str, **changes) -> tuple[dict, dict]:
    if severity not in SEVERITIES:
        raise HTTPException(404, "Unknown severity.")
    changes = {k: v for k, v in changes.items() if v is not None}
    old = next(r for r in load_rules() if r["severity"] == severity)
    if changes:
        for k in ("enabled", "email"):
            if k in changes:
                changes[k] = int(changes[k])
        with connect() as c:
            c.execute(f"UPDATE escalation_rules SET {', '.join(k + '=?' for k in changes)}, updated_at=? WHERE severity=?",
                      [*changes.values(), _now(), severity])
    return old, next(r for r in load_rules() if r["severity"] == severity)


# ---------------------------------------------------------------- email configuration
def email_problem() -> str | None:
    """Why email cannot be sent right now (None = ready). Used by /status and before every send."""
    s = get_settings()
    if not s.notify_email_enabled:
        return "NOTIFY_EMAIL_ENABLED is false"
    if not s.smtp_host or not s.smtp_from:
        return "SMTP_HOST / SMTP_FROM are not set"
    if not EMAIL_RE.match(parseaddr(s.smtp_from)[1]):
        return "SMTP_FROM is not a valid address"
    if s.smtp_user and not (s.smtp_ssl or s.smtp_starttls):
        return "refusing to send SMTP credentials without TLS (set SMTP_STARTTLS or SMTP_SSL)"
    return None


def status() -> dict:
    """Booleans and counts only: no host, user, password or address is ever returned."""
    s, problem = get_settings(), email_problem()
    return {"email_enabled": s.notify_email_enabled, "email_ready": problem is None, "email_problem": problem,
            "smtp_host_set": bool(s.smtp_host), "smtp_auth_set": bool(s.smtp_user and s.smtp_password),
            "tls": "ssl" if s.smtp_ssl else "starttls" if s.smtp_starttls else "none",
            "escalation_contacts": len([e for e in s.notify_escalation_emails if EMAIL_RE.match(e)]),
            "evaluator_interval_seconds": s.notify_interval_seconds, "email_max_attempts": s.notify_email_max_attempts}


# ---------------------------------------------------------------- creation
def emit(c, *, category: str, severity: str, title: str, message: str | None = None, dedupe_key: str | None = None,
         alert_id: int | None = None, incident_id: int | None = None, agent_ids=(), escalation_level: int = 0,
         now: str | None = None) -> int | None:
    """Insert one notification on connection `c` (the caller's transaction). Returns its id, or None when the severity's rule is
    disabled or the dedupe key already exists. Does NOT send email and does NOT audit (callers audit after commit)."""
    if category not in CATEGORIES or severity not in SEVERITIES:
        raise ValueError("invalid notification category/severity")
    _seed_rules(c)
    rule = c.execute("SELECT * FROM escalation_rules WHERE severity=?", (severity,)).fetchone()
    if not rule["enabled"]:
        return None
    email_state = "none"
    if rule["email"]:
        email_state = "pending" if email_problem() is None else "unconfigured"  # never backfills: history sent later is not mass-mailed
    cur = c.execute("INSERT OR IGNORE INTO notifications (ts, alert_id, severity, title, category, message, incident_id, dedupe_key,"
                    " vendor_visible, escalation_level, email_state) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (now or _now(), alert_id, severity, title[:300], category, message and message[:1000], incident_id, dedupe_key,
                     int(category in VENDOR_CATEGORIES), escalation_level, email_state))
    if cur.rowcount == 0:
        return None
    nid = cur.lastrowid
    for a in {str(x) for x in agent_ids if x}:
        c.execute("INSERT OR IGNORE INTO notification_scope (notification_id, agent_id) VALUES (?,?)", (nid, a))
    return nid


def audit_created(ids: list[int], actor: dict | None = None) -> None:
    """Audit trail for created notifications (call after the creating transaction has committed)."""
    if not ids:
        return
    with connect() as c:
        rows = c.execute(f"SELECT id, category, severity, escalation_level FROM notifications WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()
    for r in rows:
        audit.record(actor or SYSTEM, "notification_create", f"notification:{r['id']}",
                     detail=f"category={r['category']} severity={r['severity']} level={r['escalation_level']}")


def _scope_agents(c, nid: int) -> list[str]:
    return [r[0] for r in c.execute("SELECT agent_id FROM notification_scope WHERE notification_id=?", (nid,))]


def notify_pending_action(action: dict) -> int | None:
    """An IR action is awaiting admin approval (admin-only notification)."""
    sev = action["severity"]
    with connect() as c:
        nid = emit(c, category="pending_approval", severity=sev, dedupe_key=f"ir:{action['id']}", alert_id=action.get("alert_id"),
                   incident_id=action.get("incident_id"), agent_ids=[action["agent_id"]],
                   title=f"Response approval needed: {action['action']} {action.get('target') or ''} on agent {action['agent_id']}".replace("  ", " "),
                   message=f"Action #{action['id']} ({action['playbook_key']}) is pending approval by an IT Security Administrator.")
    audit_created([nid] if nid else [])
    return nid


# ---------------------------------------------------------------- automated checks (idempotent; safe to run repeatedly)
def sync_pending_approvals() -> list[int]:
    with connect() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM ir_actions WHERE status='pending'")]
    return [n for n in (notify_pending_action(a) for a in rows) if n]


def sync_threat_intel() -> list[int]:
    """One notification per (IOC, agent, risk) for IOCs a feed scored high/critical AND that were really seen on that agent."""
    made = []
    with connect() as c:
        rows = c.execute("SELECT i.id, i.type, i.value, i.score, i.risk, i.classification, s.agent_id FROM iocs i JOIN ioc_sightings s ON s.ioc_id=i.id"
                         " WHERE i.risk IN ('high','critical') GROUP BY i.id, s.agent_id").fetchall()
        for r in rows:
            nid = emit(c, category="threat_intel", severity=r["risk"], dedupe_key=f"ti:{r['id']}:{r['agent_id']}:{r['risk']}", agent_ids=[r["agent_id"]],
                       title=f"{r['classification'].capitalize()} {r['type'].upper()} {r['value']} observed on agent {r['agent_id']}",
                       message=f"Threat-intelligence feeds scored this indicator {r['score']}/100 ({r['risk']} risk).")
            if nid:
                made.append(nid)
    audit_created(made)
    return made


def _human(minutes: float) -> str:
    return f"{minutes / 60:.1f} h" if minutes >= 120 else f"{int(minutes)} min"


def check_overdue(now: datetime | None = None) -> list[int]:
    """Unresolved incidents older than their severity's SLA -> level 1; older than SLA + escalate_after -> level 2 (escalation)."""
    now, made = now or datetime.now(timezone.utc), []
    rules = {r["severity"]: r for r in load_rules()}
    with connect() as c:
        for inc in c.execute("SELECT * FROM incidents WHERE status IN ('open','investigating')").fetchall():
            rule, created = rules.get(inc["severity"]), _parse(inc["created_at"])
            if not rule or not rule["enabled"] or not created:
                continue
            age = (now - created).total_seconds() / 60
            if age < rule["sla_minutes"]:
                continue
            base = f"Incident #{inc['id']} ({inc['severity']}, {inc['status']}) has been unresolved for {_human(age)}; SLA is {_human(rule['sla_minutes'])}."
            levels = [(1, f"Overdue incident #{inc['id']}: {inc['title']}", base)]
            if rule["escalate_after_minutes"] > 0 and age >= rule["sla_minutes"] + rule["escalate_after_minutes"]:
                levels.append((2, f"ESCALATED incident #{inc['id']}: {inc['title']}", base + " Escalated: still unresolved after the escalation window."))
            for lvl, title, msg in levels:
                nid = emit(c, category="overdue_incident", severity=inc["severity"], title=title, message=msg, dedupe_key=f"overdue:{inc['id']}:{lvl}",
                           incident_id=inc["id"], agent_ids=[inc["agent_id"]], escalation_level=lvl)
                if nid:
                    made.append(nid)
    audit_created(made)
    return made


def run_cycle(actor: dict | None = None) -> dict:
    """The automated evaluator: overdue/escalation + pending approvals + threat intel, then email dispatch. Sync (call via to_thread)."""
    res = {"overdue": len(check_overdue()), "pending_approvals": len(sync_pending_approvals()), "threat_intel": len(sync_threat_intel())}
    res["email"] = dispatch_emails()
    if actor or any(v for k, v in res.items() if k != "email") or res["email"]["sent"] or res["email"]["failed"]:
        audit.record(actor or SYSTEM, "notification_evaluate", "notifications",
                     detail=f"overdue={res['overdue']} pending_approvals={res['pending_approvals']} threat_intel={res['threat_intel']} "
                            f"email_sent={res['email']['sent']} email_failed={res['email']['failed']}")
    return res


# ---------------------------------------------------------------- email
def _pref_row(user: dict, c=None) -> dict:
    d = DEFAULT_PREFS.get(user["role"], {"email_enabled": False, "min_severity": "high"})
    def q(cc):
        return cc.execute("SELECT * FROM notification_prefs WHERE user_id=?", (user["id"],)).fetchone()
    if c is None:
        with connect() as cc:
            r = q(cc)
    else:
        r = q(c)
    return {"email_enabled": bool(r["email_enabled"]), "min_severity": r["min_severity"], "saved": True} if r else {**d, "saved": False}


def get_prefs(user: dict) -> dict:
    return {**_pref_row(user), "email": user["email"]}


def set_prefs(user: dict, email_enabled: bool | None, min_severity: str | None) -> tuple[dict, dict]:
    if min_severity is not None and min_severity not in SEVERITIES:
        raise HTTPException(422, "Invalid severity.")
    old = _pref_row(user)
    new = {"email_enabled": old["email_enabled"] if email_enabled is None else email_enabled, "min_severity": min_severity or old["min_severity"]}
    with connect() as c:
        c.execute("INSERT INTO notification_prefs (user_id, email_enabled, min_severity, updated_at) VALUES (?,?,?,?)"
                  " ON CONFLICT(user_id) DO UPDATE SET email_enabled=excluded.email_enabled, min_severity=excluded.min_severity, updated_at=excluded.updated_at",
                  (user["id"], int(new["email_enabled"]), new["min_severity"], _now()))
    return old, get_prefs(user)


def _recipients(c, n) -> list[str]:
    """Who should be emailed for notification row `n`: admins always (per their prefs); vendors only for vendor-visible
    notifications scoped to THEIR agents; escalation contacts for level >= 2."""
    out: dict[str, None] = {}
    sev = RANK[n["severity"]]
    scope = _scope_agents(c, n["id"])
    for u in c.execute("SELECT * FROM users WHERE active=1 AND role IN ('admin','vendor')").fetchall():
        u = dict(u)
        if u["role"] == "vendor":
            if not n["vendor_visible"] or not scope:
                continue
            mine = {r[0] for r in c.execute("SELECT agent_id FROM vendor_agents WHERE vendor_id=?", (u["id"],))}
            if not mine & set(scope):
                continue
        p = _pref_row(u, c)
        if p["email_enabled"] and sev >= RANK[p["min_severity"]] and EMAIL_RE.match(u["email"]):
            out[u["email"].lower()] = None
    if n["escalation_level"] >= 2:
        for e in get_settings().notify_escalation_emails:
            if EMAIL_RE.match(e):
                out[e] = None
    return list(out)


def _build(n, to: str) -> EmailMessage:
    s = get_settings()
    clean = lambda v: re.sub(r"[\r\n]+", " ", str(v or "")).strip()  # no header injection through alert/agent text
    m = EmailMessage()
    m["From"], m["To"] = s.smtp_from, to
    m["Subject"] = f"[FreightShield][{n['severity'].upper()}] {clean(n['title'])}"[:200]
    lines = [f"Category: {n['category']}", f"Severity: {n['severity']}", f"Time (UTC): {n['ts']}"]
    if n["escalation_level"] >= 2:
        lines.append("ESCALATED: this needs immediate attention.")
    if n["message"]:
        lines += ["", n["message"]]
    if s.notify_app_url:
        lines += ["", f"Open notifications: {s.notify_app_url}/#notifications"]
    lines += ["", "You receive this because email alerts are enabled for your FreightShield account (Notifications > Preferences)."]
    m.set_content("\n".join(lines))
    return m


def _send_smtp(msg: EmailMessage) -> None:
    s, ctx = get_settings(), ssl.create_default_context()  # certificate + hostname verified
    srv = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds, context=ctx) if s.smtp_ssl \
        else smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds)
    with srv:
        if not s.smtp_ssl and s.smtp_starttls:
            srv.starttls(context=ctx)
        if s.smtp_user:
            srv.login(s.smtp_user, s.smtp_password)
        srv.send_message(msg)


def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {str(e)[:150]}".replace(get_settings().smtp_password or "\0", "***")


def _todo(c, n, maxa: int) -> list[tuple[str, int]]:
    """Recipients of notification row `n` still to be tried: never attempted, or failed with attempts left. -> [(address, attempts_so_far)]"""
    out = []
    for to in _recipients(c, n):
        d = c.execute("SELECT status, attempts FROM notification_deliveries WHERE notification_id=? AND recipient=?", (n["id"], to)).fetchone()
        if not d:
            out.append((to, 0))
        elif d["status"] == "failed" and d["attempts"] < maxa:
            out.append((to, d["attempts"]))
    return out


def dispatch_emails(limit: int = 50) -> dict:
    """Send pending email for notifications (outbox). Every attempt is stored; failures never propagate."""
    res = {"sent": 0, "failed": 0, "skipped_reason": None}
    problem = email_problem()
    if problem:
        res["skipped_reason"] = problem
        return res
    maxa, results = max(1, get_settings().notify_email_max_attempts), []
    try:
        with connect() as c:
            pend = [dict(r) for r in c.execute("SELECT * FROM notifications WHERE email_state='pending' ORDER BY id LIMIT ?", (limit,))]
            work = [(n, to, prev) for n in pend for to, prev in _todo(c, n, maxa)]
        for n, to, prev in work:  # network I/O happens outside any DB transaction
            try:
                _send_smtp(_build(n, to))
                results.append((n["id"], to, "sent", prev + 1, None))
            except Exception as e:  # noqa: BLE001 - one bad recipient must not stop the rest
                results.append((n["id"], to, "failed", prev + 1, _err(e)))
        with connect() as c:
            for nid, to, st, att, err in results:
                c.execute("INSERT INTO notification_deliveries (notification_id, recipient, status, attempts, error, attempted_at) VALUES (?,?,?,?,?,?)"
                          " ON CONFLICT(notification_id, recipient) DO UPDATE SET status=excluded.status, attempts=excluded.attempts,"
                          " error=excluded.error, attempted_at=excluded.attempted_at", (nid, to, st, att, err, _now()))
            for n in pend:  # finished once every recipient is sent or out of attempts (or nobody wants this email)
                if not _todo(c, n, maxa):
                    c.execute("UPDATE notifications SET email_state='done' WHERE id=?", (n["id"],))
    except Exception as e:  # noqa: BLE001
        log.warning("notification email dispatch failed: %s", type(e).__name__)
        res["skipped_reason"] = f"dispatch error ({type(e).__name__})"
    for nid, to, st, att, err in results:
        res["sent" if st == "sent" else "failed"] += 1
        audit.record(SYSTEM, "notification_email_sent" if st == "sent" else "notification_email_failed", f"notification:{nid}",
                     "success" if st == "sent" else "failure", detail=f"attempt={att}" + (f" error={err}" if err else ""))
    return res


def send_test_email(user: dict) -> None:
    """Send a test message to the caller's OWN registered address only (never a client-supplied recipient)."""
    problem = email_problem()
    if problem:
        raise HTTPException(409, f"Email is not ready: {problem}.")
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = get_settings().smtp_from, user["email"], "[FreightShield] Test notification email"
    m.set_content("This is a test message from FreightShield SOC notifications. Email alerts are working.")
    try:
        _send_smtp(m)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"The SMTP server did not accept the message ({_err(e)}).")


# ---------------------------------------------------------------- queries
def _read_sql(uid: int | None) -> tuple[str, list]:
    """SQL boolean 'this notification is read'. uid=None -> legacy/global view (Phase 3): read by anyone or flagged is_read."""
    if uid is None:
        return "(n.is_read=1 OR EXISTS(SELECT 1 FROM notification_reads r WHERE r.notification_id=n.id))", []
    return "EXISTS(SELECT 1 FROM notification_reads r WHERE r.notification_id=n.id AND r.user_id=?)", [uid]


def _visible(agent_ids) -> tuple[list[str], list]:
    """agent_ids None = admin (everything). A list = vendor scope; an empty list sees nothing."""
    if agent_ids is None:
        return [], []
    if not agent_ids:
        return ["0"], []
    return [f"n.vendor_visible=1 AND EXISTS(SELECT 1 FROM notification_scope s WHERE s.notification_id=n.id AND s.agent_id IN ({','.join('?' * len(agent_ids))}))"], list(agent_ids)


def _item(r, vendor: bool) -> dict:
    d = {k: r[k] for k in ("id", "ts", "alert_id", "incident_id", "severity", "title", "message", "category", "escalation_level")}
    d["is_read"] = bool(r["is_read_u"])
    if not vendor:
        d["email_state"] = r["email_state"]
    return d


def list_notifications(limit, offset, unread_only=False, user_id=None, agent_ids=None, category=None, severity=None, read=None):
    rs, ra = _read_sql(user_id)
    where, args = _visible(agent_ids)
    where, args = list(where), list(args)
    if unread_only:
        read = False
    if read is not None:
        where.append(rs if read else f"NOT {rs}")
        args += ra
    for col, v in (("n.category", category), ("n.severity", severity)):
        if v:
            where.append(f"{col}=?"), args.append(v)
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM notifications n{w}", args).fetchone()[0]
        rows = c.execute(f"SELECT n.*, {rs} AS is_read_u FROM notifications n{w} ORDER BY n.id DESC LIMIT ? OFFSET ?", [*ra, *args, limit, offset]).fetchall()
    return [_item(r, agent_ids is not None) for r in rows], total


def get_notification(nid: int, user_id: int, agent_ids=None) -> dict:
    rs, ra = _read_sql(user_id)
    where, args = _visible(agent_ids)
    where = ["n.id=?", *where]
    with connect() as c:
        r = c.execute(f"SELECT n.*, {rs} AS is_read_u FROM notifications n WHERE {' AND '.join(where)}", [*ra, nid, *args]).fetchone()
        if not r:
            raise HTTPException(404, "Notification not found.")
        d = _item(r, agent_ids is not None)
        if agent_ids is None:
            d["agent_ids"] = _scope_agents(c, nid)
            d["deliveries"] = [dict(x) for x in c.execute("SELECT recipient, status, attempts, error, attempted_at FROM notification_deliveries"
                                                          " WHERE notification_id=? ORDER BY id", (nid,))]
    return d


def summary(user_id: int | None = None, agent_ids=None) -> dict:
    rs, ra = _read_sql(user_id)
    where, args = _visible(agent_ids)
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        rows = c.execute(f"SELECT n.severity, n.category, {rs} AS rd FROM notifications n{w}", [*ra, *args]).fetchall()
    unread = [r for r in rows if not r["rd"]]
    cnt = lambda rs_, k: {v: sum(1 for r in rs_ if r[k] == v) for v in sorted({r[k] for r in rs_})}
    return {"total": len(rows), "unread": len(unread), "unread_by_severity": cnt(unread, "severity"), "unread_by_category": cnt(unread, "category")}


def mark_read(nid: int, user_id: int | None = None, agent_ids=None, read: bool = True) -> None:
    """Per-user read state. user_id=None is the legacy Phase 3 call (flags the shared row)."""
    with connect() as c:
        where, args = _visible(agent_ids)
        if not c.execute(f"SELECT 1 FROM notifications n WHERE n.id=?{''.join(' AND ' + x for x in where)}", [nid, *args]).fetchone():
            raise HTTPException(404, "Notification not found.")
        if user_id is None:
            c.execute("UPDATE notifications SET is_read=? WHERE id=?", (int(read), nid))
        elif read:
            c.execute("INSERT OR IGNORE INTO notification_reads (notification_id, user_id, read_at) VALUES (?,?,?)", (nid, user_id, _now()))
        else:
            c.execute("DELETE FROM notification_reads WHERE notification_id=? AND user_id=?", (nid, user_id))
            c.execute("UPDATE notifications SET is_read=0 WHERE id=?", (nid,))


def mark_all_read(user_id: int, agent_ids=None) -> int:
    rs, ra = _read_sql(user_id)
    where, args = _visible(agent_ids)
    where = [*where, f"NOT {rs}"]
    with connect() as c:
        ids = [r[0] for r in c.execute(f"SELECT n.id FROM notifications n WHERE {' AND '.join(where)}", [*args, *ra])]
        c.executemany("INSERT OR IGNORE INTO notification_reads (notification_id, user_id, read_at) VALUES (?,?,?)", [(i, user_id, _now()) for i in ids])
    return len(ids)


def list_deliveries(limit: int, offset: int) -> tuple[list[dict], int]:
    with connect() as c:
        total = c.execute("SELECT COUNT(*) FROM notification_deliveries").fetchone()[0]
        rows = c.execute("SELECT d.*, n.title, n.severity, n.category FROM notification_deliveries d JOIN notifications n ON n.id=d.notification_id"
                         " ORDER BY d.id DESC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(r) for r in rows], total
