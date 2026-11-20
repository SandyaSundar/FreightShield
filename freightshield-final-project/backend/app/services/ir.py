"""Incident response: playbooks -> RECOMMENDED actions -> admin approval -> execution via Wazuh Active Response -> rollback.

Safety rules (enforced here, not in the UI):
* Recommending never executes. Execution happens only inside approve()/retry() called by an authenticated admin route.
* IR_EXECUTION_ENABLED must be true or approve/retry/rollback are refused (nothing changes state).
* Status transitions are atomic compare-and-set UPDATEs, so a double click / race cannot execute an action twice.
* block_ip refuses private/loopback/link-local/reserved/multicast addresses and IR_PROTECTED_IPS; agent 000 (the manager) is never targeted.
* isolate_agent / rollbacks are only 'supported' when the operator names a matching Wazuh AR command; otherwise the action is
  'unsupported' (manual) and nothing is sent. A Wazuh reply is treated as success only if it reports >=1 affected, 0 failed items.
* Every step is appended to ir_audit (hash-chained; UPDATE/DELETE blocked by triggers) and the main audit log.
"""
import hashlib
import ipaddress
import json
import logging
from datetime import datetime, timezone

from fastapi import HTTPException

from app.core.config import get_settings
from app.core.db import connect
from app.core.errors import NotConfiguredError, UpstreamError
from app.services import audit, notifications
from app.services.detection import RANK, SEVERITIES, get_alert
from app.services.wazuh_manager import wazuh_manager

log = logging.getLogger("freightshield.ir")
ACTIONS = ("block_ip", "isolate_agent")
STEP_TYPES = ACTIONS + ("advisory",)
SYSTEM = {"id": None, "email": "system"}

DEFAULT_PLAYBOOKS = {
    "bruteforce_block_ip": {"name": "Brute force: block source IP", "trigger_rule": "auth_bruteforce", "min_severity": "high",
        "steps": [{"type": "block_ip"}, {"type": "advisory", "text": "Review successful logins from this source and rotate affected credentials."}]},
    "critical_event_isolate": {"name": "Critical event: isolate agent", "trigger_rule": "high_level_event", "min_severity": "critical",
        "steps": [{"type": "isolate_agent"}, {"type": "advisory", "text": "Collect volatile evidence before any remediation."}]},
    "fim_review": {"name": "File integrity burst: review", "trigger_rule": "fim_burst", "min_severity": "medium",
        "steps": [{"type": "advisory", "text": "Compare changed files with change tickets; escalate unexplained changes."}]},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ immutable-style audit
def _hash(prev: str, ts: str, actor: str, action_id, event: str, detail: str | None) -> str:
    return hashlib.sha256(json.dumps([prev, ts, actor, action_id, event, detail], separators=(",", ":")).encode()).hexdigest()


def log_event(actor: dict, action_id: int | None, event: str, detail: str | None = None, ip: str | None = None) -> None:
    """Append to the hash chain (serialized by BEGIN IMMEDIATE) and mirror into the main audit log. Never pass secrets."""
    who = actor.get("email") or "system"
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT hash FROM ir_audit ORDER BY id DESC LIMIT 1").fetchone()
        prev, ts = (row["hash"] if row else "0" * 64), _now()
        c.execute("INSERT INTO ir_audit (ts, actor, action_id, event, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                  (ts, who, action_id, event, detail, prev, _hash(prev, ts, who, action_id, event, detail)))
    audit.record(actor if actor.get("id") else None, f"ir_{event}", f"ir_action:{action_id}", "success", ip, detail)


def audit_list(limit: int, offset: int) -> tuple[list[dict], int]:
    with connect() as c:
        total = c.execute("SELECT COUNT(*) FROM ir_audit").fetchone()[0]
        rows = c.execute("SELECT * FROM ir_audit ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(r) for r in rows], total


def verify_chain() -> dict:
    """Recompute every hash. Any edited/removed/reordered row breaks the chain and is reported."""
    prev, n = "0" * 64, 0
    with connect() as c:
        for r in c.execute("SELECT * FROM ir_audit ORDER BY id"):
            n += 1
            if r["prev_hash"] != prev or r["hash"] != _hash(prev, r["ts"], r["actor"], r["action_id"], r["event"], r["detail"]):
                return {"valid": False, "entries": n, "first_bad_id": r["id"]}
            prev = r["hash"]
    return {"valid": True, "entries": n, "first_bad_id": None}


# ------------------------------------------------------------------ playbooks
def _pb(r) -> dict:
    return {**dict(r), "enabled": bool(r["enabled"]), "steps": json.loads(r["steps"])}


def load_playbooks() -> list[dict]:
    with connect() as c:
        for k, d in DEFAULT_PLAYBOOKS.items():  # seed defaults once; admin edits persist
            c.execute("INSERT OR IGNORE INTO ir_playbooks (key,name,enabled,trigger_rule,min_severity,steps,updated_at) VALUES (?,?,1,?,?,?,?)",
                      (k, d["name"], d["trigger_rule"], d["min_severity"], json.dumps(d["steps"]), _now()))
        return [_pb(r) for r in c.execute("SELECT * FROM ir_playbooks ORDER BY key")]


def update_playbook(key: str, enabled=None, min_severity=None, steps=None) -> tuple[dict, dict]:
    old = next((p for p in load_playbooks() if p["key"] == key), None)
    if not old:
        raise HTTPException(404, "Playbook not found.")
    if min_severity is not None and min_severity not in SEVERITIES:
        raise HTTPException(422, "Invalid severity.")
    if steps is not None:
        for s in steps:
            if s.get("type") not in STEP_TYPES or (s["type"] == "advisory" and not str(s.get("text", "")).strip()):
                raise HTTPException(422, f"Invalid step: type must be one of {STEP_TYPES} (advisory needs text).")
    with connect() as c:
        c.execute("UPDATE ir_playbooks SET enabled=?, min_severity=?, steps=?, updated_at=? WHERE key=?",
                  (int(old["enabled"] if enabled is None else enabled), min_severity or old["min_severity"],
                   json.dumps(old["steps"] if steps is None else steps), _now(), key))
    return old, next(p for p in load_playbooks() if p["key"] == key)


# ------------------------------------------------------------------ capability + validation
def capabilities() -> dict:
    s = get_settings()
    return {"execution_enabled": s.ir_execution_enabled, "wazuh_manager_configured": wazuh_manager.configured(),
            "block_ip": {"supported": bool(s.ir_ar_block_command), "rollback": bool(s.ir_ar_block_command and s.ir_ar_unblock_command)},
            "isolate_agent": {"supported": bool(s.ir_ar_isolate_command), "rollback": bool(s.ir_ar_isolate_command and s.ir_ar_unisolate_command)}}


def check_block_target(ip: str | None) -> str:
    """Return the normalized IP or raise ValueError with the reason it must not be blocked."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        raise ValueError("source IP is missing or not a valid IP address")
    if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified):
        raise ValueError("refusing to block a private/loopback/reserved address")
    if str(a) in {str(ipaddress.ip_address(p)) for p in get_settings().ir_protected_ips if _valid_ip(p)}:
        raise ValueError("address is on the protected list")
    return str(a)


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except ValueError:
        return False


# ------------------------------------------------------------------ recommendation (never executes)
def recommend(alert_id: int, actor: dict, ip: str | None = None) -> dict:
    alert = get_alert(alert_id)
    if alert["status"] in ("resolved", "false_positive"):
        raise HTTPException(409, "Alert is closed; no response is recommended.")
    caps, created, advisories, skipped = capabilities(), [], [], []
    for pb in load_playbooks():
        if not pb["enabled"] or pb["trigger_rule"] != alert["rule_key"] or RANK[alert["severity"]] < RANK[pb["min_severity"]]:
            continue
        for st in pb["steps"]:
            if st["type"] == "advisory":
                advisories.append({"playbook": pb["key"], "text": st["text"]}); continue
            status, detail, target = "pending", None, None
            if st["type"] == "block_ip":
                try:
                    target = check_block_target(alert.get("src_ip"))
                except ValueError as e:
                    status, detail = "unsupported", str(e)
            elif st["type"] == "isolate_agent":
                target = alert["agent_id"]
            if status == "pending" and not caps[st["type"]]["supported"]:
                status, detail = "unsupported", "No Wazuh Active Response command is configured for this action; perform it manually."
            if alert["agent_id"] in ("000", "0"):
                status, detail = "unsupported", "The Wazuh manager (agent 000) is never a response target."
            with connect() as c:  # dedupe: one live action per alert+playbook+action+target
                if c.execute("SELECT 1 FROM ir_actions WHERE alert_id=? AND playbook_key=? AND action=? AND IFNULL(target,'')=IFNULL(?,'')"
                             " AND status IN ('pending','executing','executed','unsupported')", (alert_id, pb["key"], st["type"], target)).fetchone():
                    skipped.append({"playbook": pb["key"], "action": st["type"], "reason": "already recommended"}); continue
                now = _now()
                cur = c.execute("INSERT INTO ir_actions (playbook_key,alert_id,incident_id,agent_id,action,target,severity,status,detail,created_at,updated_at)"
                                " VALUES (?,?,?,?,?,?,?,?,?,?,?)", (pb["key"], alert_id, alert.get("incident_id"), alert["agent_id"], st["type"],
                                                                     target, alert["severity"], status, detail, now, now))
                aid = cur.lastrowid
            log_event(actor, aid, "recommended" if status == "pending" else "recommended_unsupported",
                      f"{st['type']} target={target} playbook={pb['key']}" + (f" reason={detail}" if detail else ""), ip)
            created.append(get_action(aid))
            if status == "pending":  # Phase 8: tell the administrators an approval is waiting (never blocks or fails the recommendation)
                try:
                    notifications.notify_pending_action(get_action(aid))
                except Exception as e:  # noqa: BLE001
                    log.warning("pending-approval notification failed: %s", type(e).__name__)
    return {"alert_id": alert_id, "actions": created, "advisories": advisories, "skipped": skipped}


# ------------------------------------------------------------------ queries
def _act(r) -> dict:
    return dict(r)


def get_action(action_id: int, agent_ids=None) -> dict:
    with connect() as c:
        r = c.execute("SELECT * FROM ir_actions WHERE id=?", (action_id,)).fetchone()
    if not r or (agent_ids is not None and r["agent_id"] not in agent_ids):
        raise HTTPException(404, "Action not found.")
    return _act(r)


def list_actions(limit, offset, status=None, agent_ids=None):
    where, args = [], []
    if agent_ids is not None:  # vendor scope: empty list => nothing
        if not agent_ids:
            return [], 0
        where.append(f"agent_id IN ({','.join('?' * len(agent_ids))})"); args += list(agent_ids)
    if status:
        where.append("status=?"); args.append(status)
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM ir_actions{w}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM ir_actions{w} ORDER BY id DESC LIMIT ? OFFSET ?", [*args, limit, offset])
        return [_act(r) for r in rows], total


def summary() -> dict:
    with connect() as c:
        counts = {r[0]: r[1] for r in c.execute("SELECT status, COUNT(*) FROM ir_actions GROUP BY status")}
    return {"actions_by_status": counts, "pending_approvals": counts.get("pending", 0),
            "playbooks": load_playbooks(), "capabilities": capabilities(), "audit_chain": verify_chain()}


# ------------------------------------------------------------------ state machine
def _cas(action_id: int, frm: tuple[str, ...], to: str, **cols) -> bool:
    sets = ", ".join(f"{k}=?" for k in ("status", "updated_at", *cols))
    with connect() as c:
        cur = c.execute(f"UPDATE ir_actions SET {sets} WHERE id=? AND status IN ({','.join('?' * len(frm))})",
                        [to, _now(), *cols.values(), action_id, *frm])
        return cur.rowcount == 1


def _require_enabled() -> None:
    if not get_settings().ir_execution_enabled:
        raise HTTPException(409, "Response execution is disabled on the server (IR_EXECUTION_ENABLED=false). Nothing was changed.")


def reject(action_id: int, actor: dict, reason: str, ip=None) -> dict:
    if not _cas(action_id, ("pending",), "rejected", rejected_by=actor["email"], rejected_reason=reason):
        get_action(action_id)
        raise HTTPException(409, "Only a pending action can be rejected.")
    log_event(actor, action_id, "rejected", f"reason={reason[:200]}", ip)
    return get_action(action_id)


async def _send(a: dict, rollback: bool) -> None:
    """Call Wazuh Active Response. Raises RuntimeError with a safe reason on any failure; returns only on verified success."""
    s = get_settings()
    cmd = {("block_ip", False): s.ir_ar_block_command, ("block_ip", True): s.ir_ar_unblock_command,
           ("isolate_agent", False): s.ir_ar_isolate_command, ("isolate_agent", True): s.ir_ar_unisolate_command}[(a["action"], rollback)]
    if not cmd:
        raise RuntimeError("No Wazuh Active Response command configured for this operation.")
    if a["action"] == "block_ip":
        target = check_block_target(a["target"])  # re-validate at execution time, not only at recommendation time
        args, alert = [target], {"data": {"srcip": target}}
    else:
        args, alert = [a["agent_id"]], None
    try:
        res = await wazuh_manager.active_response(a["agent_id"], cmd, args, alert)
    except NotConfiguredError:
        raise RuntimeError("Wazuh Manager is not configured.")
    except UpstreamError as e:
        raise RuntimeError(e.detail)
    d = (res or {}).get("data") or {}
    if d.get("total_affected_items", 0) < 1 or d.get("total_failed_items", 0) > 0:
        raise RuntimeError("Wazuh did not confirm the command ran on the agent (no affected items or failed items reported).")


async def _run(action_id: int, actor: dict, ip, frm: tuple[str, ...], first: str, ok_status: str, fail_status: str, ev: str) -> dict:
    _require_enabled()
    a0 = get_action(action_id)
    if not _cas(action_id, frm, first):
        raise HTTPException(409, f"Action is '{a0['status']}'; expected one of {', '.join(frm)}.")
    rollback = first == "rolling_back"
    log_event(actor, action_id, f"{ev}_started", f"{a0['action']} target={a0['target']} agent={a0['agent_id']}", ip)
    try:
        await _send(get_action(action_id), rollback)
    except (RuntimeError, ValueError) as e:
        msg = str(e)[:300]
        cols = {"error": msg}
        _cas(action_id, (first,), fail_status, **cols)
        log_event(actor, action_id, f"{ev}_failed", msg, ip)
        log.warning("ir %s failed for action %s: %s", ev, action_id, msg)
        return get_action(action_id)
    except Exception as e:  # unexpected: record class only, never leave the action stuck in 'executing'
        _cas(action_id, (first,), fail_status, error=f"unexpected error ({type(e).__name__})")
        log_event(actor, action_id, f"{ev}_failed", f"unexpected {type(e).__name__}", ip)
        return get_action(action_id)
    cols = {"rolled_back_by": actor["email"], "rolled_back_at": _now(), "error": None} if rollback else {"executed_at": _now(), "error": None}
    _cas(action_id, (first,), ok_status, **cols)
    log_event(actor, action_id, f"{ev}_succeeded", f"{a0['action']} target={a0['target']}", ip)
    return get_action(action_id)


async def approve(action_id: int, actor: dict, ip=None) -> dict:
    """Admin approval = authorisation to execute exactly this recorded action, once."""
    _require_enabled()
    a = get_action(action_id)
    if a["status"] != "pending":
        raise HTTPException(409, f"Only a pending action can be approved (current: {a['status']}).")
    if not _cas(action_id, ("pending",), "executing", approved_by=actor["email"], approved_at=_now(), attempts=a["attempts"] + 1):
        raise HTTPException(409, "Action was already handled by another request.")
    log_event(actor, action_id, "approved", f"{a['action']} target={a['target']}", ip)
    return await _run_after_claim(action_id, actor, ip)


async def _run_after_claim(action_id: int, actor: dict, ip) -> dict:
    a0 = get_action(action_id)
    log_event(actor, action_id, "execute_started", f"{a0['action']} target={a0['target']} agent={a0['agent_id']}", ip)
    try:
        await _send(a0, False)
    except (RuntimeError, ValueError) as e:
        _cas(action_id, ("executing",), "failed", error=str(e)[:300])
        log_event(actor, action_id, "execute_failed", str(e)[:300], ip)
        return get_action(action_id)
    except Exception as e:
        _cas(action_id, ("executing",), "failed", error=f"unexpected error ({type(e).__name__})")
        log_event(actor, action_id, "execute_failed", f"unexpected {type(e).__name__}", ip)
        return get_action(action_id)
    _cas(action_id, ("executing",), "executed", executed_at=_now(), error=None)
    log_event(actor, action_id, "execute_succeeded", f"{a0['action']} target={a0['target']}", ip)
    return get_action(action_id)


async def retry(action_id: int, actor: dict, ip=None) -> dict:
    """Re-execute a FAILED action. It needs a fresh admin request (and is audited) but no new recommendation."""
    _require_enabled()
    a = get_action(action_id)
    if not _cas(action_id, ("failed",), "executing", approved_by=actor["email"], approved_at=_now(), attempts=a["attempts"] + 1):
        raise HTTPException(409, f"Only a failed action can be retried (current: {a['status']}).")
    log_event(actor, action_id, "retry_approved", f"attempt={a['attempts'] + 1}", ip)
    return await _run_after_claim(action_id, actor, ip)


async def rollback(action_id: int, actor: dict, ip=None) -> dict:
    _require_enabled()
    a = get_action(action_id)
    if a["status"] not in ("executed", "rollback_failed"):
        raise HTTPException(409, f"Only an executed action can be rolled back (current: {a['status']}).")
    if not capabilities()[a["action"]]["rollback"]:
        log_event(actor, action_id, "rollback_unsupported", "no Wazuh AR rollback command configured; manual rollback required", ip)
        raise HTTPException(409, "Rollback is not supported for this action (no Active Response rollback command is configured). Roll it back manually.")
    return await _run(action_id, actor, ip, ("executed", "rollback_failed"), "rolling_back", "rolled_back", "rollback_failed", "rollback")
