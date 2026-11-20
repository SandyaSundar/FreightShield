"""SOC notifications. Admin (IT Security Administrator): everything, plus escalation rules / evaluator / test email.
Vendor: only vendor-visible notifications on their OWN assigned agents (scope read from vendor_agents by the authenticated id,
never a parameter). Read/unread is per user. Plain `user` accounts have no access. Every state change is audited."""
import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field

from app.core.security import _ip, require_permission
from app.services import audit, notifications as n, vendor_agents

router = APIRouter(prefix="/notifications", tags=["notifications"])
vendor_router = APIRouter(prefix="/vendor/notifications", tags=["vendor"])
READ, MANAGE, VREAD = "notifications:read", "notifications:manage", "vendor:notifications"
Sev = Literal["low", "medium", "high", "critical"]
Cat = Literal["critical_alert", "alert", "new_incident", "pending_approval", "threat_intel", "overdue_incident"]
VCat = Literal["critical_alert", "alert", "new_incident", "threat_intel"]
NId = Path(ge=1)


class PrefsIn(BaseModel):
    email_enabled: bool | None = None
    min_severity: Sev | None = None


class RuleIn(BaseModel):
    enabled: bool | None = None
    email: bool | None = None
    sla_minutes: int | None = Field(None, ge=5, le=60 * 24 * 30)
    escalate_after_minutes: int | None = Field(None, ge=0, le=60 * 24 * 30)  # 0 = never escalate


def _page(items, total, page, limit):
    return {"items": items, "total": total, "page": page, "limit": limit}


def _prefs_update(body: PrefsIn, request: Request, user: dict) -> dict:
    ch = body.model_dump(exclude_none=True)
    if not ch:
        raise HTTPException(422, "Nothing to update.")
    old, new = n.set_prefs(user, body.email_enabled, body.min_severity)
    audit.record(user, "notification_prefs_update", f"user:{user['id']}", ip=_ip(request),
                 detail=", ".join(f"{k}={old[k]}->{new[k]}" for k in ch))
    return new


# ------------------------------------------------------------------ admin
@router.get("")
def list_all(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), unread: bool = False, read: bool | None = None,
             category: Cat | None = None, severity: Sev | None = None, user: dict = Depends(require_permission(READ))):
    items, total = n.list_notifications(limit, (page - 1) * limit, unread, user["id"], None, category, severity, read)
    return _page(items, total, page, limit)


@router.get("/summary")
def summary(user: dict = Depends(require_permission(READ))):
    return n.summary(user["id"])


@router.get("/status")
def status(_: dict = Depends(require_permission(READ))):
    return n.status()


@router.get("/deliveries")
def deliveries(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), _: dict = Depends(require_permission(READ))):
    items, total = n.list_deliveries(limit, (page - 1) * limit)
    return _page(items, total, page, limit)


@router.get("/rules")
def rules(_: dict = Depends(require_permission(READ))):
    return {"items": n.load_rules()}


@router.put("/rules/{severity}")
def put_rule(severity: Sev, body: RuleIn, request: Request, actor: dict = Depends(require_permission(MANAGE))):
    ch = body.model_dump(exclude_none=True)
    if not ch:
        raise HTTPException(422, "Nothing to update.")
    old, new = n.update_rule(severity, **ch)
    audit.record(actor, "escalation_rule_update", f"escalation_rule:{severity}", ip=_ip(request),
                 detail=", ".join(f"{k}={old[k]}->{new[k]}" for k in ch))
    return new


@router.post("/evaluate")
async def evaluate(actor: dict = Depends(require_permission(MANAGE))):
    """Run the automated checks now (overdue incidents / escalation, pending approvals, threat intel) and send pending email."""
    return await asyncio.to_thread(n.run_cycle, actor)  # run_cycle audits the run under the actor


@router.post("/test-email")
async def test_email(request: Request, actor: dict = Depends(require_permission(MANAGE))):
    """Sends a test message to the caller's own registered address only."""
    try:
        await asyncio.to_thread(n.send_test_email, actor)
    except HTTPException as e:
        audit.record(actor, "notification_test_email", "email", "failure", _ip(request), str(e.detail)[:200])
        raise
    audit.record(actor, "notification_test_email", "email", ip=_ip(request))
    return {"sent": True}


@router.get("/preferences")
def get_prefs(user: dict = Depends(require_permission(READ))):
    return n.get_prefs(user)


@router.put("/preferences")
def put_prefs(body: PrefsIn, request: Request, user: dict = Depends(require_permission(READ))):
    return _prefs_update(body, request, user)


@router.post("/read-all")
def read_all(request: Request, user: dict = Depends(require_permission(READ))):
    count = n.mark_all_read(user["id"])
    audit.record(user, "notification_read_all", "notifications", ip=_ip(request), detail=f"count={count}")
    return {"marked_read": count}


@router.get("/{notification_id}")
def detail(notification_id: int = NId, user: dict = Depends(require_permission(READ))):
    return n.get_notification(notification_id, user["id"])


@router.post("/{notification_id}/read")
def read_one(request: Request, notification_id: int = NId, user: dict = Depends(require_permission(READ))):
    n.mark_read(notification_id, user["id"])
    audit.record(user, "notification_read", f"notification:{notification_id}", ip=_ip(request))
    return {"read": notification_id}


@router.post("/{notification_id}/unread")
def unread_one(request: Request, notification_id: int = NId, user: dict = Depends(require_permission(READ))):
    n.mark_read(notification_id, user["id"], read=False)
    audit.record(user, "notification_unread", f"notification:{notification_id}", ip=_ip(request))
    return {"unread": notification_id}


# ------------------------------------------------------------------ vendor: own agents only, vendor-visible categories only
@vendor_router.get("")
def v_list(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), unread: bool = False, read: bool | None = None,
           category: VCat | None = None, severity: Sev | None = None, user: dict = Depends(require_permission(VREAD, audit_success=True))):
    items, total = n.list_notifications(limit, (page - 1) * limit, unread, user["id"], vendor_agents.agent_ids(user["id"]), category, severity, read)
    return _page(items, total, page, limit)


@vendor_router.get("/summary")
def v_summary(user: dict = Depends(require_permission(VREAD))):
    return n.summary(user["id"], vendor_agents.agent_ids(user["id"]))


@vendor_router.get("/preferences")
def v_get_prefs(user: dict = Depends(require_permission(VREAD))):
    return n.get_prefs(user)


@vendor_router.put("/preferences")
def v_put_prefs(body: PrefsIn, request: Request, user: dict = Depends(require_permission(VREAD))):
    return _prefs_update(body, request, user)


@vendor_router.post("/read-all")
def v_read_all(request: Request, user: dict = Depends(require_permission(VREAD))):
    count = n.mark_all_read(user["id"], vendor_agents.agent_ids(user["id"]))
    audit.record(user, "notification_read_all", "notifications", ip=_ip(request), detail=f"count={count}")
    return {"marked_read": count}


@vendor_router.get("/{notification_id}")
def v_detail(notification_id: int = NId, user: dict = Depends(require_permission(VREAD, audit_success=True))):
    return n.get_notification(notification_id, user["id"], vendor_agents.agent_ids(user["id"]))


@vendor_router.post("/{notification_id}/read")
def v_read(request: Request, notification_id: int = NId, user: dict = Depends(require_permission(VREAD))):
    n.mark_read(notification_id, user["id"], vendor_agents.agent_ids(user["id"]))
    audit.record(user, "notification_read", f"notification:{notification_id}", ip=_ip(request))
    return {"read": notification_id}


@vendor_router.post("/{notification_id}/unread")
def v_unread(request: Request, notification_id: int = NId, user: dict = Depends(require_permission(VREAD))):
    n.mark_read(notification_id, user["id"], vendor_agents.agent_ids(user["id"]), read=False)
    audit.record(user, "notification_unread", f"notification:{notification_id}", ip=_ip(request))
    return {"unread": notification_id}
