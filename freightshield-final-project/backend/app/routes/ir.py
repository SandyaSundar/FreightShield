"""Incident response API. Admin (IT Security Administrator) only for everything that reads full IR data or changes state;
vendors get a read-only view of response actions on THEIR assigned agents (scope comes from vendor_agents, never a parameter)."""
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field

from app.core.security import _ip, require_permission
from app.services import ir, notifications, vendor_agents

router = APIRouter(prefix="/ir", tags=["incident-response"])
vendor_router = APIRouter(prefix="/vendor/ir", tags=["vendor"])
Status = Literal["pending", "unsupported", "rejected", "executing", "executed", "failed", "rolling_back", "rolled_back", "rollback_failed"]
Sev = Literal["low", "medium", "high", "critical"]
READ, APPROVE, MANAGE = "ir:read", "ir:approve", "ir:manage"
ActionId = Path(ge=1)


class Step(BaseModel):
    type: Literal["block_ip", "isolate_agent", "advisory"]
    text: str | None = Field(None, max_length=500)


class PlaybookPatch(BaseModel):
    enabled: bool | None = None
    min_severity: Sev | None = None
    steps: list[Step] | None = Field(None, max_length=10)


class RejectBody(BaseModel):
    reason: str = Field(min_length=3, max_length=300)


@router.get("/summary")
def summary(_: dict = Depends(require_permission(READ))):
    return ir.summary()


@router.get("/playbooks")
def playbooks(_: dict = Depends(require_permission(READ))):
    return {"items": ir.load_playbooks()}


@router.put("/playbooks/{key}")
def put_playbook(key: str, body: PlaybookPatch, request: Request, actor: dict = Depends(require_permission(MANAGE))):
    ch = body.model_dump(exclude_none=True)
    if not ch:
        raise HTTPException(422, "Nothing to update.")
    old, new = ir.update_playbook(key, body.enabled, body.min_severity,
                                  [s.model_dump(exclude_none=True) for s in body.steps] if body.steps is not None else None)
    ir.log_event(actor, None, "playbook_updated", f"{key}: {', '.join(ch)}", _ip(request))
    return new


@router.post("/recommend/{alert_id}")
def recommend(alert_id: int, request: Request, background: BackgroundTasks, actor: dict = Depends(require_permission(MANAGE))):
    """Creates PENDING recommendations only. Nothing is executed. Approval-needed emails go out after the response (outbox)."""
    res = ir.recommend(alert_id, actor, _ip(request))
    background.add_task(notifications.dispatch_emails)
    return res


@router.get("/actions")
def actions(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), status: Status | None = None,
            _: dict = Depends(require_permission(READ))):
    items, total = ir.list_actions(limit, (page - 1) * limit, status)
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/actions/{action_id}")
def action(action_id: int = ActionId, _: dict = Depends(require_permission(READ))):
    return ir.get_action(action_id)


@router.post("/actions/{action_id}/approve")
async def approve(request: Request, action_id: int = ActionId, actor: dict = Depends(require_permission(APPROVE))):
    return await ir.approve(action_id, actor, _ip(request))


@router.post("/actions/{action_id}/reject")
def reject(body: RejectBody, request: Request, action_id: int = ActionId, actor: dict = Depends(require_permission(APPROVE))):
    return ir.reject(action_id, actor, body.reason, _ip(request))


@router.post("/actions/{action_id}/retry")
async def retry(request: Request, action_id: int = ActionId, actor: dict = Depends(require_permission(APPROVE))):
    return await ir.retry(action_id, actor, _ip(request))


@router.post("/actions/{action_id}/rollback")
async def rollback(request: Request, action_id: int = ActionId, actor: dict = Depends(require_permission(APPROVE))):
    return await ir.rollback(action_id, actor, _ip(request))


@router.get("/audit")
def audit_trail(limit: int = Query(50, ge=1, le=100), page: int = Query(1, ge=1), _: dict = Depends(require_permission(READ))):
    items, total = ir.audit_list(limit, (page - 1) * limit)
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/audit/verify")
def audit_verify(_: dict = Depends(require_permission(READ))):
    return ir.verify_chain()


@vendor_router.get("/actions")
def vendor_actions(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1),
                   user: dict = Depends(require_permission("vendor:responses", audit_success=True))):
    items, total = ir.list_actions(limit, (page - 1) * limit, agent_ids=vendor_agents.agent_ids(user["id"]))
    # vendors never see who approved/rejected or internal error text
    safe = [{k: v for k, v in i.items() if k in ("id", "agent_id", "action", "severity", "status", "created_at", "executed_at")} for i in items]
    return {"items": safe, "total": total, "page": page, "limit": limit}
