"""Detection alerts, incidents, rules, notifications. Admin: full access. Vendor: read-only, own agents only."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core.security import _ip, require_permission
from app.services import audit, detection, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer

router = APIRouter(prefix="/detections", tags=["detections"])
vendor_router = APIRouter(prefix="/vendor/detections", tags=["vendor"])
Sev = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "acknowledged", "investigating", "resolved", "false_positive"]
READ, WRITE = "detections:read", "detections:write"


class AlertPatch(BaseModel):
    status: Literal["acknowledged", "investigating", "resolved", "false_positive"]


class IncidentPatch(BaseModel):
    status: Literal["open", "investigating", "resolved"]


class RulePatch(BaseModel):
    enabled: bool | None = None
    threshold: int | None = Field(None, ge=1, le=10000)
    window_seconds: int | None = Field(None, ge=30, le=86400)
    severity: Sev | None = None
    min_level: int | None = Field(None, ge=0, le=15)


def _page(items, total, page, limit):
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/summary")
def summary(user: dict = Depends(require_permission(READ))):
    return detection.summary(user["id"])  # unread_notifications is per user since Phase 8


@router.post("/run")
async def run_scan(request: Request, actor: dict = Depends(require_permission(WRITE))):
    """Pulls real alerts from the Wazuh Indexer and runs detection now. 503/502 if Wazuh is unavailable (never fakes data)."""
    return await detection.scan(wazuh_indexer.search_alerts, actor)


@router.get("/alerts")
def alerts(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), status: AlertStatus | None = None,
           severity: Sev | None = None, agent_id: str | None = Query(None, pattern=r"^\d{3,10}$"),
           _: dict = Depends(require_permission(READ))):
    items, total = detection.list_alerts(limit, (page - 1) * limit, status, severity, agent_id)
    return _page(items, total, page, limit)


@router.get("/alerts/{alert_id}")
def alert(alert_id: int, _: dict = Depends(require_permission(READ))):
    return detection.get_alert(alert_id)


@router.patch("/alerts/{alert_id}")
def patch_alert(alert_id: int, body: AlertPatch, request: Request, actor: dict = Depends(require_permission(WRITE))):
    a, old = detection.set_alert_status(alert_id, body.status)
    audit.record(actor, "alert_status", f"alert:{alert_id}", ip=_ip(request), detail=f"{old}->{body.status}")
    return a


@router.get("/incidents")
def incidents(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1),
              status: Literal["open", "investigating", "resolved"] | None = None, _: dict = Depends(require_permission(READ))):
    items, total = detection.list_incidents(limit, (page - 1) * limit, status)
    return _page(items, total, page, limit)


@router.get("/incidents/{incident_id}")
def incident(incident_id: int, _: dict = Depends(require_permission(READ))):
    return detection.get_incident(incident_id)


@router.patch("/incidents/{incident_id}")
def patch_incident(incident_id: int, body: IncidentPatch, request: Request, actor: dict = Depends(require_permission(WRITE))):
    i, old = detection.set_incident_status(incident_id, body.status)
    audit.record(actor, "incident_status", f"incident:{incident_id}", ip=_ip(request), detail=f"{old}->{body.status}")
    return i


@router.get("/rules")
def rules(_: dict = Depends(require_permission(READ))):
    return {"items": detection.load_rules()}


@router.put("/rules/{rule_key}")
def put_rule(rule_key: str, body: RulePatch, request: Request, actor: dict = Depends(require_permission(WRITE))):
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(422, "Nothing to update.")
    r = detection.update_rule(rule_key, **changes)
    audit.record(actor, "rule_update", f"rule:{rule_key}", ip=_ip(request), detail=", ".join(f"{k}={v}" for k, v in changes.items()))
    return r


# ---- vendor: read-only and scoped by the vendor's OWN assigned agents (never a client parameter)
@vendor_router.get("/alerts")
def vendor_alerts(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), status: AlertStatus | None = None,
                  severity: Sev | None = None, user: dict = Depends(require_permission("vendor:detections", audit_success=True))):
    items, total = detection.list_alerts(limit, (page - 1) * limit, status, severity, agent_ids=vendor_agents.agent_ids(user["id"]))
    return _page(items, total, page, limit)


@vendor_router.get("/alerts/{alert_id}")
def vendor_alert(alert_id: int, user: dict = Depends(require_permission("vendor:detections", audit_success=True))):
    return detection.get_alert(alert_id, agent_ids=vendor_agents.agent_ids(user["id"]))


@vendor_router.get("/incidents")
def vendor_incidents(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1),
                     user: dict = Depends(require_permission("vendor:detections", audit_success=True))):
    items, total = detection.list_incidents(limit, (page - 1) * limit, agent_ids=vendor_agents.agent_ids(user["id"]))
    return _page(items, total, page, limit)
