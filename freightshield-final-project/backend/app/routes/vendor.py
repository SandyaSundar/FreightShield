"""Vendor data isolation. A vendor's scope is read from the user store by the authenticated user's id, never from
client input, so there is no parameter a vendor can change to see another vendor's data.
`router`: vendor self-service. `admin_router`: admins assign agents to vendors (audited)."""
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from app.core.security import _ip, require_permission
from app.routes.wazuh import MAX_LIMIT, fetch_alerts
from app.services import audit, users, vendor_agents
from app.services.wazuh_manager import wazuh_manager

AGENT_ID = r"^\d{3,10}$"
router = APIRouter(prefix="/vendor", tags=["vendor"])
admin_router = APIRouter(prefix="/vendors", tags=["vendors"])


@router.get("/agents")
async def my_agents(user: dict = Depends(require_permission("vendor:agents", audit_success=True))):
    ids = vendor_agents.agent_ids(user["id"])
    if not ids:  # never call Wazuh with an empty list: it would return every agent
        return {"data": {"affected_items": [], "total_affected_items": 0}}
    return await wazuh_manager.list_agents(agent_ids=ids, limit=len(ids))


@router.get("/alerts")
async def my_alerts(limit: int = Query(25, ge=1, le=MAX_LIMIT), page: int = Query(1, ge=1),
                    min_level: int | None = Query(None, ge=0, le=15), agent_id: str | None = Query(None, pattern=AGENT_ID),
                    user: dict = Depends(require_permission("vendor:alerts", audit_success=True))):
    ids = vendor_agents.agent_ids(user["id"])
    if agent_id:
        if agent_id not in ids:
            raise HTTPException(404, "Agent not found.")
        ids = [agent_id]
    if not ids:
        return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
                "pagination": {"page": page, "limit": limit, "count": 0, "has_more": False}}
    return await fetch_alerts(limit, page, min_level, ids)


def _vendor(vendor_id: int) -> dict:
    v = users.get_by_id(vendor_id)
    if not v or v["role"] != "vendor":
        raise HTTPException(404, "Vendor not found.")
    return v


@admin_router.get("/{vendor_id}/agents")
def list_assigned(vendor_id: int, _: dict = Depends(require_permission("users:read"))):
    return {"vendor_id": _vendor(vendor_id)["id"], "agent_ids": vendor_agents.agent_ids(vendor_id)}


@admin_router.put("/{vendor_id}/agents/{agent_id}")
def assign_agent(vendor_id: int, request: Request, agent_id: str = Path(pattern=AGENT_ID),
                 actor: dict = Depends(require_permission("users:write"))):
    _vendor(vendor_id)
    vendor_agents.assign(vendor_id, agent_id)
    audit.record(actor, "vendor_agent_assign", f"user:{vendor_id}", ip=_ip(request), detail=f"agent={agent_id}")
    return {"vendor_id": vendor_id, "agent_ids": vendor_agents.agent_ids(vendor_id)}


@admin_router.delete("/{vendor_id}/agents/{agent_id}")
def unassign_agent(vendor_id: int, request: Request, agent_id: str = Path(pattern=AGENT_ID),
                   actor: dict = Depends(require_permission("users:write"))):
    _vendor(vendor_id)
    if not vendor_agents.unassign(vendor_id, agent_id):
        raise HTTPException(404, "Agent is not assigned to this vendor.")
    audit.record(actor, "vendor_agent_unassign", f"user:{vendor_id}", ip=_ip(request), detail=f"agent={agent_id}")
    return {"vendor_id": vendor_id, "agent_ids": vendor_agents.agent_ids(vendor_id)}
