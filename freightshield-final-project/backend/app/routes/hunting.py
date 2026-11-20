"""Phase 9 threat hunting. Admin (`hunt:read`): all agents. Vendor (`vendor:hunt`): only agents assigned in vendor_agents,
looked up by the caller's own user id (never a client parameter). Every hunt is audited with its filters."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.security import _ip, require_permission
from app.services import audit, hunting, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer

router = APIRouter(prefix="/hunting", tags=["hunting"])
vendor_router = APIRouter(prefix="/vendor/hunting", tags=["vendor"])


def filters(hours: int = Query(24, ge=1, le=720), start: str | None = Query(None, max_length=40), end: str | None = Query(None, max_length=40),
            agent_id: str | None = Query(None, max_length=10), min_level: int | None = Query(None, ge=0, le=15),
            max_level: int | None = Query(None, ge=0, le=15), rule_id: str | None = Query(None, max_length=8),
            group: str | None = Query(None, max_length=64), technique: str | None = Query(None, max_length=9),
            tactic: str | None = Query(None, max_length=40), src_ip: str | None = Query(None, max_length=45),
            user: str | None = Query(None, max_length=64), q: str | None = Query(None, max_length=200)) -> dict:
    return hunting.clean_filters(dict(hours=hours, start=start, end=end, agent_id=agent_id, min_level=min_level, max_level=max_level,
                                      rule_id=rule_id, group=group, technique=technique, tactic=tactic, src_ip=src_ip, user=user, q=q))


def _vendor_scope(user: dict, f: dict) -> list[str]:
    ids = vendor_agents.agent_ids(user["id"])
    if "agent_id" in f and f["agent_id"] not in ids:
        raise HTTPException(404, "Agent not found.")
    return ids


def _audit(user, request, action, f):
    audit.record(user, action, request.url.path, ip=_ip(request), detail=hunting.audit_detail(f))


@router.get("/catalog")
def catalog(_: dict = Depends(require_permission("hunt:read"))):
    return hunting.catalog()


@router.get("/events")
async def events(request: Request, user: dict = Depends(require_permission("hunt:read")), limit: int = Query(50, ge=1, le=100), page: int = Query(1, ge=1), f: dict = Depends(filters)):
    _audit(user, request, "hunt_query", f)
    return await hunting.events(wazuh_indexer.search_alerts, f, None, limit, page)


@router.get("/analysis")
async def analysis(request: Request, user: dict = Depends(require_permission("hunt:read")), f: dict = Depends(filters)):
    _audit(user, request, "hunt_analysis", f)
    return await hunting.analysis(wazuh_indexer.search_alerts, f, None)


@vendor_router.get("/catalog")
def vendor_catalog(_: dict = Depends(require_permission("vendor:hunt"))):
    return hunting.catalog()


@vendor_router.get("/events")
async def vendor_events(request: Request, user: dict = Depends(require_permission("vendor:hunt")), limit: int = Query(50, ge=1, le=100), page: int = Query(1, ge=1), f: dict = Depends(filters)):
    ids = _vendor_scope(user, f)
    _audit(user, request, "hunt_query", f)
    if not ids:  # unassigned vendor: never query Wazuh (an empty terms filter must not become "all agents")
        return {"items": [], "total": 0, "page": page, "limit": limit, "has_more": False}
    return await hunting.events(wazuh_indexer.search_alerts, f, ids, limit, page)


@vendor_router.get("/analysis")
async def vendor_analysis(request: Request, user: dict = Depends(require_permission("vendor:hunt")), f: dict = Depends(filters)):
    ids = _vendor_scope(user, f)
    _audit(user, request, "hunt_analysis", f)
    if not ids:
        return hunting.empty_analysis(f)
    return await hunting.analysis(wazuh_indexer.search_alerts, f, ids)
