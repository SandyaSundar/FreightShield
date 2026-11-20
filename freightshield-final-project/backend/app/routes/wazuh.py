"""Wazuh integration. Every route requires authentication + a role permission (see core/security.py).
Responses are real Wazuh data, or a clear 4xx/5xx error. Credentials never leave the server."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.security import require_permission
from app.services.wazuh_indexer import wazuh_indexer
from app.services.wazuh_manager import wazuh_manager

router = APIRouter(prefix="/wazuh", tags=["wazuh"])

MAX_LIMIT = 100
MAX_WINDOW = 10000  # OpenSearch default index.max_result_window


async def fetch_alerts(limit: int, page: int, min_level: int | None, agent_ids: list[str] | None = None) -> dict:
    """Shared by the admin route and the vendor-scoped route (agent_ids=None means unscoped)."""
    offset = (page - 1) * limit
    if offset + limit > MAX_WINDOW:
        raise HTTPException(422, f"page*limit exceeds the {MAX_WINDOW} result window.")
    r = await wazuh_indexer.get_alerts(limit, offset, min_level, agent_ids)
    # OpenSearch-shaped (frontend reads hits.hits[]._source) plus pagination metadata.
    return {"hits": {"total": {"value": r["total"], "relation": "eq"}, "hits": r["hits"]},
            "pagination": {"page": page, "limit": limit, "count": len(r["hits"]),
                           "has_more": offset + len(r["hits"]) < r["total"]}}


@router.get("/manager/info", dependencies=[Depends(require_permission("wazuh:read", audit_success=True))])
async def manager_info():
    return await wazuh_manager.get_info()


@router.get("/manager/agents", dependencies=[Depends(require_permission("wazuh:agents", audit_success=True))])
async def manager_agents(status: Literal["active", "disconnected", "never_connected", "pending"] | None = Query(None),
                         limit: int = Query(500, ge=1, le=500), offset: int = Query(0, ge=0)):
    # Passed through unchanged: frontend reads data.affected_items (Wazuh's native shape).
    return await wazuh_manager.list_agents(status, limit, offset)


@router.get("/indexer/health", dependencies=[Depends(require_permission("wazuh:read", audit_success=True))])
async def indexer_health():
    return await wazuh_indexer.cluster_health()


@router.get("/indexer/alerts", dependencies=[Depends(require_permission("wazuh:alerts", audit_success=True))])
async def indexer_alerts(limit: int = Query(25, ge=1, le=MAX_LIMIT), page: int = Query(1, ge=1),
                         min_level: int | None = Query(None, ge=0, le=15)):
    return await fetch_alerts(limit, page, min_level)
