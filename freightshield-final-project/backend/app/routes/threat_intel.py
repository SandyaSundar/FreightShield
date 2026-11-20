"""Threat intelligence. Admin: full (ti:read / ti:write). Vendor: read-only, only IOCs seen on their OWN agents (scope is read
from vendor_agents by the authenticated id, never from client input). API keys are never returned; /ti/status shows booleans."""
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from pydantic import BaseModel, Field

from app.core.security import _ip, require_permission
from app.services import audit, notifications, ti_providers, threat_intel, vendor_agents
from app.services.wazuh_indexer import wazuh_indexer

router = APIRouter(prefix="/ti", tags=["threat-intel"])
vendor_router = APIRouter(prefix="/vendor/ti", tags=["vendor"])
READ, WRITE, VREAD = "ti:read", "ti:write", "vendor:threatintel"
Kind = Literal["ip", "domain", "url", "md5", "sha1", "sha256"]
Cls = Literal["malicious", "suspicious", "benign", "unknown"]


class LookupIn(BaseModel):
    value: str = Field(min_length=4, max_length=2048)


def _page(items, total, page, limit):
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/status")
def status(_: dict = Depends(require_permission(READ))):
    return {"feeds": ti_providers.status()}


@router.get("/summary")
def summary(_: dict = Depends(require_permission(READ))):
    return threat_intel.summary()


@router.post("/scan")
async def scan(background: BackgroundTasks, actor: dict = Depends(require_permission(WRITE))):
    """Reads real Wazuh alerts, extracts IOCs, enriches via configured feeds. 503/502 if Wazuh is unavailable; feed failures are reported, not fatal."""
    res = await threat_intel.scan(wazuh_indexer.search_alerts, actor)
    background.add_task(notifications.dispatch_emails)
    return res


@router.post("/lookup")
async def lookup(body: LookupIn, actor: dict = Depends(require_permission(WRITE))):
    return await threat_intel.lookup_value(body.value, actor)


@router.get("/iocs")
def iocs(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), type: Kind | None = None, classification: Cls | None = None,
         min_score: int | None = Query(None, ge=0, le=100), q: str | None = Query(None, max_length=200), _: dict = Depends(require_permission(READ))):
    items, total = threat_intel.list_iocs(limit, (page - 1) * limit, type, classification, min_score, q)
    return _page(items, total, page, limit)


@router.get("/iocs/{ioc_id}")
def ioc(ioc_id: int, _: dict = Depends(require_permission(READ))):
    return threat_intel.get_ioc(ioc_id)


@router.post("/iocs/{ioc_id}/refresh")
async def refresh(ioc_id: int, request: Request, actor: dict = Depends(require_permission(WRITE))):
    out = await threat_intel.enrich(ioc_id, force=True)
    threat_intel._notify()
    audit.record(actor, "ti_refresh", f"ioc:{ioc_id}", ip=_ip(request))
    return threat_intel.get_ioc(ioc_id) | {"refresh": out}


@router.get("/correlations")
def correlations(_: dict = Depends(require_permission(READ))):
    return {"items": threat_intel.correlations()}


# ---- vendor: read-only, own agents only
@vendor_router.get("/iocs")
def v_iocs(limit: int = Query(25, ge=1, le=100), page: int = Query(1, ge=1), classification: Cls | None = None,
           user: dict = Depends(require_permission(VREAD, audit_success=True))):
    items, total = threat_intel.list_iocs(limit, (page - 1) * limit, classification=classification, agent_ids=vendor_agents.agent_ids(user["id"]))
    return _page(items, total, page, limit)


@vendor_router.get("/iocs/{ioc_id}")
def v_ioc(ioc_id: int, user: dict = Depends(require_permission(VREAD, audit_success=True))):
    return threat_intel.get_ioc(ioc_id, agent_ids=vendor_agents.agent_ids(user["id"]))


@vendor_router.get("/correlations")
def v_corr(user: dict = Depends(require_permission(VREAD, audit_success=True))):
    return {"items": threat_intel.correlations(vendor_agents.agent_ids(user["id"]))}
