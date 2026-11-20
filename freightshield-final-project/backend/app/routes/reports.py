"""SOC reports & analytics. Admin: all data (reports:read / reports:export). Vendor: only their OWN assigned agents (scope read from
vendor_agents by the authenticated id, never client input). Plain users have no report access. Every export is audited."""
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response

from app.core.security import _ip, require_permission
from app.services import reports, vendor_agents

router = APIRouter(prefix="/reports", tags=["reports"])
vendor_router = APIRouter(prefix="/vendor/reports", tags=["vendor"])
Days = Query(30, ge=1, le=365)
Fmt = Literal["csv", "pdf"]
Dataset = Literal["summary", "alerts", "incidents"]


def _send(fmt, dataset, days, user, request, agent_ids, scope) -> Response:
    body, media, name, rows = reports.export(fmt, dataset, days, agent_ids)
    reports.audit_export(user, fmt, dataset, days, rows, scope, _ip(request))
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"',
                                                     "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/summary")
def summary(days: int = Days, _: dict = Depends(require_permission("reports:read"))):
    return reports.build(days)


@router.get("/export")
def export(request: Request, format: Fmt = "csv", dataset: Dataset = "summary", days: int = Days,
           user: dict = Depends(require_permission("reports:export"))):
    return _send(format, dataset, days, user, request, None, "admin:all")


@vendor_router.get("/summary")
def v_summary(days: int = Days, user: dict = Depends(require_permission("vendor:reports", audit_success=True))):
    return reports.build(days, vendor_agents.agent_ids(user["id"]))


@vendor_router.get("/export")
def v_export(request: Request, format: Fmt = "csv", dataset: Dataset = "summary", days: int = Days,
             user: dict = Depends(require_permission("vendor:reports"))):
    ids = vendor_agents.agent_ids(user["id"])
    return _send(format, dataset, days, user, request, ids, f"vendor:{len(ids)}agents")
