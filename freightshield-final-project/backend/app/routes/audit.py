"""Audit log viewer (admin only)."""
from fastapi import APIRouter, Depends, Query

from app.core.security import require_permission
from app.services import audit

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs")
def logs(limit: int = Query(50, ge=1, le=100), page: int = Query(1, ge=1), action: str | None = Query(None, max_length=64),
         actor_id: int | None = None, outcome: str | None = Query(None, pattern="^(success|denied|failure)$"),
         _: dict = Depends(require_permission("audit:read"))):
    items, total = audit.list_logs(limit, (page - 1) * limit, action, actor_id, outcome)
    return {"items": items, "total": total, "page": page, "limit": limit}
