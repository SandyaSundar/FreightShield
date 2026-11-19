"""Role-based access control (roles, permissions, dependencies that guard routes). TODO: implement once authentication exists."""
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/rbac", tags=["rbac"])


@router.get("/status")
async def rbac_status() -> None:
    # Placeholder: explicit 501 so nothing can mistake this for a working feature.
    raise HTTPException(status_code=501, detail="rbac module is not implemented yet.")
