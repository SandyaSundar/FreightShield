"""Authentication (login, token issue/refresh, logout). TODO: integrate a real identity provider or user store; no fake auth is provided."""
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/status")
async def auth_status() -> None:
    # Placeholder: explicit 501 so nothing can mistake this for a working feature.
    raise HTTPException(status_code=501, detail="auth module is not implemented yet.")
