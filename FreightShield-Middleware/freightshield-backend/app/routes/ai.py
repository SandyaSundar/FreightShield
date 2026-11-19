"""AI orchestration (alert triage, summarisation, routing to LLM providers). TODO: implement."""
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/status")
async def ai_status() -> None:
    # Placeholder: explicit 501 so nothing can mistake this for a working feature.
    raise HTTPException(status_code=501, detail="ai module is not implemented yet.")
