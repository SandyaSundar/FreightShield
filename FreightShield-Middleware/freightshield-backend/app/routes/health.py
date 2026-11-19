"""Liveness endpoint. Reports whether Wazuh is configured, never the credentials."""
from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import get_settings
from app.services.wazuh_indexer import wazuh_indexer
from app.services.wazuh_manager import wazuh_manager

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "freightshield-backend",
        "environment": get_settings().app_env,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "integrations": {"wazuh_manager_configured": wazuh_manager.configured(),
                         "wazuh_indexer_configured": wazuh_indexer.configured()},
    }
