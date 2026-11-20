"""FreightShield SOC backend entry point. Run: uvicorn app.main:app --port 8000"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core import hardening
from app.core.errors import register_error_handlers
from app.core.security import MIN_SECRET_LEN
from app.routes import ai, audit, ir, auth, detections, health, hunting, notifications, rbac, reports, threat_intel, users, vendor, wazuh, vault
from app.services import detection
from app.services import notifications as notify_service
from app.services.wazuh_indexer import wazuh_indexer

settings = get_settings()
log = logging.getLogger("freightshield.detection")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Optional background scanner (DETECTION_INTERVAL_SECONDS > 0 and Wazuh Indexer configured). Off by default."""
    task = None
    if settings.detection_interval_seconds > 0 and wazuh_indexer.configured():
        async def loop():
            while True:
                try:
                    await detection.scan(wazuh_indexer.search_alerts)
                except Exception as e:  # keep scanning; the failure is logged, never swallowed silently
                    log.warning("detection scan failed: %s", type(e).__name__)
                await asyncio.sleep(settings.detection_interval_seconds)
        task = asyncio.create_task(loop())
    ntask = None
    if settings.notify_interval_seconds > 0:  # Phase 8: overdue/escalation evaluator + email outbox (DB only; no Wazuh needed)
        async def nloop():
            while True:
                try:
                    await asyncio.to_thread(notify_service.run_cycle)
                except Exception as e:  # noqa: BLE001
                    log.warning("notification cycle failed: %s", type(e).__name__)
                await asyncio.sleep(settings.notify_interval_seconds)
        ntask = asyncio.create_task(nloop())
    yield
    for t in (task, ntask):
        if t:
            t.cancel()


_prod = settings.app_env.lower() == "production"
if _prod and len(settings.auth_jwt_secret) < MIN_SECRET_LEN:
    raise RuntimeError("AUTH_JWT_SECRET must be at least 32 characters in production.")
if _prod and any(o.startswith("http://") and "localhost" not in o and "127.0.0.1" not in o for o in settings.cors_allowed_origins):
    logging.getLogger("freightshield").warning("CORS_ALLOWED_ORIGINS contains a non-HTTPS origin in production.")

# Phase 10: interactive API docs are disabled in production (no free endpoint map for attackers).
app = FastAPI(title="FreightShield SOC API", version="0.11.0", lifespan=lifespan,
              docs_url=None if _prod else "/docs", redoc_url=None if _prod else "/redoc",
              openapi_url=None if _prod else "/openapi.json")

# Hardening runs inside CORS so even 403/413/429 responses carry CORS headers the SPA can read.
hardening.install(app)
# CORS: origins come from CORS_ALLOWED_ORIGINS (localhost + Vercel), never hard-coded; wildcard is stripped in config.
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_allowed_origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                   allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
                   expose_headers=["Content-Disposition", "Retry-After"], max_age=600)
register_error_handlers(app)

for r in (health.router, auth.router, rbac.router, users.router, audit.router, wazuh.router, vendor.router, vendor.admin_router, detections.router,
          detections.vendor_router, notifications.router, notifications.vendor_router, ai.router, ir.router, ir.vendor_router, threat_intel.router, threat_intel.vendor_router, reports.router, reports.vendor_router, hunting.router, hunting.vendor_router, vault.router):
    app.include_router(r, prefix="/api")
