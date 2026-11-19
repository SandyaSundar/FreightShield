"""FreightShield SOC backend entry point. Run: uvicorn app.main:app --port 8000"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.routes import ai, auth, health, rbac, wazuh

settings = get_settings()
app = FastAPI(title="FreightShield SOC API", version="0.1.0")

# CORS: origins come from CORS_ALLOWED_ORIGINS (localhost + Vercel), never hard-coded.
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_allowed_origins,
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
register_error_handlers(app)

for r in (health.router, auth.router, rbac.router, wazuh.router, ai.router):
    app.include_router(r, prefix="/api")
