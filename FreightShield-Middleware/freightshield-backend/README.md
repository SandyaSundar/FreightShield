# FreightShield SOC Backend (FastAPI)

Foundation backend for the SOC platform. Wazuh credentials stay server-side; the frontend only talks to `/api/*`.
Auth, RBAC and AI routes are placeholders (HTTP 501). No fake auth or fake Wazuh data.

## Setup
```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # then edit values
uvicorn app.main:app --reload --port 8000
```
Check: `curl http://localhost:8000/api/health` · Docs: http://localhost:8000/docs

## Structure
- `app/main.py` – app, CORS, routers
- `app/core/` – config (env), shared errors
- `app/routes/` – health, auth, rbac, wazuh, ai
- `app/services/` – `wazuh_manager.py` (port 55000), `wazuh_indexer.py` (port 9200)

## Notes
- `CORS_ALLOWED_ORIGINS`: comma-separated; add your Vercel URL.
- Unconfigured Wazuh -> 503 `not_configured`; unreachable/bad creds -> 502/503 `upstream_error`.
- Before production: implement auth + RBAC and protect `/api/wazuh/*`; use a trusted TLS cert (`WAZUH_VERIFY_SSL=true`).


## Wazuh (Phase 2)
- `GET /api/wazuh/indexer/alerts?limit=25&page=1&min_level=` (limit 1-100, page*limit <= 10000), `GET /api/wazuh/manager/agents`, `/manager/info`, `/indexer/health`.
- All Wazuh routes require a valid session JWT (cookie `fs_session` or Bearer, HS256, `AUTH_JWT_SECRET` >= 32 chars) with role `admin` or `analyst`. No secret configured = 503 (fail closed). The login endpoint that issues tokens is still unimplemented (`/api/auth/status` -> 501).
- Tests: `pip install -r requirements-dev.txt && python -m pytest` (all Wazuh calls mocked).
