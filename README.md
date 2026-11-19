# FreightShield SOC

**FreightShield SOC** is a modular Security Operations Center platform designed to connect Wazuh Manager and Wazuh Indexer through a FastAPI middleware layer, with a lightweight JavaScript frontend.

## Current implementation

- FastAPI backend foundation and health endpoint
- Frontend-to-backend CORS configuration
- Wazuh Manager agent retrieval endpoint
- Wazuh Indexer alert retrieval endpoint with pagination and severity filtering
- Session-token authentication guards and admin/analyst access checks for Wazuh routes
- Safe upstream error handling and configurable TLS verification
- Vanilla JavaScript frontend for SOC dashboards, alerts, agents, incidents, AI assistant and user-role views

> Google OAuth token issuance, persistent incident management, AI orchestration, PostgreSQL persistence and automated response are planned follow-on work; they are not represented as completed features in this project snapshot.

## Architecture

```text
Browser (Vanilla JavaScript)
          |
          | /api/*
          v
FastAPI Middleware
     |          |
     v          v
Wazuh       Wazuh
Manager     Indexer
(55000)     (9200)
```

## Backend setup

From the `freightshield-backend` directory:

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
# .venv\\Scripts\\Activate.ps1

pip install -r requirements-dev.txt
cp .env.example .env
```

Edit the local `.env` with your own Wazuh Manager and Indexer credentials and a random `AUTH_JWT_SECRET` of at least 32 characters. **Never commit `.env` or paste credentials into source code.**

Run tests:

```bash
python -m pytest -v
```

Start the API:

```bash
uvicorn app.main:app --reload --port 8000
```

Health check: `http://localhost:8000/api/health`  
API documentation: `http://localhost:8000/docs`

## Frontend setup

From the `freightshield-frontend` directory:

1. Copy `js/config.example.js` to `js/config.js`.
2. Set the Google OAuth client ID and backend API base URL as appropriate.
3. Start a local static server:

```bash
python -m http.server 5173
```

Open `http://localhost:5173`.

## Wazuh connectivity

The backend must be able to reach the configured Wazuh Manager API (normally port `55000`) and Wazuh Indexer (normally port `9200`). Private LAN addresses are not reachable from a cloud deployment unless a secure VPN or tunnel is configured.

Use trusted TLS certificates in production. Disabling certificate verification is suitable only for controlled self-signed lab environments.

## Verification snapshot

The latest development test report supplied for this snapshot records **30 backend tests passed, 0 failed, 0 skipped**, with Python compilation checks passing. Re-run the commands above in your own environment to independently reproduce the result.

## Security notes

- Wazuh credentials and JWT signing secrets belong only in the backend environment.
- Keep `.env` out of version control.
- Wazuh routes are protected and fail closed when the JWT secret is unavailable.
- Do not enable disruptive Active Response actions without authorization, validation and audit logging.

## Roadmap

1. Google OAuth authentication and session issuance
2. Persistent user and role management
3. Incident management and audit history
4. AI-assisted alert investigation and recommendations
5. Threat correlation and monitoring enhancements
6. Human-approved incident response automation
7. PostgreSQL persistence and production deployment

---

Built as a modular SOC project integrating Wazuh with a custom web-based security operations interface.
