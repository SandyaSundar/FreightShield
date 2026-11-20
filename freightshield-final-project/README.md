# FreightShield SOC

React and TypeScript operations console for the preserved FreightShield Phase 1–10 FastAPI service. All security records and access checks come from the service; there are no sample incidents, users, alerts, or AI responses.

## Start locally

Requirements: Node.js 20+, npm, Python 3.10+.

1. Install frontend packages and set its public settings:

   ```sh
   npm install
   cp .env.example .env
   # Set VITE_GOOGLE_CLIENT_ID to the Google OAuth web client ID.
   # Local API defaults to http://localhost:8000/api.
   npm run dev
   ```

2. In another terminal, configure and start the API:

   ```sh
   cd backend
   python3 -m venv .venv
   . .venv/bin/activate  # Windows: .venv\\Scripts\\activate
   pip install -r requirements-dev.txt
   cp .env.example .env
   # Configure GOOGLE_CLIENT_ID, AUTH_JWT_SECRET and any providers you use.
   python -m app.cli create-admin admin@example.com
   uvicorn app.main:app --reload --port 8000
   ```

   The browser connects to `http://localhost:8000/api` by default. For the Vite proxy, set `VITE_API_BASE_URL=/api`; `FREIGHTSHIELD_API_PROXY_TARGET` changes the proxy destination. For a separately hosted API, set `VITE_API_BASE_URL` to its address ending in `/api`, add your frontend origin to backend `CORS_ALLOWED_ORIGINS`, and keep the API secret values on the backend.

3. Add the exact frontend origin to Google OAuth's **Authorized JavaScript origins** and to backend `CORS_ALLOWED_ORIGINS`. For example, local Vite commonly uses `http://localhost:5173`; the Lovable preview origin must also be allowed when testing that preview. The Content Security Policy includes the origin in `VITE_API_BASE_URL` when it is an absolute URL. Keep the Google client ID public, but never place Wazuh, AI, signing, mail, or threat-feed secrets in the browser environment.

## Build and checks

```sh
npm run build
npm test
npx playwright install chromium
npm run test:e2e
```

The Playwright smoke tests start the local API and UI and create temporary test-role sessions in `/tmp`; they do not add users or operational data to your service database. Install Chromium once with `npx playwright install chromium`. Backend tests and endpoints can be checked with:

```sh
cd backend
pip install -r requirements-dev.txt
pytest
```

Run `npm run dev` and the backend concurrently when using the API. The Google OAuth client ID and server provider credentials are not included in this archive; live Google, Wazuh, AI, threat-feed, email, and response-execution checks require the corresponding configuration. See `backend/README.md` and `backend/SECURITY.md` before deploying.

## Pages and access

The console retains the source pages: operations overview, Wazuh alerts and agents, detections, incidents, detection rules, incident response, notifications, threat intelligence, threat hunting, reports, AI SOC Investigator, AI Email Router, users and vendor assignments, audit trail, profile, and the vendor-scoped counterparts. Page access is derived from `/api/auth/me`; the FastAPI service remains the real authorization and vendor-isolation boundary. The delivery and pickup maps are clearly labeled simulations because the API has no carrier tracking data.

AI requests can run for up to three minutes. User and vendor maps use OpenStreetMap tiles and OSRM road routing with a straight-line fallback. The theme can be changed in the top bar.

## Data migration note

No database, SQLite file, user list, or operational record export was included in the supplied archive. The service creates its local database when first run, but old accounts and SOC records are not present. Export the source SQLite tables and user identities as CSV or JSON and import them before expecting existing users, assignments, audit history, incidents, or settings to appear. Existing provider credentials must be configured securely on the backend.

## Verification matrix

The live browser run exercised the login screen, API health check, Admin shell, Vendor shell, User shell, and both map simulations against a locally started FastAPI service. It verified that admin user listing is denied to vendor and standard-user sessions. Test sessions and their isolated local test database are outside the project and service database. Google sign-in could not be completed because Google OAuth and the JWT signing secret are absent. The API reports Wazuh Manager and Indexer as unconfigured; live SOC data, AI providers, threat-intelligence feeds, SMTP, and incident-response execution therefore remain unverified. The 236-test backend suite checks the source service without modifying it.

The Lovable-hosted preview does not run the bundled FastAPI service; its sign-in page will show the API as unavailable until the API is deployed or started where the browser can reach it. For a deployed API, set `VITE_API_BASE_URL`, allow the exact preview origin in backend `CORS_ALLOWED_ORIGINS`, and redeploy the frontend.

| Page | Connected endpoints | Verification |
|---|---|---|
| Sign-in and session | `/health`, `/auth/status`, `/auth/google`, `/auth/google/signup` (additive: self-sign-up, standard User role only), `/auth/me`, `/auth/logout` | Browser: health and sign-in screen. Backend tests: auth/session controls. Google sign-in unavailable without OAuth and JWT configuration. |
| Operations overview | `/health`, `/wazuh/manager/info`, `/wazuh/manager/agents`, `/wazuh/indexer/health`, `/wazuh/indexer/alerts`, `/detections/summary` | Admin shell live; API features not live-tested because Wazuh is unconfigured. Backend tests passed. |
| Wazuh alerts | `/wazuh/indexer/alerts` | Backend tests only; Wazuh unavailable. |
| Wazuh agents | `/wazuh/manager/agents` | Backend tests only; Wazuh unavailable. |
| Detections | `/detections/run`, `/detections/alerts`, `/detections/alerts/{id}` | Backend tests only; live Wazuh data unavailable. |
| Incidents | `/detections/incidents`, `/detections/incidents/{id}` | Backend tests only; live Wazuh data unavailable. |
| Detection rules | `/detections/rules`, `/detections/rules/{key}` | Backend tests only; live Wazuh data unavailable. |
| Incident response | `/ir/summary`, `/ir/actions`, `/ir/actions/{id}/approve`, `/reject`, `/retry`, `/rollback`, `/ir/playbooks`, `/ir/playbooks/{key}`, `/ir/recommend/{alert_id}`, `/ir/audit`, `/ir/audit/verify` | Backend tests only; Wazuh unavailable and execution disabled by default. |
| Notifications | `/notifications`, `/notifications/summary`, `/notifications/preferences`, `/notifications/rules`, `/notifications/deliveries`, `/notifications/evaluate`, `/notifications/test-email`, `/notifications/read-all`, `/notifications/{id}/read`, `/notifications/{id}/unread` | Backend tests only; SMTP unavailable. |
| Threat intelligence | `/ti/summary`, `/ti/status`, `/ti/iocs`, `/ti/iocs/{id}`, `/ti/iocs/{id}/refresh`, `/ti/correlations`, `/ti/scan`, `/ti/lookup` | Backend tests only; live threat-feed providers unavailable. |
| Threat hunting | `/hunting/analysis`, `/hunting/events` | Backend tests only; Wazuh unavailable. |
| Reports & analytics | `/reports/summary`, `/reports/export` (CSV/PDF) | Backend tests only; live SOC data unavailable. |
| AI SOC Investigator | `/ai/status`, `/ai/soc/ask` | Admin tools visible live; AI page and requests not live-tested because provider credentials are unavailable. Backend tests passed. |
| AI Email Router | `/ai/status`, `/ai/email/analyze` | Admin tools visible live; AI page and requests not live-tested because provider credentials are unavailable. Backend tests passed. |
| Users & roles | `/users`, `/users/{id}`, `/rbac/roles`, `/vendors/{id}/agents` | Admin API access and vendor/user denial checked live; backend RBAC and vendor-isolation tests passed. |
| Audit trail | `/audit/logs`, `/ir/audit/verify` | Backend tests only; no source audit records were included. |
| My profile | `/rbac/me` | Role shells checked live; profile view not opened. Backend RBAC tests passed. |
| My agents | `/vendor/agents` | Vendor navigation checked live; backend vendor-isolation tests passed. Wazuh unavailable. |
| My alerts | `/vendor/alerts` | Backend vendor-isolation tests only; Wazuh unavailable. |
| My detections | `/vendor/detections/alerts`, `/vendor/detections/incidents` | Backend vendor-isolation tests only; Wazuh unavailable. |
| My responses | `/vendor/ir/actions` | Backend tests only; Wazuh unavailable. |
| My notifications | `/vendor/notifications`, `/vendor/notifications/summary`, `/vendor/notifications/preferences`, `/vendor/notifications/read-all` | Vendor navigation checked live; backend vendor-isolation tests passed. |
| My threat intelligence | `/vendor/ti/iocs`, `/vendor/ti/correlations` | Backend vendor-isolation tests only; provider feeds unavailable. |
| My threat hunting | `/vendor/hunting/analysis`, `/vendor/hunting/events` | Backend vendor-isolation tests only; Wazuh unavailable. |
| My reports | `/vendor/reports/summary`, `/vendor/reports/export` (CSV/PDF) | Backend vendor-isolation tests only; SOC data unavailable. |
| Pickup simulation | No carrier API; OpenStreetMap tiles and OSRM routing | Vendor route and play/pause/resume/reset checked live; map services may fall back when unavailable. |
| Delivery simulation | No carrier API; OpenStreetMap tiles and OSRM routing | User route and play/pause/resume/reset checked live; map services may fall back when unavailable. |

“Backend tests” refers to the original 236 passing FastAPI tests; it does not claim every listed endpoint was individually called or that an external provider was connected live.


## Google sign-in, self-sign-up and MFA
See [docs/GOOGLE_AUTH.md](docs/GOOGLE_AUTH.md) for the sign-up flow, configuration, run commands and the MFA limitation (Google, not FreightShield, controls MFA).
