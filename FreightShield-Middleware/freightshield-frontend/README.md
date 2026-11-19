# FreightShield SOC Frontend
Static app (no build step): Google OAuth sign-in, role-based navigation, SOC views (dashboard, alerts, agents, incidents, AI assistant, user roles).

## Run
```bash
cp js/config.example.js js/config.js   # set GOOGLE_CLIENT_ID and API_BASE_URL
python3 -m http.server 5173            # then open http://localhost:5173
```
Add `http://localhost:5173` (and your Vercel URL) as **Authorized JavaScript origins** for the OAuth client in Google Cloud Console, and to the backend `CORS_ALLOWED_ORIGINS`.

## How auth + RBAC work
1. Google Sign-In returns an ID token in the browser.
2. Frontend sends it to `POST /api/auth/google`; the **backend must verify it** (signature, audience, expiry), look up the user's role, and set an httpOnly session cookie.
3. `GET /api/auth/me` -> `{email,name,role}`; `POST /api/auth/logout`.
4. Roles: `admin`, `analyst`, `viewer` (see `js/rbac.js`). The UI only hides pages; **the backend must enforce permissions on every route**.

## Backend routes this frontend expects
Existing: `/api/wazuh/manager/agents`. Not built yet (frontend shows an honest "not available" message): `/api/auth/*`, `/api/wazuh/indexer/alerts`, `/api/incidents`, `/api/ai/chat`, `/api/rbac/users`.
No fake data is shown anywhere; Wazuh credentials never reach the browser.
