# FreightShield SOC Backend (FastAPI)

Phase 1–10 backend for the SOC platform. Google sign-in, Admin/User/Vendor RBAC, vendor-scoped reads, AI agent endpoints, detections, notifications, incident response, threat intelligence, reporting, and threat hunting are implemented. Wazuh credentials and other private provider keys stay server-side; the frontend only talks to `/api/*`.

## Setup
```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # configure local values; never commit .env
python -m app.cli create-admin admin@example.com
uvicorn app.main:app --reload --port 8000
```
Check: `curl http://localhost:8000/api/health` · Docs: http://localhost:8000/docs

Create the Google OAuth client and configure `GOOGLE_CLIENT_ID`, `AUTH_JWT_SECRET`, `CORS_ALLOWED_ORIGINS`, and the Wazuh endpoints and credentials in `.env`. See `SECURITY.md` before production. The AI agents, threat-intelligence feeds, and mail delivery require their corresponding provider configuration; they fail visibly when not configured.

## Structure
- `app/main.py` – app, CORS, routers
- `app/core/` – config (env), shared errors
- `app/routes/` – health, auth, rbac, wazuh, ai
- `app/services/` – `wazuh_manager.py` (port 55000), `wazuh_indexer.py` (port 9200)

## Notes
- `CORS_ALLOWED_ORIGINS`: comma-separated; add your Vercel URL.
- Unconfigured Wazuh -> 503 `not_configured`; unreachable/bad creds -> 502/503 `upstream_error`.
- Before production: set `APP_ENV=production` (Secure/SameSite=None session cookie), use a trusted TLS cert (`WAZUH_VERIFY_SSL=true`).


## Wazuh (Phase 2)
- `GET /api/wazuh/indexer/alerts?limit=25&page=1&min_level=` (limit 1-100, page*limit <= 10000), `GET /api/wazuh/manager/agents`, `/manager/info`, `/indexer/health`.
- All Wazuh routes require a valid session JWT (cookie `fs_session` or Bearer, HS256, `AUTH_JWT_SECRET` >= 32 chars) with a role that holds the route's permission (`admin` for `/api/wazuh/*`). No secret configured = 503 (fail closed).
- Tests: `pip install -r requirements-dev.txt && python -m pytest` (Wazuh/Google calls are faked in unit tests; they prove logic, not connectivity).


## RBAC + auth (Phase 1)
Exactly three roles (`app/core/roles.py`): `admin` = **IT Security Administrator**, `user` = **User**, `vendor` = **Vendor**. Stored in SQLite (`users.role` with a CHECK constraint); the JWT carries only the user id, so role/disable changes apply on the next request.
- First admin: `python -m app.cli create-admin you@example.com`, then manage users via `/api/users`. Only pre-registered, active users can sign in.
- `POST /api/auth/google {credential}` verifies the Google ID token (Google JWKS, audience = `GOOGLE_CLIENT_ID`, issuer, expiry, verified email) and sets the httpOnly `fs_session` cookie. `POST /api/auth/google/signup {credential}` (additive) verifies the same token and creates a new account with the standard `user` role only (409 if the email already exists; disable with `SELF_SIGNUP_ENABLED=false`). `GET /api/auth/me`, `POST /api/auth/logout`, `GET /api/auth/status`.
- Permissions: admin = Wazuh read/agents/alerts, users, audit, AI. Vendor = `vendor:agents`, `vendor:alerts`. User = profile only.
- Vendor isolation: admins assign Wazuh agents with `PUT /api/vendors/{vendor_id}/agents/{agent_id}`; vendors use `/api/vendor/agents` and `/api/vendor/alerts`, scoped server-side by their own user id (never a client parameter). Unassigned vendors never trigger a Wazuh call.
- Audit log (`/api/audit/logs`): logins (success/denied), logout, access denials, sensitive reads, user and vendor-assignment changes.

## Phase 2 live verification
With the backend running and `.env` filled in: `python -m scripts.verify_integration [--google-credential <real ID token>]` (nothing mocked; PASS/FAIL/SKIP per check).

## Detection (Phase 3)
Real Wazuh alerts are read from the Indexer (`wazuh-alerts-*`, last `DETECTION_LOOKBACK_SECONDS` or the longest rule window), normalized, and evaluated by rules in `app/services/detection.py`. Nothing is synthesized; if Wazuh is down/unconfigured the scan returns 503/502 and creates nothing.
- **Rules** (thresholds/window/severity/min Wazuh level/enabled are stored in SQLite and editable via `PUT /api/detections/rules/{key}`): `auth_bruteforce` (>=5 auth failures per agent+source IP in 5 min, high, MITRE T1110), `high_level_event` (Wazuh `rule.level` >= 10, MITRE taken from Wazuh's own `rule.mitre`), `fim_burst` (>=10 syscheck events/agent in 5 min, medium). MITRE comes from Wazuh when present, otherwise the static mapping on the rule; rules without an applicable technique have none.
- **Dedupe:** one alert per rule+group; a rescan refreshes the open alert instead of creating another. A resolved/false-positive alert re-triggers only on events newer than it.
- **Incidents:** alerts on the same agent within 30 min join one incident (severity = max, MITRE merged). Correlation is per agent so vendor isolation holds.
- **Statuses:** alerts `new -> acknowledged -> investigating -> resolved | false_positive`; incidents `open | investigating | resolved`. Admin notifications (in-app, `GET /api/notifications`) are created for new alerts at or above `DETECTION_NOTIFY_MIN_SEVERITY`.
- **Run:** `POST /api/detections/run` (admin) or set `DETECTION_INTERVAL_SECONDS` > 0 for a background scan. All changes, scans and alert creation are audited.
- **RBAC:** admin = full; vendor = read-only `/api/vendor/detections/*` for assigned agents only; user = none.
- Tests: `tests/test_detection_engine.py` and `tests/test_detection_api.py` use SYNTHETIC events (logic only). `scripts/verify_integration.py` includes the LIVE detection checks.

## Phase 4 – AI agents
Existing CrewAI projects live unmodified in `agents/`. Install their deps with `pip install -r requirements-ai.txt`, set `OPENAI_API_KEY` and `EXA_API_KEY` in `.env` (server-side only).
- `GET /api/ai/status` – readiness + missing prerequisites per agent
- `POST /api/ai/soc/ask` – SOC Investigator crew (live Wazuh via the agent's read-only tool)
- `POST /api/ai/email/analyze` – Harbor Email Router classification (flow.json steps reused); recommendation only, nothing is forwarded
All require the `ai:use` permission (admin); every call is audited without content. Tests: `pytest tests/test_ai.py` (agents mocked).

## Phase 5 – Incident response
Playbooks (`ir_playbooks`, seeded defaults, admin-editable) turn detection alerts into **pending** recommendations. An IT Security Administrator must approve each action; only then is it executed through Wazuh Active Response (`PUT /active-response`, single agent). Nothing executes automatically, and `IR_EXECUTION_ENABLED=false` (default) refuses all execution.
- Actions: `block_ip` (public IPs only; private/loopback/reserved, `IR_PROTECTED_IPS` and agent 000 refused), `isolate_agent` (only if you define a custom AR command in Wazuh and set `IR_AR_ISOLATE_COMMAND`). Rollback needs `IR_AR_UNBLOCK_COMMAND` / `IR_AR_UNISOLATE_COMMAND`; otherwise it is reported as manual.
- Workflow: pending -> approved+executing -> executed | failed (retry) -> rolled_back | rollback_failed; or rejected / unsupported.
- API: `/api/ir/{summary,playbooks,recommend/{alert_id},actions,actions/{id}/{approve|reject|retry|rollback},audit,audit/verify}`; vendors: read-only `/api/vendor/ir/actions` scoped to their agents.
- `ir_audit` is hash-chained and UPDATE/DELETE are blocked by SQLite triggers; `/audit/verify` recomputes the chain. Tests: `pytest tests/test_ir.py`.

## Phase 8 – SOC notifications & escalation
In-app notifications plus optional email, driven by real detection / response / threat-intel data (nothing synthesized).
- **Categories:** `critical_alert`, `alert`, `new_incident` (one notification per detection event; critical wins over new-incident, new-incident over plain alert), `pending_approval` (IR action waiting for an admin), `threat_intel` (IOC scored high/critical by a feed AND seen on an agent; one per IOC+agent+risk), `overdue_incident` (level 1 = past SLA, level 2 = escalated).
- **Escalation rules** (`escalation_rules`, seeded defaults, admin-editable via `PUT /api/notifications/rules/{severity}`): per severity `enabled`, `email`, `sla_minutes`, `escalate_after_minutes` (0 = never). Defaults: critical 60/60, high 240/240, medium 1440/off, low 4320/off. Only critical/high email by default. Level-2 notifications also go to `NOTIFY_ESCALATION_EMAILS`.
- **Automation:** detection scans create notifications inline; the evaluator (`NOTIFY_INTERVAL_SECONDS`, default 300, 0 = off; also after each scan and on `POST /api/notifications/evaluate`) raises overdue/escalation, pending-approval and threat-intel notifications and sends pending email. All checks are idempotent (dedupe keys).
- **Email:** off until `NOTIFY_EMAIL_ENABLED=true` and `SMTP_HOST`/`SMTP_FROM` are set. STARTTLS or implicit TLS with certificate verification; credentials are refused without TLS. Outbox pattern: rows are written first, sent after commit, every attempt stored in `notification_deliveries`, up to `NOTIFY_EMAIL_MAX_ATTEMPTS`. Admins are opted in by default (min severity high), vendors opt in. Vendors are only emailed for vendor-visible notifications on their own agents. Switching email on later does not mass-mail history. SMTP secrets are never returned (`GET /api/notifications/status` returns booleans) or audited.
- **API (admin, `notifications:read`/`manage`):** `GET /api/notifications` (filters `category,severity,read,unread`), `/summary`, `/status`, `/deliveries`, `/rules`, `/preferences`, `/{id}`, `POST /{id}/read|unread`, `/read-all`, `PUT /rules/{severity}`, `PUT /preferences`, `POST /evaluate`, `POST /test-email` (sends to the caller's own address only).
- **Vendor (`vendor:notifications`):** `/api/vendor/notifications` (+ `/summary`, `/preferences`, `/{id}`, `/{id}/read|unread`, `/read-all`): only vendor-visible categories scoped to the vendor's own agents (scope from `vendor_agents`, never a parameter). `pending_approval` and `overdue_incident` are admin-only. `user` role: no access.
- **Read/unread is per user** (`notification_reads`). Phase 3 `notifications` table is migrated in place (old rows stay, category `alert`).
- **Audit:** `notification_create`, `notification_read|unread|read_all`, `notification_prefs_update`, `escalation_rule_update`, `notification_evaluate`, `notification_test_email`, `notification_email_sent|failed`, plus every access denial.
- Tests: `tests/test_notifications_service.py`, `tests/test_notifications_api.py` (simulated inputs + fake SMTP). Live SMTP check: `python -m scripts.verify_notifications --to you@example.com`.

## Phase 9 – Advanced threat hunting
Hunts run directly against REAL Wazuh alerts (`wazuh-alerts-*`); nothing is synthesized or stored. If the Indexer is down or unconfigured the API returns 503/502 – never sample data.
- **Filters** (query params, validated server-side, 422 on bad input): `hours` (1-720, default 24) or `start`/`end` (ISO), `agent_id`, `min_level`/`max_level`, `rule_id`, `group` (rule.groups), `technique` (`rule.mitre.id`, e.g. T1110 / T1110.003), `tactic` (ATT&CK tactic name), `src_ip`, `user` (dstuser/srcuser/Windows targetUserName), `q` (simple_query_string on `rule.description` + `full_log`, max 200 chars). All become one OpenSearch `bool` filter (`app/services/hunting.py: build_query`).
- **Suspicious behaviour** (over the newest `HUNT_MAX_EVENTS` events of the range, default 5000): `password_spray` (1 source, >=5 accounts failed in 15 min, T1110.003), `bruteforce_success` (>=3 failures then a success, same source+agent, 15 min, T1110+T1078, critical), `lateral_movement` (1 source authenticating on >=3 agents in 30 min, T1021), `privilege_escalation` (>=3 sudo/su failures by one account in 10 min, or a Wazuh-tagged Privilege Escalation event at level >=7, T1548 / Wazuh's own technique), `sensitive_file_change` (FIM on passwd/shadow/sudoers/authorized_keys/cron/systemd/Run keys -> T1098/T1548/T1053/T1543/T1547), `multi_tactic_chain` (>=3 distinct tactics on one agent in 60 min, critical).
- **Alert correlation:** per-agent activity chains (gaps <= 30 min) kept when they show >=2 tactics, a Wazuh level >=10 or a behaviour finding; scored 0-100 (tactics, max level, behaviours, volume) and linked to the Phase 3 detection alerts of the same agent and time span.
- **MITRE mapping:** ATT&CK matrix in kill-chain order from Wazuh's own `rule.mitre` tags (aggregations = exact counts over the whole range) plus the techniques inferred by the behaviours.
- **Stats:** top rules/agents/source IPs/users/groups, level distribution, timeline (OpenSearch aggregations).
- **API:** admin (`hunt:read`): `GET /api/hunting/events?limit=&page=&<filters>`, `GET /api/hunting/analysis?<filters>`, `GET /api/hunting/catalog`. Vendor (`vendor:hunt`): `/api/vendor/hunting/{events,analysis,catalog}` – every query gets a `terms agent.id` filter from `vendor_agents` (caller's own id), results are re-filtered by agent after the upstream call, `agent_id` outside the scope = 404, an unassigned vendor never triggers a Wazuh call. `user` role: no access.
- **Audit:** every hunt is logged (`hunt_query`, `hunt_analysis`) with its filters; all denials are logged as `access_denied`.
- **Env:** `HUNT_MAX_EVENTS` (default 5000, capped at 10000). No new tables; Phase 1-8 data is untouched.
- Tests: `pytest tests/test_hunting.py` (SIMULATED Wazuh-shaped hits: logic, RBAC and isolation). Live: `python -m scripts.verify_integration` now includes a Phase 9 section.

## Phase 10 — Security hardening
See [SECURITY.md](SECURITY.md). Run tests: `pytest -q` (236 tests).

## Phase 11 – Encrypted API-key vault
- Admin-only, write-only secret management at `/api/vault/secrets`; secret values are never returned.
- Supported keys: `OPENAI_API_KEY`, `EXA_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`.
- Values are encrypted in SQLite using XChaCha20-Poly1305 (PyNaCl/libsodium). The 32-byte master key is supplied separately as 64 hex characters in `FREIGHTSHIELD_VAULT_MASTER_KEY`.
- Generate a key with `python -m scripts.generate_vault_key`. Back up the master key securely. Losing it makes encrypted values unrecoverable.
- Existing `.env` keys remain as a compatibility fallback until explicitly moved into the vault. After verifying vault-backed integrations, remove those values from `.env`.
- The vault is write-only over HTTP: admins can list configured/masked metadata, set, or delete keys; there is no API to reveal a stored key.
- Install `PyNaCl` via `pip install -r requirements.txt`. Never commit `.env` or the master key.
