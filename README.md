FreightShield SOC
An AI-assisted Security Operations Center for freight and logistics environments.

FreightShield SOC brings security monitoring, incident management, threat intelligence, threat hunting, response workflows, reporting, notifications, and AI-assisted investigation into one role-aware platform. It is designed around the Harbor & Finch Freight case study and the Defense track: detect suspicious activity, reduce operational blind spots, protect sensitive records, and support accountable incident response.
Table of Contents
- Project Overview
- Key Capabilities
- Technology Stack
- System Architecture
- User Roles
- Project Structure
- Getting Started
- Environment Configuration
- Security Design
- Testing and Verification
- Important Deployment Notes
- Known Limitations
Project Overview
FreightShield addresses operational security gaps such as:
- Former employees retaining access after termination.
- Unusual bulk exports and unexpected data-access volume.
- Security notifications being routed to the wrong department.
- Vendor or payment-record changes made through overprivileged integrations.
- Sensitive credentials appearing in support records.
- Audit findings remaining open without verified closure.
The platform combines preventive access controls with detection, investigation, response, and governance workflows. It does not assume that every alert proves malicious activity; analysts must validate evidence and context.
Key Capabilities
Area	Capability
Identity and access	Authentication, role-based access control, vendor scoping
Wazuh monitoring	Manager agent information and Indexer alerts
Detection	Rule-based detections, alert lifecycle, incident correlation
AI assistance	SOC investigation and email classification/routing analysis
Incident response	Playbooks, recommendations, approval-gated response actions
Threat intelligence	IOC extraction, enrichment, risk scoring, and correlation
Reporting	Security summaries, alert/incident exports, operational metrics
Notifications	In-app notifications, escalation rules, optional email delivery
Threat hunting	Behaviour-pattern searches, event correlation, MITRE mapping
API key protection	Encrypted provider-key storage through the integrated vault


Technology Stack
Frontend
- React 19 for the component-based user interface.
- TypeScript for typed application code.
- Vite for local development and production builds.
- Tailwind CSS 4 for styling.
- TanStack Router for application routing.
- TanStack React Query for API data fetching, caching, and synchronization.
- Recharts for data visualizations.
The current frontend is a React + TypeScript application. It uses the npm/Vite ES-module toolchain; it is not the earlier vanilla-JavaScript DOM application.
Backend
- Python 3.10+
- FastAPI
- SQLite for application-managed persistence
- Wazuh Manager API and Wazuh Indexer/OpenSearch integration
- AI agent integrations and external threat-intelligence providers
System Architecture
┌──────────────────────────────────────────────┐
│            React + TypeScript UI             │
│       Vite · Tailwind · TanStack Query        │
└──────────────────────┬───────────────────────┘
                       │ HTTPS / REST
┌──────────────────────▼───────────────────────┐
│                 FastAPI Backend              │
│ Auth · RBAC · Detection · Incidents · AI      │
│ SOAR · Threat Intel · Hunting · Reports      │
│ Notifications · Audit · Key Vault            │
└───────┬──────────────┬──────────────┬────────┘
        │              │              │
     Wazuh         SQLite DB      External APIs
 Manager/Indexer                 AI · TI · SMTP
The frontend consumes the backend API. Authorization and vendor data isolation must be enforced by the backend; hiding a page in the UI is not a security boundary.
User Roles
FreightShield exposes three primary application roles:
Role	Intended access
IT Security Administrator (admin)	Security operations, configuration, investigations, approvals, users, audit, and administration
User (user)	User-facing operational views permitted by the backend
Vendor (vendor)	Read-only, vendor-scoped views for assigned agents and related records


The backend is the authority for role checks and vendor-to-agent scope. Do not rely on client-side role checks alone.
Project Structure
FreightShield/
├── backend/                 # FastAPI application and services
│   ├── app/
│   ├── agents/
│   ├── tests/
│   └── ...
├── src/                     # React + TypeScript frontend source
├── public/                  # Static frontend assets
├── package.json             # npm scripts and frontend dependencies
├── vite.config.*            # Vite configuration
├── index.html               # Vite application entry
├── README.md
└── ...
Folder names may vary slightly by packaged revision; use the paths present in the archive.
Getting Started
Prerequisites
- Node.js 20 or newer and npm
- Python 3.10 or newer
- Access to a Wazuh Manager/Indexer if live SOC telemetry is required
- Provider credentials only for the integrations you intend to enable
1. Start the frontend
From the project root:
npm install
cp .env.example .env
npm run dev
The Vite development server prints the local frontend URL when it starts.
2. Configure and start the backend
cd backend
python -m venv .venv

# macOS/Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements-dev.txt
cp .env.example .env
python -m app.cli create-admin admin@example.com
uvicorn app.main:app --reload --port 8000
If your checkout uses a different backend entry point or setup script, follow the backend-specific README and .env.example included in that checkout.
3. Build and test the frontend
npm run build
npm test
npm run lint
If the package provides browser end-to-end tests:
npx playwright install chromium
npm run test:e2e
4. Run backend tests
cd backend
pytest
Run the frontend and backend together when testing the integrated application.
Environment Configuration
Configure secrets in the backend .env file. Typical integration settings include:
Integration	Configuration
Google sign-in	GOOGLE_CLIENT_ID and the configured authentication/JWT settings
Wazuh Manager	Manager URL, username, password, and TLS verification setting
Wazuh Indexer	Indexer URL, username, password, and TLS verification setting
Threat intelligence	VirusTotal, AbuseIPDB, and OTX API keys
AI services	Provider API keys and agent-specific settings
Email notifications	SMTP host, port, username, password, and TLS settings
API key vault	FREIGHTSHIELD_VAULT_MASTER_KEY


Use the exact variable names in the current backend/.env.example; names can differ between revisions. Keep .env files and master keys out of source control. The Google client ID used by the browser is public configuration; provider secrets, Wazuh credentials, signing secrets, and the vault master key must remain server-side.

Generate and back up the vault master key using the project-provided key-generation script. Store it separately from the database. Losing the master key can make encrypted credentials unrecoverable.
Security Design
- Backend-enforced role checks and vendor data scoping.
- Server-side handling of provider credentials.
- Approval-gated incident-response actions, with execution disabled by default unless explicitly configured.
- Audit records for security-sensitive operations.
- Input validation and safeguards around response actions.
- Encrypted API-key storage when the vault is configured.
Encryption at rest does not protect secrets from a compromised running backend or an attacker who can access the vault master key. Rotate/revoke provider credentials if compromise is suspected. Review the included security documentation before deployment.
Testing and Verification
The project archive includes backend and frontend test assets. Reported automated test totals are development results, not a substitute for deployment-specific validation.

Before a live demonstration or deployment, verify:
1. Frontend production build and browser navigation.
2. Backend test suite and health endpoint.
3. Login, logout, and each role's access restrictions.
4. Vendor isolation using more than one vendor account.
5. Wazuh Manager and Indexer connectivity from the backend host.
6. AI provider, threat-intelligence, and SMTP connectivity.
7. API-key vault encryption/decryption with the configured master key.
8. Incident-response safeguards in a lab environment before enabling execution.
A passing mocked or local test does not prove that a private Wazuh instance or external provider is reachable.
Important Deployment Notes
- A frontend hosted on a public platform cannot directly reach a private LAN address such as 192.168.x.x. The backend must be reachable through a properly secured network path, VPN, or controlled deployment.
- Configure CORS for the exact frontend origin.
- Configure Google OAuth authorized origins and redirect settings for the deployed frontend.
- Use HTTPS in deployed environments.
- Keep response execution disabled until Wazuh Active Response commands and rollback procedures have been tested in a lab.
- Back up the SQLite database and vault master key separately and securely.
- Do not commit .env, API keys, passwords, JWT secrets, or vault keys.
Known Limitations
- Live integrations depend on credentials, network reachability, TLS configuration, and provider availability.
- AI analysis quality and availability depend on the configured model/provider.
- Email analysis does not imply automatic mailbox ingestion or forwarding unless the corresponding connector is configured and verified.
- Carrier tracking/map demonstrations are simulations where no live carrier-tracking API is connected.
- Threat-intelligence results may be incomplete when feeds are unavailable, rate-limited, or have no result for an indicator.
- Response execution should be treated as a controlled administrative operation, not an automatically safe action.
FreightShield SOC — Detect. Investigate. Respond. Govern.
