# FreightShield SOC
### Intelligent Security Operations Center Platform

**Detect. Investigate. Enrich. Respond. Protect.**

FreightShield SOC is an AI-assisted Security Operations Center platform designed to help organizations monitor security events, detect suspicious behaviour, investigate threats, manage incidents and coordinate security responses through a centralized interface.

The platform integrates Wazuh monitoring, threat intelligence, AI-assisted investigations, automated detection, incident response, reporting, notifications and threat hunting.

---

## 1. Project Overview

Modern organizations face security challenges such as unauthorized access, suspicious data exports, compromised credentials, malicious API activity and delayed incident response.

FreightShield SOC addresses these challenges through a centralized security monitoring and investigation platform.

The system aims to provide:

- Centralized security monitoring.
- Automated threat detection.
- AI-assisted security investigations.
- Threat intelligence enrichment.
- Incident management and response.
- Role-based access control.
- Security reporting and analytics.
- Automated notifications and escalation.
- Behaviour-based threat hunting.
- Secure API key management.

## 2. Key Features

| Module | Description |
|---|---|
| Authentication & RBAC | Secure authentication and Admin, User and Vendor roles |
| Wazuh Integration | Security event and agent monitoring |
| Detection Engine | Rule-based alert detection and correlation |
| AI SOC Copilot | AI-assisted investigation and analysis |
| Email Intelligence | Security email classification and routing recommendations |
| Incident Response | Approval-based security response workflows |
| Threat Intelligence | IOC enrichment using external intelligence providers |
| Reports & Analytics | Security metrics, reports and PDF/CSV exports |
| Notifications | In-app notifications, email configuration and escalation |
| Threat Hunting | Behaviour detection, MITRE ATT&CK mapping and event correlation |
| API Key Vault | Encrypted API key storage and controlled backend access |

## 3. Technology Stack

**Frontend**
- HTML5
- CSS3
- JavaScript ES Modules

**Backend**
- Python
- FastAPI
- REST APIs

**Security Monitoring**
- Wazuh Manager
- Wazuh Indexer
- OpenSearch

**Database and Security**
- SQLite
- JWT authentication
- Role-based access control
- XChaCha20-Poly1305 encryption for the API Key Vault

**AI and Threat Intelligence**
- Gemini / configured AI provider
- CrewAI-based investigation agents
- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Exa

*Actual provider availability depends on configuration, credentials and network access.*

## 4. System Architecture

```text
                 USERS
                   |
                   v
        FREIGHTSHIELD FRONTEND
                   |
                   v
           PYTHON FASTAPI
                   |
        +----------+-----------+
        |          |           |
        v          v           v
      WAZUH      DATABASE    API KEY VAULT
        |          |           |
        v          v           v
     ALERTS     INCIDENTS    ENCRYPTED KEYS
        |
        v
  DETECTION ENGINE
        |
        v
  THREAT INTELLIGENCE
        |
        v
   AI SOC ANALYST
        |
        v
  INCIDENT RESPONSE
        |
        v
 REPORTS & NOTIFICATIONS
        |
        v
    THREAT HUNTING
```

## 5. Implemented Development Phases

### Phase 1 – Authentication and RBAC
- Admin, User and Vendor roles.
- Authentication and authorization.
- Vendor-specific agent access.
- Backend permission enforcement.

### Phase 2 – Wazuh Integration
- Wazuh Manager integration.
- Wazuh Indexer integration.
- Agent and security-event retrieval.

### Phase 3 – Detection Engine
- Brute-force detection.
- High-severity event detection.
- File-integrity event burst detection.
- Alert correlation and incident management.

### Phase 4 – AI Integration
- SOC AI investigation assistant.
- Email classification and routing recommendations.
- Integration of existing AI agent projects.

### Phase 5 – Incident Response
- Configurable response playbooks.
- Approval-based response execution.
- Wazuh Active Response integration.
- Response audit history.

### Phase 6 – Threat Intelligence
- IOC extraction and normalization.
- VirusTotal, AbuseIPDB and OTX enrichment.
- Risk scoring and alert correlation.
- Threat intelligence dashboard.

### Phase 7 – Reports and Analytics
- Alert and incident reports.
- MTTA and MTTR calculations.
- PDF and CSV exports.
- Vendor-scoped reporting.

### Phase 8 – Notifications and Escalation
- In-app notifications.
- Email notification configuration.
- Severity-based escalation.
- Notification history and read/unread tracking.

### Phase 9 – Advanced Threat Hunting
- Behaviour-based detection.
- Suspicious activity identification.
- Alert correlation into attack chains.
- MITRE ATT&CK mapping.
- Advanced Wazuh event filtering.
- Threat Hunting dashboard.

### API Key Vault – Security Enhancement
- XChaCha20-Poly1305 authenticated encryption.
- Separate 256-bit master encryption key.
- Encrypted API key storage.
- Backend-only secret access.
- Administrative secret management.
- Audit logging.

## 6. Role-Based Access Control

FreightShield supports three primary roles.

| Capability | Administrator | User | Vendor |
|---|:---:|:---:|:---:|
| Security dashboard | Full | Permitted data | Scoped data |
| Wazuh monitoring | Yes | Restricted | Assigned agents |
| Incident management | Full | Permitted actions | Read-only scope |
| Threat intelligence | Full | Restricted | Assigned scope |
| Incident response | Yes | No | Read-only scope |
| Reports | Full | Permitted data | Own data |
| Notifications | Full | Restricted | Own notifications |
| Threat hunting | Full | Restricted | Assigned agents |
| User management | Yes | No | No |
| API key management | Yes | No | No |

All permissions must be enforced by backend authorization, not merely by hiding frontend controls.

## 7. Installation and Setup

### Prerequisites

- Python 3.10 or later (use the version supported by the project dependencies).
- pip.
- Git.
- Node.js only if using a frontend build tool.
- Access to a configured Wazuh Manager and Indexer.
- API credentials for the integrations you intend to enable.

### Clone the Repository

```bash
git clone https://github.com/SandyaSundar/FreightShield.git
cd FreightShield
```

### Backend Setup

Navigate to the backend directory:

```bash
cd freightshield-backend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a local `.env` file using the project's environment variable template.

Start the backend using the project's configured FastAPI entry point. For example, if the application entry point is `app.main:app`:

```bash
uvicorn app.main:app --reload
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### Frontend Setup

The existing frontend uses HTML, CSS and JavaScript ES Modules.

Serve the frontend using a local development server and configure its API base URL to point to the FastAPI backend.

Do not open the HTML file directly if the application relies on ES modules or API routing.

## 8. Environment Configuration

Keep credentials in the backend `.env` file.

Typical configuration categories include:

```env
# Application
APP_ENV=development

# Wazuh
WAZUH_MANAGER_URL=
WAZUH_INDEXER_URL=
WAZUH_MANAGER_USER=
WAZUH_MANAGER_PASSWORD=
WAZUH_INDEXER_USER=
WAZUH_INDEXER_PASSWORD=

# Authentication
GOOGLE_CLIENT_ID=

# AI
AI_SOC_LLM_MODEL=

# Threat Intelligence
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=

# API Key Vault
FREIGHTSHIELD_VAULT_MASTER_KEY=

# Notifications
SMTP_HOST=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=
```

Use the exact variable names expected by the corresponding project modules. The above is a configuration reference, not a replacement for the project's `.env.example`.

**Never commit `.env` files, passwords, API keys or master encryption keys to GitHub.**

## 9. API Key Vault Security

FreightShield includes an API Key Vault implementation intended to protect third-party integration credentials.

Security design:

- API keys are encrypted before database storage.
- A separate 32-byte master key is used.
- XChaCha20-Poly1305 provides authenticated encryption.
- Secrets are decrypted only when required by backend integrations.
- Secret values are not intended to be returned to frontend clients.
- Administrative secret operations are audited.

**Important security requirements:**

1. Keep the master key separate from the database.
2. Back up the master key securely.
3. Rotate provider credentials immediately if compromised.
4. Test encryption and decryption with the required cryptographic dependency installed.
5. Complete an independent security review before production use.

Encryption at rest does not protect secrets from a fully compromised running backend.

## 10. Testing

Run the project's test suite from the backend directory:

```bash
python -m pytest
```

The development reports recorded:

| Development milestone | Reported result |
|---|---|
| Phase 9 package | 209 tests passed |
| Vault-integrated package | 236 passed, 1 skipped |

The skipped vault test required PyNaCl, which was unavailable in the offline development environment.

Additional checks include Python compilation, frontend JavaScript syntax validation, simulated service tests and PDF export validation.

These are reported development results, not independent certification. Live Wazuh connectivity, live provider calls, SMTP delivery and complete browser-based end-to-end operation still require verification in the target environment.

## 11. Security Considerations

FreightShield is designed with the following security principles:

- Least-privilege access.
- Backend-enforced RBAC.
- Vendor data isolation.
- Secure credential handling.
- Approval before sensitive response actions.
- Audit logging.
- Threat intelligence enrichment.
- Input validation.
- Secure API communication.

Production deployment should additionally verify HTTPS, CSRF protection where applicable, rate limiting, session security, dependency vulnerabilities, database backups and secret rotation.

## 12. Project Limitations and Future Improvements

Areas requiring further validation or development include:

- Live Wazuh integration testing in the target network.
- Full cryptographic vault testing and independent review.
- Browser-based frontend and mobile testing.
- Live SMTP verification.
- Production deployment and monitoring.
- Configurable advanced threat-hunting thresholds.
- Additional notification channels such as Slack or webhooks.
- End-to-end security testing and penetration testing.

## 13. Project Goal

FreightShield aims to transform traditional security monitoring into an integrated, intelligence-driven SOC workflow.

The overall security lifecycle is:

**DETECT → INVESTIGATE → ENRICH → RESPOND → REPORT → NOTIFY → HUNT**

By combining Wazuh, AI-assisted analysis, threat intelligence and controlled incident response, FreightShield aims to help security teams identify threats faster, investigate incidents more effectively and improve organizational security visibility.

---

## 14. Acknowledgement

**Project:** FreightShield SOC  
**Category:** Cybersecurity / Security Operations Center  
**Repository:** https://github.com/SandyaSundar/FreightShield

*Developed as a cybersecurity project focused on intelligent threat detection, investigation, response and security automation.*
