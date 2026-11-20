"""Central configuration, loaded once from environment variables / .env."""
import os
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()  # reads .env from the project root if present


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes")


class Settings(BaseModel):
    app_env: str = "development"
    cors_allowed_origins: list[str] = []
    wazuh_manager_url: str = ""
    wazuh_manager_user: str = ""
    wazuh_manager_password: str = ""
    wazuh_indexer_url: str = ""
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: str = ""
    wazuh_verify_ssl: bool = True
    wazuh_timeout_seconds: float = 10.0
    auth_jwt_secret: str = ""
    auth_cookie_name: str = "fs_session"
    auth_token_ttl_minutes: int = 60
    google_client_id: str = ""
    self_signup_enabled: bool = True        # Google self-registration (always role "user"); set false to restore invite-only
    detection_lookback_seconds: int = 900
    detection_interval_seconds: int = 0
    detection_max_events: int = 5000
    detection_notify_min_severity: str = "medium"
    database_path: str = "data/freightshield.db"
    ai_soc_agent_path: str = "agents/ai_soc_copilot___wazuh_investigator_v1"
    ai_email_agent_path: str = "agents/harbor_flich_email_router_v1"
    ai_timeout_seconds: int = 180
    ai_max_concurrent: int = 2
    ir_execution_enabled: bool = False   # safety switch: nothing is executed until an operator turns this on
    ir_ar_block_command: str = "firewall-drop"
    ir_ar_unblock_command: str = ""      # empty = rollback of block_ip is not supported (manual)
    ir_ar_isolate_command: str = ""      # Wazuh has no built-in isolation: only supported if a custom AR command is set
    ir_ar_unisolate_command: str = ""
    ir_protected_ips: list[str] = []
    virustotal_api_key: str = ""      # Phase 6 threat intel: keys are server-side only, never returned by any endpoint
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    ti_timeout_seconds: float = 8.0
    ti_cache_ttl_seconds: int = 86400  # an enriched IOC is not re-queried inside this window (saves quota, dedupes lookups)
    ti_max_lookups_per_scan: int = 25
    ti_vt_per_minute: int = 4          # VirusTotal public-API quota; raise for premium keys
    ti_lookback_seconds: int = 86400
    # Phase 8 notifications. SMTP credentials are server-side only and never returned by any endpoint.
    notify_email_enabled: bool = False   # master switch: no email is ever sent unless an operator turns this on
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    smtp_ssl: bool = False               # implicit TLS (port 465); takes precedence over STARTTLS
    smtp_timeout_seconds: float = 10.0
    notify_escalation_emails: list[str] = []  # extra recipients for escalated (level 2) notifications
    notify_app_url: str = ""             # optional link to the web app, shown in emails
    hunt_max_events: int = 5000           # Phase 9: events analysed per hunt (<= 10000)
    notify_interval_seconds: int = 300   # background overdue/escalation evaluator; 0 = off
    notify_email_max_attempts: int = 3
    # Phase 10 security hardening
    auth_jwt_issuer: str = "freightshield"
    auth_jwt_audience: str = "freightshield-api"
    csrf_cookie_name: str = "fs_csrf"
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 300        # per client IP, all API routes
    rate_limit_auth_per_minute: int = 10    # per client IP, sign-in
    rate_limit_ai_per_minute: int = 20      # per client IP, AI copilot (expensive upstream calls)
    max_body_bytes: int = 1_048_576
    trust_proxy: bool = False               # honour X-Forwarded-For (only behind a trusted reverse proxy)
    vault_master_key: str = ""              # 32-byte key encoded as 64 hex chars; keep outside DB


@lru_cache
def get_settings() -> Settings:
    origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173")
    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        cors_allowed_origins=[o.strip().rstrip("/") for o in origins.split(",") if o.strip() and o.strip() != "*"],
        wazuh_manager_url=os.getenv("WAZUH_MANAGER_URL", "").rstrip("/"),
        wazuh_manager_user=os.getenv("WAZUH_MANAGER_USER", ""),
        wazuh_manager_password=os.getenv("WAZUH_MANAGER_PASSWORD", ""),
        wazuh_indexer_url=os.getenv("WAZUH_INDEXER_URL", "").rstrip("/"),
        wazuh_indexer_user=os.getenv("WAZUH_INDEXER_USER", ""),
        wazuh_indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
        wazuh_verify_ssl=_bool("WAZUH_VERIFY_SSL", True),
        wazuh_timeout_seconds=float(os.getenv("WAZUH_TIMEOUT_SECONDS", "10")),
        auth_jwt_secret=os.getenv("AUTH_JWT_SECRET", ""),
        auth_cookie_name=os.getenv("AUTH_COOKIE_NAME", "fs_session"),
        auth_token_ttl_minutes=max(5, min(720, int(os.getenv("AUTH_TOKEN_TTL_MINUTES", "60")))),
        google_client_id=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        self_signup_enabled=_bool("SELF_SIGNUP_ENABLED", True),
        detection_lookback_seconds=int(os.getenv("DETECTION_LOOKBACK_SECONDS", "900")),
        detection_interval_seconds=int(os.getenv("DETECTION_INTERVAL_SECONDS", "0")),
        detection_max_events=int(os.getenv("DETECTION_MAX_EVENTS", "5000")),
        detection_notify_min_severity=os.getenv("DETECTION_NOTIFY_MIN_SEVERITY", "medium").strip().lower(),
        database_path=os.getenv("DATABASE_PATH", "data/freightshield.db"),
        ai_soc_agent_path=os.getenv("AI_SOC_AGENT_PATH", "agents/ai_soc_copilot___wazuh_investigator_v1"),
        ai_email_agent_path=os.getenv("AI_EMAIL_AGENT_PATH", "agents/harbor_flich_email_router_v1"),
        ai_timeout_seconds=int(os.getenv("AI_TIMEOUT_SECONDS", "180")),
        ai_max_concurrent=int(os.getenv("AI_MAX_CONCURRENT", "2")),
        ir_execution_enabled=_bool("IR_EXECUTION_ENABLED", False),
        ir_ar_block_command=os.getenv("IR_AR_BLOCK_COMMAND", "firewall-drop").strip(),
        ir_ar_unblock_command=os.getenv("IR_AR_UNBLOCK_COMMAND", "").strip(),
        ir_ar_isolate_command=os.getenv("IR_AR_ISOLATE_COMMAND", "").strip(),
        ir_ar_unisolate_command=os.getenv("IR_AR_UNISOLATE_COMMAND", "").strip(),
        ir_protected_ips=[i.strip() for i in os.getenv("IR_PROTECTED_IPS", "").split(",") if i.strip()],
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        otx_api_key=os.getenv("OTX_API_KEY", "").strip(),
        ti_timeout_seconds=float(os.getenv("TI_TIMEOUT_SECONDS", "8")),
        ti_cache_ttl_seconds=int(os.getenv("TI_CACHE_TTL_SECONDS", "86400")),
        ti_max_lookups_per_scan=int(os.getenv("TI_MAX_LOOKUPS_PER_SCAN", "25")),
        ti_vt_per_minute=int(os.getenv("TI_VT_PER_MINUTE", "4")),
        ti_lookback_seconds=int(os.getenv("TI_LOOKBACK_SECONDS", "86400")),
        notify_email_enabled=_bool("NOTIFY_EMAIL_ENABLED", False),
        smtp_host=os.getenv("SMTP_HOST", "").strip(),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER", "").strip(),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_from=os.getenv("SMTP_FROM", "").strip(),
        smtp_starttls=_bool("SMTP_STARTTLS", True),
        smtp_ssl=_bool("SMTP_SSL", False),
        smtp_timeout_seconds=float(os.getenv("SMTP_TIMEOUT_SECONDS", "10")),
        notify_escalation_emails=[e.strip().lower() for e in os.getenv("NOTIFY_ESCALATION_EMAILS", "").split(",") if e.strip()],
        notify_app_url=os.getenv("NOTIFY_APP_URL", "").strip().rstrip("/"),
        hunt_max_events=int(os.getenv("HUNT_MAX_EVENTS", "5000")),
        notify_interval_seconds=int(os.getenv("NOTIFY_INTERVAL_SECONDS", "300")),
        notify_email_max_attempts=int(os.getenv("NOTIFY_EMAIL_MAX_ATTEMPTS", "3")),
        auth_jwt_issuer=os.getenv("AUTH_JWT_ISSUER", "freightshield").strip(),
        auth_jwt_audience=os.getenv("AUTH_JWT_AUDIENCE", "freightshield-api").strip(),
        csrf_cookie_name=os.getenv("CSRF_COOKIE_NAME", "fs_csrf"),
        rate_limit_enabled=_bool("RATE_LIMIT_ENABLED", True),
        rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "300")),
        rate_limit_auth_per_minute=int(os.getenv("RATE_LIMIT_AUTH_PER_MINUTE", "10")),
        rate_limit_ai_per_minute=int(os.getenv("RATE_LIMIT_AI_PER_MINUTE", "20")),
        max_body_bytes=int(os.getenv("MAX_BODY_BYTES", "1048576")),
        trust_proxy=_bool("TRUST_PROXY", False),
        vault_master_key=os.getenv("FREIGHTSHIELD_VAULT_MASTER_KEY", "").strip(),
    )
