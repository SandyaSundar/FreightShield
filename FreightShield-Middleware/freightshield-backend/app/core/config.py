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


@lru_cache
def get_settings() -> Settings:
    origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173")
    return Settings(
        app_env=os.getenv("APP_ENV", "development"),
        cors_allowed_origins=[o.strip() for o in origins.split(",") if o.strip()],
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
    )
