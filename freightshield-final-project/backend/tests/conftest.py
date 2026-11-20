import pytest

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _isolate_wazuh_settings(monkeypatch):
    """Tests must never depend on (or contact) a real Wazuh configured in .env."""
    s = get_settings()
    for k in ("wazuh_manager_url", "wazuh_manager_user", "wazuh_manager_password",
              "wazuh_indexer_url", "wazuh_indexer_user", "wazuh_indexer_password"):
        monkeypatch.setattr(s, k, "")
    monkeypatch.setattr(s, "wazuh_verify_ssl", True)


@pytest.fixture(autouse=True)
def _auth_and_db(monkeypatch, tmp_path):
    """Fresh SQLite DB per test and a valid JWT secret."""
    from tests.helpers import SECRET
    s = get_settings()
    monkeypatch.setattr(s, "database_path", str(tmp_path / "t.db"))
    monkeypatch.setattr(s, "auth_jwt_secret", SECRET)


@pytest.fixture(autouse=True)
def _isolate_notification_email(monkeypatch):
    """Phase 8: tests must never open a real SMTP connection, whatever the developer's .env says."""
    s = get_settings()
    monkeypatch.setattr(s, "notify_email_enabled", False)
    for k in ("smtp_host", "smtp_user", "smtp_password", "smtp_from", "notify_app_url"):
        monkeypatch.setattr(s, k, "")
    monkeypatch.setattr(s, "notify_escalation_emails", [])


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Phase 10: the in-memory rate limiter is process-global; every test starts with an empty window."""
    from app.core.hardening import limiter
    limiter.reset()
    yield
    limiter.reset()
