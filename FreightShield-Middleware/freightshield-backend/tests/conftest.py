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
