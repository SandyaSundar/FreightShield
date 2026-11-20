import os
import pytest

nacl = pytest.importorskip("nacl")


def test_vault_roundtrip_and_tamper(tmp_path, monkeypatch):
    from app.core.config import get_settings
    from app.core.db import connect
    from app.services import secret_vault

    db = tmp_path / "vault.db"
    monkeypatch.setenv("DATABASE_PATH", str(db))
    monkeypatch.setenv("FREIGHTSHIELD_VAULT_MASTER_KEY", "11" * 32)
    get_settings.cache_clear()
    secret_vault.put("OPENAI_API_KEY", "test-secret-value")
    assert secret_vault.get("OPENAI_API_KEY") == "test-secret-value"
    with connect() as c:
        row = c.execute("SELECT ciphertext,nonce FROM secret_vault WHERE name='OPENAI_API_KEY'").fetchone()
        assert b"test-secret-value" not in bytes(row["ciphertext"])
        bad = bytearray(row["ciphertext"]); bad[0] ^= 1
        c.execute("UPDATE secret_vault SET ciphertext=? WHERE name='OPENAI_API_KEY'", (bytes(bad),))
    with pytest.raises(secret_vault.VaultUnavailable):
        secret_vault.get("OPENAI_API_KEY")
    get_settings.cache_clear()


def test_vault_rejects_unknown_key():
    from app.services import secret_vault
    with pytest.raises(ValueError):
        secret_vault.put("DATABASE_PASSWORD", "nope")
