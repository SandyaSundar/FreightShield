"""Encrypted server-side secret vault. XChaCha20-Poly1305 via libsodium/PyNaCl."""
import os
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.db import connect

ALLOWED = {"OPENAI_API_KEY", "EXA_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"}


class VaultUnavailable(RuntimeError):
    pass


def _crypto():
    try:
        from nacl.bindings import (
            crypto_aead_xchacha20poly1305_ietf_encrypt,
            crypto_aead_xchacha20poly1305_ietf_decrypt,
        )
        from nacl.utils import random as random_bytes
    except ImportError as exc:
        raise VaultUnavailable("PyNaCl is required for the secret vault.") from exc
    raw = get_settings().vault_master_key
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise VaultUnavailable("FREIGHTSHIELD_VAULT_MASTER_KEY must be 64 hexadecimal characters.") from exc
    if len(key) != 32:
        raise VaultUnavailable("FREIGHTSHIELD_VAULT_MASTER_KEY must decode to exactly 32 bytes.")
    return key, crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt, random_bytes


def put(name: str, value: str) -> None:
    if name not in ALLOWED:
        raise ValueError("Unsupported secret name.")
    key, enc, _, random_bytes = _crypto()
    nonce = random_bytes(24)
    aad = f"freightshield-secret-v1:{name}".encode()
    ciphertext = enc(value.encode("utf-8"), aad, nonce, key)
    with connect() as c:
        c.execute("""INSERT INTO secret_vault(name,ciphertext,nonce,key_version,updated_at)
                     VALUES(?,?,?,1,?) ON CONFLICT(name) DO UPDATE SET
                     ciphertext=excluded.ciphertext, nonce=excluded.nonce,
                     key_version=excluded.key_version, updated_at=excluded.updated_at""",
                  (name, ciphertext, nonce, datetime.now(timezone.utc).isoformat()))


def get(name: str) -> str | None:
    if name not in ALLOWED:
        raise ValueError("Unsupported secret name.")
    with connect() as c:
        row = c.execute("SELECT ciphertext,nonce,key_version FROM secret_vault WHERE name=?", (name,)).fetchone()
    if row is None:
        return os.getenv(name) or None  # backwards-compatible migration path; move values into vault to encrypt at rest
    if row["key_version"] != 1:
        raise VaultUnavailable("Unsupported vault key version.")
    key, _, dec, _ = _crypto()
    aad = f"freightshield-secret-v1:{name}".encode()
    try:
        return dec(bytes(row["ciphertext"]), aad, bytes(row["nonce"]), key).decode("utf-8")
    except Exception as exc:
        raise VaultUnavailable("Stored secret could not be authenticated; check vault key and database integrity.") from exc


def inventory() -> list[dict]:
    with connect() as c:
        stored = {r["name"]: r["updated_at"] for r in c.execute("SELECT name,updated_at FROM secret_vault")}
    return [{"name": n, "stored_encrypted": n in stored, "environment_fallback": bool(os.getenv(n)) and n not in stored,
             "updated_at": stored.get(n)} for n in sorted(ALLOWED)]


def delete(name: str) -> bool:
    if name not in ALLOWED:
        raise ValueError("Unsupported secret name.")
    with connect() as c:
        cur = c.execute("DELETE FROM secret_vault WHERE name=?", (name,))
        return cur.rowcount > 0
