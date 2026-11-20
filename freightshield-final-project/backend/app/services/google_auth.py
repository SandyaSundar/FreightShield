"""Verifies a Google Sign-In ID token (signature via Google's published keys, audience, issuer, expiry)."""
import jwt
from fastapi import HTTPException
from jwt import PyJWKClient

from app.core.config import get_settings
from app.core.errors import NotConfiguredError, UpstreamError

JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")
_jwks = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=3600)
_KEYS_UNREACHABLE = getattr(jwt, "PyJWKClientConnectionError", ())  # exists in PyJWT >= 2.8


def verify_id_token(credential: str) -> dict:
    """Returns the verified claims (with a verified email) or raises 401 / 503 / UpstreamError."""
    client_id = get_settings().google_client_id
    if not client_id:
        raise NotConfiguredError("google_oauth")
    try:
        key = _jwks.get_signing_key_from_jwt(credential).key
        claims = jwt.decode(credential, key, algorithms=["RS256"], audience=client_id, leeway=10,
                            options={"require": ["exp", "iss", "aud", "sub"]})
    except _KEYS_UNREACHABLE as e:
        raise UpstreamError("google_oauth", "Cannot fetch Google signing keys.", 503) from e
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid Google credential.")
    if claims["iss"] not in ISSUERS or not claims.get("email") or claims.get("email_verified") not in (True, "true"):
        raise HTTPException(401, "Invalid Google credential.")
    return claims
