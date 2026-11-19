import time
import jwt
from app.core.config import get_settings

SECRET = "test-secret-test-secret-test-secret-1234"


def set_secret(monkeypatch):
    monkeypatch.setattr(get_settings(), "auth_jwt_secret", SECRET)


def token(role="analyst", exp_in=300, secret=SECRET):
    return jwt.encode({"sub": "u1", "role": role, "exp": int(time.time()) + exp_in}, secret, algorithm="HS256")


def auth_headers(role="analyst"):
    return {"Authorization": f"Bearer {token(role)}"}
