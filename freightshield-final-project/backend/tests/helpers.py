import time
import jwt
from app.services import users

SECRET = "test-secret-test-secret-test-secret-1234"


def claims(sub, exp_in=300, **extra):
    now = int(time.time())
    c = {"sub": str(sub), "iat": now, "nbf": now, "exp": now + exp_in, "iss": "freightshield",
         "aud": "freightshield-api", "jti": f"t-{sub}-{now}-{exp_in}"}
    c.update(extra)
    return {k: v for k, v in c.items() if v is not None}


def token(user_id, role=None, exp_in=300, secret=SECRET, **extra):
    return jwt.encode(claims(user_id, exp_in, **extra), secret, algorithm="HS256")


def make_user(role="admin"):
    return users.get_by_email(f"{role}@test.local") or users.create(f"{role}@test.local", role)


def auth_headers(role="admin"):
    return {"Authorization": f"Bearer {token(make_user(role)['id'])}"}
