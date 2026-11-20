"""Bootstrap the first admin (there is no login yet to do it through the API).

Usage: python -m app.cli create-admin you@example.com
Creates the user as admin, or promotes/re-activates an existing one. Audited as actor "cli".
"""
import sys

from app.services import audit, users


def create_admin(email: str) -> dict:
    u = users.get_by_email(email)
    u = users.update(u["id"], None, "admin", True) if u else users.create(email, "admin")
    audit.record({"id": None, "email": "cli"}, "bootstrap_admin", f"user:{u['id']}", detail=f"email={u['email']}")
    return u


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "create-admin":
        sys.exit("usage: python -m app.cli create-admin EMAIL")
    print("admin ready:", create_admin(sys.argv[2])["email"])
