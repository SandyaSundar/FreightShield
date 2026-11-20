"""Single source of truth for roles, display labels and API permissions (the frontend reads these from the API)."""
from typing import Literal

Role = Literal["admin", "user", "vendor"]
ROLES: tuple[str, ...] = ("admin", "user", "vendor")
ROLE_LABELS: dict[str, str] = {"admin": "IT Security Administrator", "user": "User", "vendor": "Vendor"}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"wazuh:read", "wazuh:agents", "wazuh:alerts", "users:read", "users:write",
                        "audit:read", "ai:use", "detections:read", "detections:write",
                        "notifications:read", "notifications:manage", "ir:read", "ir:approve", "ir:manage", "ti:read", "ti:write", "reports:read", "reports:export", "hunt:read"}),
    "user": frozenset(),    # consumers get no security-data access; only their own profile (/rbac/me)
    # Vendors see only the Wazuh agents/alerts an admin assigned to them (enforced in routes/vendor.py).
    "vendor": frozenset({"vendor:agents", "vendor:alerts", "vendor:detections", "vendor:responses", "vendor:threatintel", "vendor:reports", "vendor:notifications", "vendor:hunt"}),
}


def profile(user: dict) -> dict:
    """Public session/identity view of a user row (shared by /auth/me and /rbac/me)."""
    return {"id": user["id"], "email": user["email"], "role": user["role"], "role_label": ROLE_LABELS[user["role"]],
            "permissions": sorted(ROLE_PERMISSIONS[user["role"]])}
