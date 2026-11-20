"""User store (role + active flag). Roles live here, not in the JWT, so changes apply immediately."""
import sqlite3
from datetime import datetime, timezone

from fastapi import HTTPException

from app.core.db import connect
from app.core.roles import ROLES


def _d(row) -> dict | None:
    return None if row is None else {**dict(row), "active": bool(row["active"])}


def get_by_id(uid: int) -> dict | None:
    with connect() as c:
        return _d(c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())


def get_by_email(email: str) -> dict | None:
    with connect() as c:
        return _d(c.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone())


def create(email: str, role: str) -> dict:
    if role not in ROLES:
        raise HTTPException(422, "Unknown role.")
    try:
        with connect() as c:
            cur = c.execute("INSERT INTO users (email, role, active, created_at) VALUES (?,?,1,?)",
                            (email.lower(), role, datetime.now(timezone.utc).isoformat()))
            return _d(c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())
    except sqlite3.IntegrityError:
        raise HTTPException(409, "A user with this email already exists.")


def list_users(limit: int, offset: int, role: str | None = None, active: bool | None = None):
    where, args = [], []
    if role:
        where.append("role=?"), args.append(role)
    if active is not None:
        where.append("active=?"), args.append(int(active))
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM users{w}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM users{w} ORDER BY id LIMIT ? OFFSET ?", [*args, limit, offset])
        return [_d(r) for r in rows], total


def _guard(c, row, actor_id: int | None, loses_admin: bool, self_change: bool) -> None:
    if actor_id == row["id"] and self_change:
        raise HTTPException(409, "You cannot change your own role/status or delete yourself.")
    if loses_admin and row["role"] == "admin" and row["active"]:
        others = c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id<>?",
                           (row["id"],)).fetchone()[0]
        if others == 0:
            raise HTTPException(409, "Cannot remove the last active admin.")


def update(uid: int, actor_id: int | None, role: str | None = None, active: bool | None = None) -> dict:
    if role is not None and role not in ROLES:
        raise HTTPException(422, "Unknown role.")
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found.")
        new_role = role or row["role"]
        new_active = row["active"] if active is None else int(active)
        changed = new_role != row["role"] or new_active != row["active"]
        _guard(c, row, actor_id, new_role != "admin" or not new_active, changed)
        c.execute("UPDATE users SET role=?, active=? WHERE id=?", (new_role, new_active, uid))
        if new_role != "vendor":  # no stale vendor scope if the user is later made a vendor again
            c.execute("DELETE FROM vendor_agents WHERE vendor_id=?", (uid,))
        return _d(c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())


def delete(uid: int, actor_id: int | None) -> dict:
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found.")
        _guard(c, row, actor_id, True, True)
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        return _d(row)
