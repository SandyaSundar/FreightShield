"""Append-only audit log. Never pass secrets, tokens or passwords in `detail`."""
from datetime import datetime, timezone

from app.core.db import connect


def record(actor: dict | None, action: str, target: str | None = None, outcome: str = "success",
           ip: str | None = None, detail: str | None = None) -> None:
    with connect() as c:
        c.execute("INSERT INTO audit_log (ts, actor_id, actor_email, action, target, outcome, ip, detail)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (datetime.now(timezone.utc).isoformat(), actor and actor.get("id"), actor and actor.get("email"),
                   action, target, outcome, ip, detail))


def list_logs(limit: int, offset: int, action: str | None = None, actor_id: int | None = None,
              outcome: str | None = None) -> tuple[list[dict], int]:
    where, args = [], []
    for col, val in (("action", action), ("actor_id", actor_id), ("outcome", outcome)):
        if val is not None:
            where.append(f"{col}=?")
            args.append(val)
    w = f" WHERE {' AND '.join(where)}" if where else ""
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM audit_log{w}", args).fetchone()[0]
        rows = c.execute(f"SELECT * FROM audit_log{w} ORDER BY id DESC LIMIT ? OFFSET ?", [*args, limit, offset])
        return [dict(r) for r in rows], total
