"""Vendor -> Wazuh agent assignments. This table is the ONLY source of what a vendor may see."""
from datetime import datetime, timezone

from app.core.db import connect


def agent_ids(vendor_id: int) -> list[str]:
    with connect() as c:
        return [r[0] for r in c.execute("SELECT agent_id FROM vendor_agents WHERE vendor_id=? ORDER BY agent_id",
                                        (vendor_id,))]


def assign(vendor_id: int, agent_id: str) -> None:
    with connect() as c:
        c.execute("INSERT OR IGNORE INTO vendor_agents (vendor_id, agent_id, created_at) VALUES (?,?,?)",
                  (vendor_id, agent_id, datetime.now(timezone.utc).isoformat()))


def unassign(vendor_id: int, agent_id: str) -> bool:
    with connect() as c:
        return c.execute("DELETE FROM vendor_agents WHERE vendor_id=? AND agent_id=?", (vendor_id, agent_id)).rowcount > 0
