"""SQLite access (stdlib). Path comes from DATABASE_PATH; schema is created on first use."""
import os
import sqlite3
from contextlib import contextmanager

from app.core.config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('admin','user','vendor')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id INTEGER,
  actor_email TEXT,
  action TEXT NOT NULL,
  target TEXT,
  outcome TEXT NOT NULL,
  ip TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit_log(ts);
-- Vendor data isolation: a vendor only ever sees Wazuh agents (and their alerts) assigned to them here.
CREATE TABLE IF NOT EXISTS detection_rules (
  rule_key TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1, threshold INTEGER NOT NULL,
  window_seconds INTEGER NOT NULL, severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  min_level INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved')),
  agent_id TEXT NOT NULL, alert_count INTEGER NOT NULL DEFAULT 1, mitre TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL, last_activity TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, dedupe_key TEXT NOT NULL, rule_key TEXT NOT NULL, title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','acknowledged','investigating','resolved','false_positive')),
  agent_id TEXT NOT NULL, agent_name TEXT, src_ip TEXT, event_count INTEGER NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, mitre TEXT NOT NULL DEFAULT '[]', evidence TEXT NOT NULL DEFAULT '[]',
  incident_id INTEGER REFERENCES incidents(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS det_alert_key ON detection_alerts(dedupe_key);
CREATE INDEX IF NOT EXISTS det_alert_agent ON detection_alerts(agent_id);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_id INTEGER, severity TEXT NOT NULL,
  title TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ir_playbooks (
  key TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, trigger_rule TEXT NOT NULL,
  min_severity TEXT NOT NULL CHECK (min_severity IN ('low','medium','high','critical')), steps TEXT NOT NULL, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ir_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, playbook_key TEXT NOT NULL, alert_id INTEGER, incident_id INTEGER,
  agent_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT, severity TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','unsupported','rejected','executing','executed','failed','rolling_back','rolled_back','rollback_failed')),
  detail TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  approved_by TEXT, approved_at TEXT, rejected_by TEXT, rejected_reason TEXT, executed_at TEXT, error TEXT,
  rolled_back_by TEXT, rolled_back_at TEXT, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ir_action_status ON ir_actions(status);
CREATE INDEX IF NOT EXISTS ir_action_agent ON ir_actions(agent_id);
-- Immutable-style IR audit: hash-chained, and UPDATE/DELETE are rejected by triggers.
CREATE TABLE IF NOT EXISTS ir_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action_id INTEGER, event TEXT NOT NULL,
  detail TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS ir_audit_no_update BEFORE UPDATE ON ir_audit BEGIN SELECT RAISE(ABORT, 'ir_audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ir_audit_no_delete BEFORE DELETE ON ir_audit BEGIN SELECT RAISE(ABORT, 'ir_audit is append-only'); END;
-- Phase 6 threat intelligence. One row per unique IOC (type,value); sightings tie it to Wazuh alerts/agents (vendor scope).
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL CHECK (type IN ('ip','domain','url','md5','sha1','sha256')),
  value TEXT NOT NULL, score INTEGER, classification TEXT NOT NULL DEFAULT 'unknown', risk TEXT NOT NULL DEFAULT 'unknown',
  mitre TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, enriched_at TEXT, UNIQUE (type, value)
);
CREATE TABLE IF NOT EXISTS ioc_sightings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE, wazuh_alert_id TEXT NOT NULL,
  agent_id TEXT NOT NULL, rule_id TEXT, level INTEGER NOT NULL DEFAULT 0, ts TEXT NOT NULL, groups TEXT NOT NULL DEFAULT '[]',
  mitre TEXT NOT NULL DEFAULT '[]', src_is_ioc INTEGER NOT NULL DEFAULT 0, UNIQUE (ioc_id, wazuh_alert_id)
);
CREATE INDEX IF NOT EXISTS sight_agent ON ioc_sightings(agent_id);
CREATE TABLE IF NOT EXISTS ioc_enrichments (
  ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE, provider TEXT NOT NULL, status TEXT NOT NULL, score INTEGER,
  summary TEXT NOT NULL DEFAULT '{}', fetched_at TEXT NOT NULL, PRIMARY KEY (ioc_id, provider)
);
CREATE TABLE IF NOT EXISTS vendor_agents (
  vendor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (vendor_id, agent_id)
);
-- Phase 8 notifications. The Phase 3 `notifications` table is extended in place (see MIGRATIONS); these tables hang off it.
-- Vendor isolation: a vendor sees a notification only if it is vendor_visible AND scoped to one of their assigned agents.
CREATE TABLE IF NOT EXISTS notification_scope (
  notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE, agent_id TEXT NOT NULL,
  PRIMARY KEY (notification_id, agent_id)
);
CREATE INDEX IF NOT EXISTS notif_scope_agent ON notification_scope(agent_id);
-- Read/unread is per user (several admins, several vendors), not global.
CREATE TABLE IF NOT EXISTS notification_reads (
  notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, read_at TEXT NOT NULL,
  PRIMARY KEY (notification_id, user_id)
);
CREATE TABLE IF NOT EXISTS notification_prefs (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, email_enabled INTEGER NOT NULL,
  min_severity TEXT NOT NULL CHECK (min_severity IN ('low','medium','high','critical')), updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS escalation_rules (
  severity TEXT PRIMARY KEY CHECK (severity IN ('low','medium','high','critical')), enabled INTEGER NOT NULL DEFAULT 1,
  email INTEGER NOT NULL DEFAULT 0, sla_minutes INTEGER NOT NULL, escalate_after_minutes INTEGER NOT NULL DEFAULT 0, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS notification_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  recipient TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('sent','failed')), attempts INTEGER NOT NULL DEFAULT 1,
  error TEXT, attempted_at TEXT NOT NULL, UNIQUE (notification_id, recipient)
);
-- Phase 10: server-side session revocation (logout). Rows expire with the token and are purged lazily.
CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL);
-- Phase 11: encrypted provider/API secrets. Plaintext is never persisted here.
CREATE TABLE IF NOT EXISTS secret_vault (
  name TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);
"""


MIGRATIONS = (("detection_alerts", "acknowledged_at", "TEXT"), ("incidents", "resolved_at", "TEXT"),  # Phase 7: real MTTA/MTTR inputs
              # Phase 8: the Phase 3 notifications table gains categories, escalation and an email outbox state (old rows keep working)
              ("notifications", "category", "TEXT NOT NULL DEFAULT 'alert'"), ("notifications", "message", "TEXT"),
              ("notifications", "incident_id", "INTEGER"), ("notifications", "dedupe_key", "TEXT"),
              ("notifications", "vendor_visible", "INTEGER NOT NULL DEFAULT 0"), ("notifications", "escalation_level", "INTEGER NOT NULL DEFAULT 0"),
              ("notifications", "email_state", "TEXT NOT NULL DEFAULT 'none'"))
POST_MIGRATION = ("CREATE UNIQUE INDEX IF NOT EXISTS notif_dedupe ON notifications(dedupe_key) WHERE dedupe_key IS NOT NULL",
                  "CREATE INDEX IF NOT EXISTS notif_category ON notifications(category)",
                  "CREATE INDEX IF NOT EXISTS notif_email_state ON notifications(email_state)")


def _migrate(conn) -> None:
    """Add columns missing from databases created by earlier phases (CREATE IF NOT EXISTS never alters existing tables)."""
    for table, col, decl in MIGRATIONS:
        if col not in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    for sql in POST_MIGRATION:
        conn.execute(sql)


@contextmanager
def connect():
    path = get_settings().database_path
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
