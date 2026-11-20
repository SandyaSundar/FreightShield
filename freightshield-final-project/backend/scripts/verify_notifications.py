"""Phase 8 LIVE check of email delivery. Run from the backend folder with .env filled in:

    python -m scripts.verify_notifications --to you@yourcompany.com

Nothing is mocked: it connects to the SMTP server named in .env (TLS verified), authenticates and sends ONE test message to --to.
It also checks the notification tables of the configured DATABASE_PATH. PASS/FAIL/SKIP per check; exit code 1 if anything FAILED.
"""
import argparse
import sys
from email.message import EmailMessage

from app.core.config import get_settings
from app.core.db import connect
from app.services import notifications as nt

bad = 0


def rec(status: str, name: str, detail: str = "") -> None:
    global bad
    bad += status == "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", help="address that receives the test email (omit to skip the SMTP send)")
    a = ap.parse_args()
    with connect() as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        need = {"notifications", "notification_scope", "notification_reads", "notification_prefs", "escalation_rules", "notification_deliveries"}
        rec("PASS" if need <= tables else "FAIL", "notification tables exist", ", ".join(sorted(need - tables)))
        cols = {r[1] for r in c.execute("PRAGMA table_info(notifications)")}
        rec("PASS" if {"category", "dedupe_key", "vendor_visible", "escalation_level", "email_state"} <= cols else "FAIL", "notifications table migrated")
    problem = nt.email_problem()
    if problem:
        rec("SKIP", "SMTP send", problem)
    elif not a.to:
        rec("SKIP", "SMTP send", "pass --to ADDRESS to send a real test message")
    else:
        m = EmailMessage()
        m["From"], m["To"], m["Subject"] = get_settings().smtp_from, a.to, "[FreightShield] SMTP verification"
        m.set_content("Live SMTP verification from scripts/verify_notifications.py.")
        try:
            nt._send_smtp(m)
            rec("PASS", "SMTP send", f"accepted by the server for {a.to}")
        except Exception as e:  # noqa: BLE001
            rec("FAIL", "SMTP send", nt._err(e))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
