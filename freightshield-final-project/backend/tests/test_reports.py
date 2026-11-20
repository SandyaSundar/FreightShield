"""Phase 7 reports & analytics. Data is produced by the REAL detection pipeline into a temp SQLite DB (no mocks of report logic);
only timestamps are set directly so MTTA/MTTR have known answers. Live Wazuh is not involved (reports read stored data)."""
import csv
import io
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.core.db import connect
from app.main import app
from app.services import audit, detection, reports, vendor_agents
from tests.helpers import auth_headers, make_user
from tests.test_detection_engine import fails, run

NOW = datetime.now(timezone.utc)
T = lambda m: (NOW - timedelta(hours=2) + timedelta(minutes=m)).isoformat()


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
def data():
    """Two agents, one alert each (real rule engine). Agent 001: created T0, acked +10m, resolved +70m. Agent 002: open, evil title."""
    run(fails(6, "001") + fails(6, "002", "198.51.100.7"), now=NOW)
    a1 = detection.list_alerts(10, 0, agent_id="001")[0][0]
    a2 = detection.list_alerts(10, 0, agent_id="002")[0][0]
    with connect() as c:
        c.execute("UPDATE detection_alerts SET created_at=?, acknowledged_at=?, resolved_at=?, status='resolved' WHERE id=?", (T(0), T(10), T(70), a1["id"]))
        c.execute("UPDATE detection_alerts SET title='=cmd|calc' WHERE id=?", (a2["id"],))
    return a1, a2


# ---- pure
def test_duration_stats_and_empty():
    s = reports.duration_stats([("2026-01-01T00:00:00+00:00", "2026-01-01T00:10:00+00:00"), ("2026-01-01T00:00:00+00:00", "2026-01-01T00:30:00+00:00"),
                                ("2026-01-01T01:00:00+00:00", "2026-01-01T00:00:00+00:00"), ("bad", "x")])   # negative + invalid dropped
    assert s == {"count": 2, "mean_seconds": 1200.0, "median_seconds": 1200.0, "max_seconds": 1800.0}
    assert reports.duration_stats([])["mean_seconds"] is None


def test_trend_is_zero_filled_daily():
    since = datetime(2026, 11, 1, tzinfo=timezone.utc)
    t = reports.trend([{"created_at": "2026-11-02T10:00:00+00:00", "severity": "high"}, {"created_at": "2026-11-09T10:00:00+00:00", "severity": "low"}], since, since + timedelta(days=3))
    assert [d["total"] for d in t] == [0, 1, 0, 0] and t[1]["high"] == 1


def test_csv_cells_cannot_be_formulas():
    assert [reports._safe(x) for x in ("=1+1", "+1", "-1", "@x", "ok", None)] == ["'=1+1", "'+1", "'-1", "'@x", "ok", ""]


def test_migration_adds_columns_to_old_database(tmp_path, monkeypatch):
    import sqlite3
    from app.core.config import get_settings
    p = tmp_path / "old.db"
    sqlite3.connect(p).executescript("CREATE TABLE incidents (id INTEGER PRIMARY KEY, title TEXT, severity TEXT, status TEXT, agent_id TEXT, alert_count INT, mitre TEXT, created_at TEXT, last_activity TEXT, updated_at TEXT);")
    monkeypatch.setattr(get_settings(), "database_path", str(p))
    with connect() as c:
        assert "resolved_at" in {r[1] for r in c.execute("PRAGMA table_info(incidents)")}
    with connect():
        pass  # idempotent


# ---- service on real stored data
def test_build_metrics_trends_and_scope(data):
    r = reports.build(7, None, NOW)
    assert r["totals"]["alerts"] == 2 and r["totals"]["open_alerts"] == 1 and r["alerts_by_severity"]["high"] == 2
    assert r["metrics"]["mtta"]["mean_seconds"] == 600.0 and r["metrics"]["mttr_alerts"]["mean_seconds"] == 4200.0
    assert sum(d["total"] for d in r["alert_trend"]) == 2
    v = reports.build(7, ["001"], NOW)
    assert v["totals"]["alerts"] == 1 and v["top_agents"][0]["agent"] == "web-01"
    assert reports.build(7, [], NOW)["totals"]["alerts"] == 0   # vendor with no agents sees nothing, not everything


def test_status_changes_record_ack_and_resolve_times(data):
    _, a2 = data
    first = detection.set_alert_status(a2["id"], "investigating")[0]["acknowledged_at"]
    assert first and detection.set_alert_status(a2["id"], "resolved")[0]["acknowledged_at"] == first
    assert detection.set_incident_status(a2["incident_id"], "resolved")[0]["resolved_at"]
    assert detection.set_incident_status(a2["incident_id"], "open")[0]["resolved_at"] is None


# ---- HTTP: RBAC
ADMIN_GET = ["/reports/summary", "/reports/export?format=csv&dataset=alerts"]
VENDOR_GET = ["/vendor/reports/summary", "/vendor/reports/export?format=csv&dataset=alerts"]


@pytest.mark.anyio
async def test_authentication_and_role_matrix(data):
    async with client() as c:
        for p in ADMIN_GET + VENDOR_GET:
            assert (await c.get(f"/api{p}")).status_code == 401, p
        for role in ("user", "vendor"):
            for p in ADMIN_GET:
                assert (await c.get(f"/api{p}", headers=auth_headers(role))).status_code == 403, (role, p)
        for role in ("user", "admin"):
            for p in VENDOR_GET:
                assert (await c.get(f"/api{p}", headers=auth_headers(role))).status_code == 403, (role, p)
        assert (await c.get("/api/reports/summary", headers=auth_headers("admin"))).status_code == 200


@pytest.mark.anyio
async def test_parameter_validation(data):
    async with client() as c:
        h = auth_headers("admin")
        for q in ("days=0", "days=9999", "format=xlsx", "dataset=users", "days=abc"):
            assert (await c.get(f"/api/reports/export?{q}", headers=h)).status_code == 422, q


@pytest.mark.anyio
async def test_admin_summary_and_exports_use_real_data(data):
    async with client() as c:
        h = auth_headers("admin")
        s = (await c.get("/api/reports/summary?days=7", headers=h)).json()
        assert s["totals"]["alerts"] == 2 and s["metrics"]["mtta"]["count"] == 1
        r = await c.get("/api/reports/export?format=csv&dataset=alerts&days=7", headers=h)
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and r.headers["x-content-type-options"] == "nosniff"
        rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
        assert len(rows) == 3 and not any(cell.startswith("=") for row in rows for cell in row)
        p = await c.get("/api/reports/export?format=pdf&dataset=summary&days=7", headers=h)
        assert p.status_code == 200 and p.content.startswith(b"%PDF") and p.headers["content-type"] == "application/pdf"


@pytest.mark.anyio
async def test_vendor_isolation_in_summary_and_exports(data):
    vend = make_user("vendor")
    vendor_agents.assign(vend["id"], "001")
    async with client() as c:
        h = auth_headers("vendor")
        assert (await c.get("/api/vendor/reports/summary", headers=h)).json()["totals"]["alerts"] == 1
        csv_ = (await c.get("/api/vendor/reports/export?format=csv&dataset=alerts", headers=h)).text
        rows = list(csv.reader(io.StringIO(csv_.lstrip("\ufeff"))))
        assert [r[6] for r in rows[1:]] == ["001"] and "198.51.100.7" not in csv_ and "=cmd" not in csv_   # column 6 = agent_id
        for ds in ("incidents", "summary"):
            assert "198.51.100.7" not in (await c.get(f"/api/vendor/reports/export?format=csv&dataset={ds}", headers=h)).text
        vendor_agents.unassign(vend["id"], "001")
        assert (await c.get("/api/vendor/reports/summary", headers=h)).json()["totals"]["alerts"] == 0


@pytest.mark.anyio
async def test_every_export_is_audited_without_secrets(data):
    vend = make_user("vendor")
    vendor_agents.assign(vend["id"], "001")
    async with client() as c:
        await c.get("/api/reports/export?format=csv&dataset=alerts", headers=auth_headers("admin"))
        await c.get("/api/reports/export?format=pdf&dataset=summary&days=7", headers=auth_headers("admin"))
        await c.get("/api/vendor/reports/export?format=csv&dataset=incidents", headers=auth_headers("vendor"))
        await c.get("/api/reports/export", headers=auth_headers("user"))   # denied
    logs, _ = audit.list_logs(100, 0)
    exp = [l for l in logs if l["action"] == "report_export"]
    assert len(exp) == 3 and {l["actor_email"] for l in exp} == {"admin@test.local", "vendor@test.local"}
    assert any("format=pdf" in l["detail"] and "scope=admin:all" in l["detail"] for l in exp) and any("vendor:1agents" in l["detail"] for l in exp)
    assert ("access_denied", "denied") in {(l["action"], l["outcome"]) for l in logs}
    assert "key" not in str([l["detail"] for l in exp]).lower()


@pytest.mark.anyio
async def test_exports_never_contain_configured_secrets(data, monkeypatch):
    from app.core.config import get_settings
    s = get_settings()
    for k in ("virustotal_api_key", "abuseipdb_api_key", "otx_api_key", "wazuh_manager_password"):
        monkeypatch.setattr(s, k, "TOPSECRET123")
    async with client() as c:
        h = auth_headers("admin")
        body = (await c.get("/api/reports/summary", headers=h)).text + (await c.get("/api/reports/export?dataset=summary", headers=h)).text
        assert "TOPSECRET123" not in body and "TOPSECRET123" not in (await c.get("/api/reports/export?format=pdf", headers=h)).content.decode("latin-1")
