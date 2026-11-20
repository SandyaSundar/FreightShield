"""Feed clients with a mocked HTTP transport (SIMULATED feeds). Proves status mapping, quotas and key handling,
NOT that the real VirusTotal/AbuseIPDB/OTX APIs behave this way: see scripts/verify_threat_intel.py for the live check."""
import httpx
import pytest

from app.core.config import get_settings
from app.services import ti_providers as tp

_REAL_ASYNC_CLIENT = httpx.AsyncClient


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    s = get_settings()
    for k in ("virustotal_api_key", "abuseipdb_api_key", "otx_api_key"):
        monkeypatch.setattr(s, k, "SECRET-KEY-VALUE")
    monkeypatch.setattr(tp, "limiter", tp._Limiter())


def mock(monkeypatch, handler):
    def factory(**kw):
        kw["transport"] = httpx.MockTransport(handler)
        return _REAL_ASYNC_CLIENT(**kw)
    monkeypatch.setattr(tp.httpx, "AsyncClient", factory)


@pytest.mark.anyio
async def test_no_key_means_unavailable_and_no_request(monkeypatch):
    for k in ("virustotal_api_key", "abuseipdb_api_key", "otx_api_key"):
        monkeypatch.setattr(get_settings(), k, "")
    mock(monkeypatch, lambda r: pytest.fail("no request may be made without a key"))
    out = await tp.lookup("ip", "45.33.32.156")
    assert {v["status"] for v in out.values()} == {"unavailable"}


@pytest.mark.anyio
async def test_virustotal_parse_and_key_only_in_header(monkeypatch):
    seen = []

    def h(r):
        seen.append(r)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 10}}}})
    mock(monkeypatch, h)
    r = await tp.virustotal("ip", "45.33.32.156")
    assert r["status"] == "ok" and r["summary"]["malicious"] == 7
    assert seen[0].headers["x-apikey"] == "SECRET-KEY-VALUE" and "SECRET-KEY-VALUE" not in str(seen[0].url)
    assert "SECRET-KEY-VALUE" not in str(r)


@pytest.mark.anyio
@pytest.mark.parametrize("code,status", [(404, "not_found"), (429, "rate_limited"), (401, "error"), (500, "error")])
async def test_http_errors_map_to_statuses(monkeypatch, code, status):
    mock(monkeypatch, lambda r: httpx.Response(code, json={}))
    assert (await tp.abuseipdb("ip", "45.33.32.156"))["status"] == status


@pytest.mark.anyio
async def test_timeout_and_connection_errors_do_not_raise(monkeypatch):
    def boom(r):
        raise httpx.ReadTimeout("slow")
    mock(monkeypatch, boom)
    assert (await tp.otx("domain", "evil-example.com"))["status"] == "timeout"
    mock(monkeypatch, lambda r: (_ for _ in ()).throw(httpx.ConnectError("down")))
    assert (await tp.otx("domain", "evil-example.com"))["status"] == "error"


@pytest.mark.anyio
async def test_local_vt_quota_stops_requests(monkeypatch):
    monkeypatch.setattr(get_settings(), "ti_vt_per_minute", 2)
    calls = []
    mock(monkeypatch, lambda r: calls.append(1) or httpx.Response(200, json={"data": {"attributes": {}}}))
    st = [(await tp.virustotal("ip", "45.33.32.156"))["status"] for _ in range(3)]
    assert st == ["ok", "ok", "rate_limited"] and len(calls) == 2


@pytest.mark.anyio
async def test_lookup_routes_by_type_and_isolates_failures(monkeypatch):
    def h(r):
        if "virustotal" in r.url.host:
            raise httpx.ReadTimeout("x")
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 5}, "pulse_info": {"count": 1}})
    mock(monkeypatch, h)
    ip = await tp.lookup("ip", "45.33.32.156")
    assert set(ip) == {"virustotal", "abuseipdb", "otx"} and ip["virustotal"]["status"] == "timeout" and ip["abuseipdb"]["status"] == "ok"
    assert set(await tp.lookup("md5", "d41d8cd98f00b204e9800998ecf8427e")) == {"virustotal", "otx"}  # AbuseIPDB is IP-only
