"""Threat-intel feed clients (VirusTotal v3, AbuseIPDB v2, AlienVault OTX). API keys are sent only in request headers and are
never logged or returned. Every call yields {status, summary}; status in ok|not_found|unavailable|rate_limited|timeout|error.
A failing feed never raises: the caller keeps the other feeds' verdicts."""
import asyncio
import logging
import time

import httpx

from app.core.config import get_settings
from app.services.ti_ioc import vt_url_id
from app.services import secret_vault

log = logging.getLogger("freightshield.ti")
VT, ABUSE, OTX = "virustotal", "abuseipdb", "otx"
SUPPORTS = {VT: {"ip", "domain", "url", "md5", "sha1", "sha256"}, ABUSE: {"ip"}, OTX: {"ip", "domain", "url", "md5", "sha1", "sha256"}}


class _Limiter:
    """Sliding-window limiter (per provider, per process): wait-free refusal -> 'rate_limited' rather than hammering the API."""
    def __init__(self):
        self.hits: dict[str, list[float]] = {}

    def allow(self, name: str, per_minute: int) -> bool:
        now, h = time.monotonic(), self.hits.setdefault(name, [])
        h[:] = [t for t in h if now - t < 60]
        if len(h) >= per_minute:
            return False
        h.append(now)
        return True


limiter = _Limiter()


def keys() -> dict[str, str]:
    s = get_settings()
    return {VT: secret_vault.get("VIRUSTOTAL_API_KEY") or s.virustotal_api_key,
            ABUSE: secret_vault.get("ABUSEIPDB_API_KEY") or s.abuseipdb_api_key,
            OTX: secret_vault.get("OTX_API_KEY") or s.otx_api_key}


def status() -> dict:
    return {p: {"configured": bool(k)} for p, k in keys().items()}   # booleans only: key material never leaves the server


def _res(status: str, summary: dict | None = None) -> dict:
    return {"status": status, "summary": summary or {}}


async def _get(url: str, headers: dict, params: dict | None = None, rate: tuple[str, int] | None = None) -> dict:
    if rate and not limiter.allow(*rate):
        return _res("rate_limited", {"detail": "local quota reached"})
    try:
        async with httpx.AsyncClient(timeout=get_settings().ti_timeout_seconds) as c:
            r = await c.get(url, headers=headers, params=params)
    except httpx.TimeoutException:
        return _res("timeout")
    except httpx.RequestError as e:
        return _res("error", {"detail": f"cannot reach feed ({type(e).__name__})"})
    if r.status_code == 404:
        return _res("not_found")
    if r.status_code == 429:
        return _res("rate_limited", {"detail": "feed returned 429"})
    if r.status_code in (401, 403):
        return _res("error", {"detail": "feed rejected the configured API key"})
    if r.status_code >= 400:
        return _res("error", {"detail": f"feed returned HTTP {r.status_code}"})
    try:
        return {"status": "ok", "summary": {}, "json": r.json()}
    except ValueError:
        return _res("error", {"detail": "feed returned invalid JSON"})


async def virustotal(kind: str, value: str) -> dict:
    k = keys()[VT]
    if not k:
        return _res("unavailable", {"detail": "VIRUSTOTAL_API_KEY not set"})
    path = {"ip": f"ip_addresses/{value}", "domain": f"domains/{value}", "url": f"urls/{vt_url_id(value)}"}.get(kind, f"files/{value}")
    r = await _get(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": k}, rate=(VT, get_settings().ti_vt_per_minute))
    if r["status"] != "ok":
        return r
    a = (r["json"].get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    return _res("ok", {"malicious": int(st.get("malicious", 0)), "suspicious": int(st.get("suspicious", 0)),
                       "harmless": int(st.get("harmless", 0)), "undetected": int(st.get("undetected", 0)),
                       "reputation": a.get("reputation"), "last_analysis_date": a.get("last_analysis_date")})


async def abuseipdb(kind: str, value: str) -> dict:
    k = keys()[ABUSE]
    if not k:
        return _res("unavailable", {"detail": "ABUSEIPDB_API_KEY not set"})
    r = await _get("https://api.abuseipdb.com/api/v2/check", {"Key": k, "Accept": "application/json"},
                   {"ipAddress": value, "maxAgeInDays": 90})
    if r["status"] != "ok":
        return r
    d = r["json"].get("data") or {}
    return _res("ok", {"abuse_confidence": int(d.get("abuseConfidenceScore", 0)), "total_reports": int(d.get("totalReports", 0)),
                       "country": d.get("countryCode"), "isp": d.get("isp"), "last_reported_at": d.get("lastReportedAt")})


async def otx(kind: str, value: str) -> dict:
    k = keys()[OTX]
    if not k:
        return _res("unavailable", {"detail": "OTX_API_KEY not set"})
    seg = {"ip": "IPv4", "domain": "domain", "url": "url"}.get(kind, "file")
    r = await _get(f"https://otx.alienvault.com/api/v1/indicators/{seg}/{value}/general", {"X-OTX-API-KEY": k})
    if r["status"] != "ok":
        return r
    pulses = (r["json"].get("pulse_info") or {})
    return _res("ok", {"pulse_count": int(pulses.get("count", 0)),
                       "pulse_names": [str(p.get("name"))[:80] for p in (pulses.get("pulses") or [])[:5]]})


FUNCS = {VT: virustotal, ABUSE: abuseipdb, OTX: otx}


async def lookup(kind: str, value: str) -> dict[str, dict]:
    """Query every provider that supports this IOC type, concurrently. Never raises."""
    names = [p for p, t in SUPPORTS.items() if kind in t]
    rs = await asyncio.gather(*(FUNCS[p](kind, value) for p in names), return_exceptions=True)
    out = {}
    for p, r in zip(names, rs):
        if isinstance(r, Exception):
            log.warning("feed %s failed: %s", p, type(r).__name__)
            r = _res("error", {"detail": f"unexpected failure ({type(r).__name__})"})
        r.pop("json", None)
        out[p] = r
    return out
