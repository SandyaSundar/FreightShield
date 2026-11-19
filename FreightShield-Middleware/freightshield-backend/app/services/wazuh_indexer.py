"""Client for the Wazuh Indexer (OpenSearch) API, default port 9200. Basic auth from env vars."""
import httpx

from app.core.config import get_settings
from app.core.errors import NotConfiguredError, UpstreamError

_SERVICE = "wazuh_indexer"


class WazuhIndexerService:
    def __init__(self) -> None:
        self.s = get_settings()

    def configured(self) -> bool:
        s = self.s
        return bool(s.wazuh_indexer_url and s.wazuh_indexer_user and s.wazuh_indexer_password)

    async def request(self, method: str, path: str, json: dict | None = None) -> dict:
        if not self.configured():
            raise NotConfiguredError(_SERVICE)
        try:
            async with httpx.AsyncClient(base_url=self.s.wazuh_indexer_url, verify=self.s.wazuh_verify_ssl,
                                         timeout=self.s.wazuh_timeout_seconds,
                                         auth=(self.s.wazuh_indexer_user, self.s.wazuh_indexer_password)) as c:
                r = await c.request(method, path, json=json)
                r.raise_for_status()
                return r.json()
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code in (401, 403):
                raise UpstreamError(_SERVICE, "Wazuh Indexer rejected the configured credentials.", 502) from e
            raise UpstreamError(_SERVICE, f"Wazuh Indexer returned HTTP {code}.") from e
        except httpx.TimeoutException as e:
            raise UpstreamError(_SERVICE, "Wazuh Indexer timed out.", 504) from e
        except httpx.RequestError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e).upper():
                raise UpstreamError(_SERVICE, "TLS verification of Wazuh Indexer failed (untrusted certificate).", 502) from e
            raise UpstreamError(_SERVICE, f"Cannot reach Wazuh Indexer ({type(e).__name__}).", 503) from e

    async def cluster_health(self) -> dict:
        return await self.request("GET", "/_cluster/health")

    async def search_alerts(self, query: dict, size: int = 50) -> dict:
        """Run a search against wazuh-alerts-* with a caller-supplied OpenSearch query body."""
        return await self.request("POST", "/wazuh-alerts-*/_search", json={**query, "size": min(size, 500)})

    async def get_alerts(self, limit: int, offset: int, min_level: int | None = None) -> dict:
        """Real alerts from wazuh-alerts-*, newest first. Nothing is synthesised."""
        query: dict = {"query": {"range": {"rule.level": {"gte": min_level}}} if min_level else {"match_all": {}},
                       "sort": [{"timestamp": {"order": "desc"}}], "from": offset, "track_total_hits": True}
        data = await self.search_alerts(query, size=limit)
        hits = data.get("hits", {})
        total = hits.get("total", {})
        return {"total": total.get("value", 0) if isinstance(total, dict) else int(total or 0),
                "hits": [{"_id": h.get("_id"), "_source": h.get("_source", {})} for h in hits.get("hits", [])]}


wazuh_indexer = WazuhIndexerService()
