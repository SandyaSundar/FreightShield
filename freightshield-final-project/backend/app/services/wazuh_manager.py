"""Client for the Wazuh Manager (server) API, default port 55000.

Auth flow: POST /security/user/authenticate with HTTP Basic -> short-lived JWT,
then send it as a Bearer token. Credentials come from env vars only.
"""
import time

import httpx

from app.core.config import get_settings
from app.core.errors import NotConfiguredError, UpstreamError

_SERVICE = "wazuh_manager"


class WazuhManagerService:
    def __init__(self) -> None:
        self.s = get_settings()
        self._token: str | None = None
        self._token_ts = 0.0

    def configured(self) -> bool:
        s = self.s
        return bool(s.wazuh_manager_url and s.wazuh_manager_user and s.wazuh_manager_password)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.s.wazuh_manager_url, verify=self.s.wazuh_verify_ssl,
                                 timeout=self.s.wazuh_timeout_seconds)

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        # Wazuh JWTs last 15 min by default; refresh a bit early.
        if self._token and time.time() - self._token_ts < 600:
            return self._token
        r = await client.post("/security/user/authenticate?raw=true",
                              auth=(self.s.wazuh_manager_user, self.s.wazuh_manager_password))
        if r.status_code == 401:
            raise UpstreamError(_SERVICE, "Wazuh Manager rejected the configured credentials.", 502)
        r.raise_for_status()
        self._token, self._token_ts = r.text.strip(), time.time()
        return self._token

    async def request(self, method: str, path: str, params: dict | None = None, json: dict | None = None) -> dict:
        """Authenticated call to the Manager API. Returns parsed JSON."""
        if not self.configured():
            raise NotConfiguredError(_SERVICE)
        try:
            async with self._client() as c:
                token = await self._get_token(c)
                r = await c.request(method, path, params=params, json=json, headers={"Authorization": f"Bearer {token}"})
                r.raise_for_status()
                return r.json()
        except httpx.HTTPStatusError as e:
            raise UpstreamError(_SERVICE, f"Wazuh Manager returned HTTP {e.response.status_code}.") from e
        except httpx.TimeoutException as e:
            raise UpstreamError(_SERVICE, "Wazuh Manager timed out.", 504) from e
        except httpx.RequestError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e).upper():
                raise UpstreamError(_SERVICE, "TLS verification of Wazuh Manager failed (untrusted certificate).", 502) from e
            raise UpstreamError(_SERVICE, f"Cannot reach Wazuh Manager ({type(e).__name__}).", 503) from e

    async def get_info(self) -> dict:
        return await self.request("GET", "/")

    async def list_agents(self, status: str | None = None, limit: int = 500, offset: int = 0,
                          agent_ids: list[str] | None = None) -> dict:
        params: dict = {"limit": limit, "offset": offset, "sort": "+id"}
        if agent_ids is not None:  # callers must not pass an empty list (Wazuh would then return ALL agents)
            params["agents_list"] = ",".join(agent_ids)
        if status:
            params["status"] = status
        return await self.request("GET", "/agents", params=params)

    async def active_response(self, agent_id: str, command: str, arguments: list[str], alert: dict | None = None) -> dict:
        """PUT /active-response: run an Active Response command on ONE agent (never broadcast)."""
        body: dict = {"command": command, "arguments": arguments}
        if alert:
            body["alert"] = alert
        return await self.request("PUT", "/active-response", params={"agents_list": agent_id}, json=body)


wazuh_manager = WazuhManagerService()
