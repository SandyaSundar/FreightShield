import pytest
import httpx
from app.main import app

@pytest.mark.anyio
async def test_health_endpoint():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver"
    ) as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "freightshield-backend"
        assert "environment" in data
        assert "timestamp" in data
        assert "integrations" in data
        assert data["integrations"]["wazuh_manager_configured"] is False
        assert data["integrations"]["wazuh_indexer_configured"] is False

@pytest.mark.anyio
async def test_cors_headers_localhost():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver"
    ) as client:
        response = await client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET"
            }
        )
        assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"

@pytest.mark.anyio
async def test_cors_headers_loopback():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver"
    ) as client:
        response = await client.options(
            "/api/health",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "GET"
            }
        )
        assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"

@pytest.mark.anyio
async def test_placeholder_endpoints_return_501():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver"
    ) as client:
        r_auth = await client.get("/api/auth/status")
        assert r_auth.status_code == 501

        r_rbac = await client.get("/api/rbac/status")
        assert r_rbac.status_code == 501

        r_ai = await client.get("/api/ai/status")
        assert r_ai.status_code == 501

@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    from tests.helpers import set_secret
    set_secret(monkeypatch)


@pytest.mark.anyio
async def test_unconfigured_wazuh_safe_error_response():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver"
    ) as client:
        from tests.helpers import auth_headers
        h = auth_headers()
        r_mgr = await client.get("/api/wazuh/manager/agents", headers=h)
        assert r_mgr.status_code == 503
        mgr_data = r_mgr.json()
        assert mgr_data["error"] == "not_configured"
        assert mgr_data["service"] == "wazuh_manager"
        assert "password" not in str(mgr_data).lower()
        assert "user" not in str(mgr_data).lower()

        # Wazuh indexer health when unconfigured returns 503
        r_idx = await client.get("/api/wazuh/indexer/health", headers=h)
        assert r_idx.status_code == 503
        idx_data = r_idx.json()
        assert idx_data["error"] == "not_configured"
        assert idx_data["service"] == "wazuh_indexer"
