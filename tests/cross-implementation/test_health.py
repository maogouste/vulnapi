"""
Health endpoint tests for API Security Dojo.

Verifies that /health endpoint works correctly across all implementations.
"""

import pytest


class TestHealthEndpoint:
    """Test /health endpoint across all backends."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, backend, http_client):
        """Test that /health returns 200 OK."""
        backend_name, backend_config = backend
        url = backend_config["url"]

        response = await http_client.get(f"{url}/health")

        assert response.status_code == 200, f"{backend_name}: /health should return 200"

    @pytest.mark.asyncio
    async def test_health_returns_status_healthy(self, backend, http_client):
        """Test that /health returns status: healthy."""
        backend_name, backend_config = backend
        url = backend_config["url"]

        response = await http_client.get(f"{url}/health")
        data = response.json()

        assert "status" in data, f"{backend_name}: /health should return 'status' field"
        assert data["status"] == "healthy", f"{backend_name}: status should be 'healthy'"

    @pytest.mark.asyncio
    async def test_health_returns_json(self, backend, http_client):
        """Test that /health returns valid JSON with correct content-type."""
        backend_name, backend_config = backend
        url = backend_config["url"]

        response = await http_client.get(f"{url}/health")

        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type, \
            f"{backend_name}: /health should return application/json"

        # Should not raise exception
        data = response.json()
        assert isinstance(data, dict), f"{backend_name}: /health should return JSON object"
