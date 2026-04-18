"""
ai/tests/test_api.py

Integration tests for the FastAPI HTTP endpoints.
Uses httpx.AsyncClient with an in-memory DuckDB (no filesystem).

Run: pytest ai/tests/ -v --asyncio-mode=auto
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from ai.main import app
from ai.core.models import (
    AIRequest,
    Finding,
    OWASPCategory,
    Severity,
    Endpoint,
    HTTPMethod,
    EndpointStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client():
    """HTTP test client using the FastAPI app with lifespan disabled."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


def _sample_finding(idx: int = 1) -> dict:
    return {
        "id": f"BOLA-test-{idx}",
        "severity": "CRITICAL",
        "owasp_category": "API1:2023 - Broken Object Level Authorization",
        "title": "BOLA test finding",
        "description": "Test description",
        "evidence": f"GET /v1/users/100{idx} → 200",
        "cvss_score": 8.1,
        "risk_score": 85,
        "tags": ["BOLA", "IDOR"],
        "endpoint": {
            "path": f"/v1/users/100{idx}/orders",
            "method": "GET",
            "auth_required": True,
            "auth_type": "JWT/Bearer",
            "has_rate_limit": False,
            "endpoint_status": "DOCUMENTED",
            "status_code": 200,
        },
    }


def _sample_request(n_findings: int = 2) -> dict:
    return {
        "scan_id": "test-abcd1234",
        "target": "https://api.test.example.com",
        "findings": [_sample_finding(i) for i in range(1, n_findings + 1)],
    }


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_health_returns_ok(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "model_loaded" in data
    assert "version" in data


# ---------------------------------------------------------------------------
# /analyze-findings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_analyze_findings_structure(client):
    """Verify response structure matches AIResponse schema."""
    with patch("ai.main.generate_remediation") as mock_gen, \
         patch("ai.main.get_cached_remediation", return_value=None), \
         patch("ai.main.save_remediation_cache"), \
         patch("ai.main.log_findings"):

        mock_gen.return_value = (
            "Add ownership validation before returning resources.",
            "if current_user.id != user_id:\n    raise HTTPException(403)",
        )

        resp = await client.post("/analyze-findings", json=_sample_request(2))

    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert "findings_enriched" in data
    assert "model_used" in data
    assert "inference_ms" in data
    assert data["findings_enriched"] == 2
    assert len(data["findings"]) == 2


@pytest.mark.asyncio
async def test_analyze_findings_each_has_id(client):
    with patch("ai.main.generate_remediation") as mock_gen, \
         patch("ai.main.get_cached_remediation", return_value=None), \
         patch("ai.main.save_remediation_cache"), \
         patch("ai.main.log_findings"):

        mock_gen.return_value = ("Remediation text.", "code snippet here")
        resp = await client.post("/analyze-findings", json=_sample_request(3))

    data = resp.json()
    ids = [f["id"] for f in data["findings"]]
    assert ids == ["BOLA-test-1", "BOLA-test-2", "BOLA-test-3"]


@pytest.mark.asyncio
async def test_analyze_findings_uses_cache(client):
    """Cache hit should not call generate_remediation."""
    with patch("ai.main.generate_remediation") as mock_gen, \
         patch("ai.main.get_cached_remediation", return_value=("cached fix", "cached code")), \
         patch("ai.main.save_remediation_cache"), \
         patch("ai.main.log_findings"):

        resp = await client.post("/analyze-findings", json=_sample_request(1))

    mock_gen.assert_not_called()
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_analyze_findings_empty_payload(client):
    resp = await client.post("/analyze-findings", json={"scan_id": "x", "target": "y", "findings": []})
    assert resp.status_code == 200
    assert resp.json()["findings_enriched"] == 0


@pytest.mark.asyncio
async def test_analyze_findings_llm_failure_returns_fallback(client):
    """When LLM raises, a fallback message should still be returned (not 500)."""
    with patch("ai.main.generate_remediation", side_effect=RuntimeError("LLM unavailable")), \
         patch("ai.main.get_cached_remediation", return_value=None), \
         patch("ai.main.log_findings"):

        resp = await client.post("/analyze-findings", json=_sample_request(1))

    assert resp.status_code == 200
    # Enriched count is 0 because the finding raised, but we still get a response entry
    data = resp.json()
    assert len(data["findings"]) == 1
    assert "unavailable" in data["findings"][0]["remediation"].lower()


# ---------------------------------------------------------------------------
# /history
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_history_returns_list(client):
    with patch("ai.main.get_scan_history") as mock_hist:
        from ai.core.models import HistoryResponse
        mock_hist.return_value = HistoryResponse(entries=[], total=0)
        resp = await client.get("/history")

    assert resp.status_code == 200
    assert "entries" in resp.json()
    assert "total" in resp.json()


@pytest.mark.asyncio
async def test_history_target_filter(client):
    with patch("ai.main.get_scan_history") as mock_hist:
        from ai.core.models import HistoryResponse
        mock_hist.return_value = HistoryResponse(entries=[], total=0)
        resp = await client.get("/history", params={"target": "https://api.example.com"})

    assert resp.status_code == 200
    mock_hist.assert_called_once()
    call_args = mock_hist.call_args
    assert call_args[0][0] == "https://api.example.com"
