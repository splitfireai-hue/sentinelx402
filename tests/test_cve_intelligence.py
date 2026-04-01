"""Integration tests for CVE intelligence endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _mock_cve(cve_id="CVE-2024-3400", score=10.0, desc="Test CVE"):
    """Create a mock CVE object matching nvdlib response shape."""
    cve = MagicMock()
    cve.id = cve_id
    cve.score = ["V31", score, "CRITICAL"]
    cve.cwe = [{"lang": "en", "value": "CWE-78"}]
    cve.references = []
    cve.cpe = []
    cve.descriptions = [{"lang": "en", "value": desc}]
    return cve


@pytest.mark.asyncio
async def test_cve_lookup(client):
    mock_cve = _mock_cve()
    with patch("app.services.cve_service.nvdlib") as mock_nvdlib:
        mock_nvdlib.searchCVE.return_value = [mock_cve]
        resp = await client.get("/api/v1/cves/CVE-2024-3400")

    assert resp.status_code == 200
    data = resp.json()
    assert data["cve_id"] == "CVE-2024-3400"
    assert data["cvss"] == 10.0
    assert data["risk"] == "critical"
    assert data["patch_urgency"] == "critical"


@pytest.mark.asyncio
async def test_cve_not_found(client):
    with patch("app.services.cve_service.nvdlib") as mock_nvdlib:
        mock_nvdlib.searchCVE.return_value = []
        resp = await client.get("/api/v1/cves/CVE-9999-0000")

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cve_invalid_format(client):
    resp = await client.get("/api/v1/cves/NOTACVE")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_recent_cves(client):
    mock_cves = [_mock_cve("CVE-2024-{}".format(i), 9.0 + i * 0.1) for i in range(3)]
    with patch("app.services.cve_service.nvdlib") as mock_nvdlib:
        mock_nvdlib.searchCVE.return_value = mock_cves
        resp = await client.get("/api/v1/cves/recent", params={"limit": 5})

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["cves"]) == 3
    assert data["total"] == 3


@pytest.mark.asyncio
async def test_search_cves(client):
    mock_cves = [_mock_cve("CVE-2024-1234", 8.5, "Apache vulnerability")]
    with patch("app.services.cve_service.nvdlib") as mock_nvdlib:
        mock_nvdlib.searchCVE.return_value = mock_cves
        resp = await client.get("/api/v1/cves/search", params={"keyword": "apache"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["keyword"] == "apache"
    assert len(data["results"]) == 1


@pytest.mark.asyncio
async def test_search_cves_keyword_too_short(client):
    resp = await client.get("/api/v1/cves/search", params={"keyword": "a"})
    assert resp.status_code == 422
