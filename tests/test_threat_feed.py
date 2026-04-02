"""Integration tests for threat feed endpoints."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert data["checks"]["database"] == "ok"


@pytest.mark.asyncio
async def test_info(client):
    resp = await client.get("/info")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "SentinelX402"
    assert len(data["endpoints"]) == 6
    assert data["free_tier"]["requests"] == 1000


@pytest.mark.asyncio
async def test_domain_lookup_known(client):
    resp = await client.get("/api/v1/threats/lookup", params={"domain": "login-secure-paypal.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "login-secure-paypal.com"
    assert data["risk_score"] >= 90
    assert data["threat_type"] == "phishing"
    assert data["confidence"] == 0.95
    assert len(data["related_domains"]) > 0


@pytest.mark.asyncio
async def test_domain_lookup_unknown(client):
    resp = await client.get("/api/v1/threats/lookup", params={"domain": "totally-safe-site.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "risk_score" in data
    assert "threat_type" in data


@pytest.mark.asyncio
async def test_domain_lookup_invalid(client):
    resp = await client.get("/api/v1/threats/lookup", params={"domain": "not a domain!!!"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_ip_known(client):
    resp = await client.get("/api/v1/threats/ip", params={"ip": "185.220.101.42"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "185.220.101.42"
    assert data["risk_score"] >= 90
    assert "c2" in data["threat_types"]


@pytest.mark.asyncio
async def test_ip_unknown(client):
    resp = await client.get("/api/v1/threats/ip", params={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] < 20


@pytest.mark.asyncio
async def test_ip_invalid(client):
    resp = await client.get("/api/v1/threats/ip", params={"ip": "not-an-ip"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_feed(client):
    resp = await client.get("/api/v1/threats/feed", params={"page": 1, "page_size": 10})
    assert resp.status_code == 200
    data = resp.json()
    assert "indicators" in data
    assert data["total"] >= 1
    assert data["page"] == 1
    assert data["page_size"] == 10


@pytest.mark.asyncio
async def test_security_headers(client):
    resp = await client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
