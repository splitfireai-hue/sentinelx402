"""Tests for free tier tracking and usage endpoint."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_usage_endpoint_initial(client):
    resp = await client.get("/usage")
    assert resp.status_code == 200
    data = resp.json()
    assert data["used"] == 0
    assert data["limit"] == 1000
    assert data["remaining"] == 1000
    assert data["free_tier_active"] is True


@pytest.mark.asyncio
async def test_free_tier_decrements(client):
    # Check initial usage
    usage1 = await client.get("/usage")
    used_before = usage1.json()["used"]

    # Make a paid API call
    await client.get("/api/v1/threats/lookup", params={"domain": "login-secure-paypal.com"})

    # Check usage incremented
    usage2 = await client.get("/usage")
    used_after = usage2.json()["used"]
    assert used_after == used_before + 1


@pytest.mark.asyncio
async def test_free_paths_not_counted(client):
    usage1 = await client.get("/usage")
    used_before = usage1.json()["used"]

    # Health, info, usage are free — should not count
    await client.get("/health")
    await client.get("/info")
    await client.get("/usage")

    usage2 = await client.get("/usage")
    used_after = usage2.json()["used"]
    assert used_after == used_before


@pytest.mark.asyncio
async def test_info_shows_free_tier(client):
    resp = await client.get("/info")
    data = resp.json()
    assert "free_tier" in data
    assert data["free_tier"]["enabled"] is True
    assert data["free_tier"]["requests"] == 1000


@pytest.mark.asyncio
async def test_multiple_calls_decrement(client):
    # Make 3 API calls
    await client.get("/api/v1/threats/lookup", params={"domain": "login-secure-paypal.com"})
    await client.get("/api/v1/threats/ip", params={"ip": "185.220.101.42"})
    await client.get("/api/v1/threats/feed", params={"page": 1, "page_size": 5})

    usage = await client.get("/usage")
    data = usage.json()
    assert data["used"] == 3
    assert data["remaining"] == 997
