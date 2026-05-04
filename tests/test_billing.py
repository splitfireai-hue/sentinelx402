"""Shared-billing tests for SentinelX402.

These mirror the auth/middleware tests in SentinelCorp — the same code is wired
into both services so a key issued on one works on the other (assuming both
services point at the same Postgres in production).
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

from app.services import auth


@pytest.mark.asyncio
async def test_tiers_match_sentinelcorp():
    assert set(auth.TIERS.keys()) == {"free", "dev", "startup", "enterprise"}
    assert auth.TIERS["dev"].monthly_quota == 50_000
    assert auth.TIERS["startup"].monthly_quota == 500_000


@pytest.mark.asyncio
async def test_x402_billing_product_is_correct():
    from app.config import settings

    assert settings.BILLING_PRODUCT == "sentinelx402"


@pytest.mark.asyncio
async def test_pricing_redirects_to_sentinelcorp():
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/pricing.json")
        assert r.status_code == 200
        d = r.json()
        assert d["billing_enabled"] in (True, False)
        assert "sentinelcorp" in d["signup_url"]
        assert "sentinelcorp" in d["dashboard_url"]


@pytest.mark.asyncio
async def test_billing_me_requires_key():
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/billing/me")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_key_format_and_hash():
    raw = auth.generate_raw_key()
    assert raw.startswith("sk_live_")
    h = auth.hash_key(raw)
    assert len(h) == 64
    assert h == auth.hash_key(raw)
