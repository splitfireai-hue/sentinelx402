"""Test fixtures for SentinelX402."""

from __future__ import annotations

import json
import os
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Override settings BEFORE importing app modules
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"  # in-memory SQLite
os.environ["REDIS_URL"] = ""
os.environ["X402_ENABLED"] = "false"
os.environ["ENVIRONMENT"] = "test"

from app.models.base import Base
from app.models.threat import ThreatIndicator

engine = create_async_engine("sqlite+aiosqlite://", echo=False)
test_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
async def setup_db():
    """Create and tear down tables for each test."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db() -> AsyncGenerator[AsyncSession, None]:
    async with test_session_factory() as session:
        yield session


@pytest.fixture
async def seeded_db(db: AsyncSession) -> AsyncSession:
    """DB with sample threat indicators."""
    indicators = [
        ThreatIndicator(
            indicator_type="domain",
            value="login-secure-paypal.com",
            risk_score=94,
            threat_type="phishing",
            source="sentinelx402",
            tags=json.dumps(["financial", "credential-theft"]),
        ),
        ThreatIndicator(
            indicator_type="domain",
            value="secure-paypa1-login.com",
            risk_score=96,
            threat_type="phishing",
            source="sentinelx402",
            tags=json.dumps(["financial", "credential-theft"]),
        ),
        ThreatIndicator(
            indicator_type="ip",
            value="185.220.101.42",
            risk_score=95,
            threat_type="c2",
            source="sentinelx402",
            tags=json.dumps(["cobalt-strike", "c2-server"]),
        ),
    ]
    db.add_all(indicators)
    await db.commit()
    return db


@pytest.fixture
async def client(seeded_db):
    """Test client with seeded DB, no Redis, no x402."""
    from httpx import ASGITransport, AsyncClient
    from app.database import get_db
    from app.main import app

    async def override_get_db():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    with patch("app.main.init_redis", new_callable=AsyncMock), \
         patch("app.main.close_redis", new_callable=AsyncMock), \
         patch("app.services.threat_service.cache_get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.threat_service.cache_set", new_callable=AsyncMock), \
         patch("app.services.cve_service.cache_get", new_callable=AsyncMock, return_value=None), \
         patch("app.services.cve_service.cache_set", new_callable=AsyncMock):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    app.dependency_overrides.clear()
