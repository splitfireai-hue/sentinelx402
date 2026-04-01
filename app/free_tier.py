"""Free tier tracking — first N requests free per client (IP or wallet address)."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.usage import UsageRecord

logger = logging.getLogger(__name__)

# Paths that are always free
FREE_PATHS = {"/health", "/info", "/usage", "/docs", "/redoc", "/openapi.json"}


def get_client_id_from_request(request) -> str:
    """Extract client identifier — wallet address header or IP."""
    wallet = request.headers.get("x-wallet-address", "")
    if wallet:
        return "wallet:{}".format(wallet.lower())
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    return "ip:{}".format(client_ip)


def is_free_path(path: str) -> bool:
    return path in FREE_PATHS or not path.startswith("/api/")


async def track_usage(client_id: str, db: AsyncSession) -> Optional[int]:
    """Track a request. Returns remaining free requests, or None if exhausted."""
    result = await db.execute(
        select(UsageRecord).where(UsageRecord.client_id == client_id)
    )
    record = result.scalar_one_or_none()

    if record is None:
        record = UsageRecord(
            client_id=client_id,
            request_count=0,
            first_request=datetime.utcnow(),
            last_request=datetime.utcnow(),
        )
        db.add(record)
        await db.flush()

    if record.request_count >= settings.FREE_TIER_REQUESTS:
        return None  # exhausted

    record.request_count += 1
    record.last_request = datetime.utcnow()
    await db.commit()

    return settings.FREE_TIER_REQUESTS - record.request_count


async def get_usage(client_id: str, db: AsyncSession) -> dict:
    """Get usage stats for a client."""
    result = await db.execute(
        select(UsageRecord).where(UsageRecord.client_id == client_id)
    )
    record = result.scalar_one_or_none()
    used = record.request_count if record else 0
    limit = settings.FREE_TIER_REQUESTS
    return {
        "client_id": client_id,
        "used": used,
        "limit": limit,
        "remaining": max(limit - used, 0),
        "free_tier_active": used < limit,
    }
