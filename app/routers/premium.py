"""Premium endpoints — API keys, historical data, webhooks.

These features create dependency on the SentinelX402 hosted infrastructure:
- API keys tie clients to your account system
- Historical data exists only on your server (not in public repo)
- Webhook subscriptions push data from your server to clients
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field, HttpUrl
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.lookup_history import APIKey, LookupHistory, Webhook

logger = logging.getLogger(__name__)
router = APIRouter()


# --- Schemas ---

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    email: str = Field(..., max_length=200)


class APIKeyResponse(BaseModel):
    key: str
    name: str
    tier: str
    monthly_quota: int
    created_at: datetime


class WebhookCreate(BaseModel):
    url: HttpUrl
    event_type: str = Field("new_threat", pattern="^(new_threat|india_advisory|critical_cve)$")
    filter_tag: Optional[str] = ""


class WebhookResponse(BaseModel):
    id: int
    url: str
    event_type: str
    filter_tag: str
    active: bool
    created_at: datetime


class HistoricalLookup(BaseModel):
    indicator_value: str
    indicator_type: str
    risk_score: float
    threat_type: str
    looked_up_at: datetime


class HistoricalStatsResponse(BaseModel):
    indicator: str
    total_lookups: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    unique_clients: int
    timeline: List[HistoricalLookup] = []


# --- Helpers ---

def _generate_key() -> str:
    """Generate a secure API key."""
    return "sx_" + secrets.token_urlsafe(32)


async def _validate_key(
    db: AsyncSession,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Optional[APIKey]:
    """Validate API key from header. Returns None if no key provided (free tier)."""
    if not x_api_key:
        return None
    result = await db.execute(
        select(APIKey).where(APIKey.key == x_api_key, APIKey.active == True)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    # Update last_used
    key.last_used = datetime.utcnow()
    await db.commit()
    return key


async def _require_key(
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> APIKey:
    """Require a valid API key for premium endpoints."""
    key = await _validate_key(db, x_api_key)
    if not key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Get one free at POST /api/v1/keys/register",
        )
    return key


# --- API Key Management ---

@router.post("/keys/register", response_model=APIKeyResponse)
async def register_key(
    body: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
):
    """Register for a free API key.

    Free tier: 10,000 requests/month, higher rate limits than anonymous.
    Upgrade to Pro for webhooks and historical data access.
    """
    # Check if email already registered
    existing = await db.execute(
        select(APIKey).where(APIKey.email == body.email, APIKey.active == True)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="Email already has an active API key. Contact support to reset.",
        )

    key = APIKey(
        key=_generate_key(),
        name=body.name,
        email=body.email,
        tier="free",
        monthly_quota=10000,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    return APIKeyResponse(
        key=key.key,
        name=key.name,
        tier=key.tier,
        monthly_quota=key.monthly_quota,
        created_at=key.created_at,
    )


@router.get("/keys/me", response_model=APIKeyResponse)
async def get_my_key(
    api_key: APIKey = Depends(_require_key),
):
    """Get info about your API key."""
    return APIKeyResponse(
        key=api_key.key,
        name=api_key.name,
        tier=api_key.tier,
        monthly_quota=api_key.monthly_quota,
        created_at=api_key.created_at,
    )


# --- Historical Data (requires API key) ---

@router.get("/history/{indicator}", response_model=HistoricalStatsResponse)
async def get_indicator_history(
    indicator: str,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(_require_key),
):
    """Get historical lookup stats for an indicator.

    Server-only data. Not replicable by forks — builds over time.
    Shows how often this indicator is being checked by agents worldwide.
    """
    since = datetime.utcnow() - timedelta(days=days)

    # Total lookups
    count_result = await db.execute(
        select(func.count(LookupHistory.id))
        .where(
            LookupHistory.indicator_value == indicator,
            LookupHistory.looked_up_at >= since,
        )
    )
    total = count_result.scalar_one() or 0

    # First/last seen
    first_result = await db.execute(
        select(func.min(LookupHistory.looked_up_at))
        .where(LookupHistory.indicator_value == indicator)
    )
    last_result = await db.execute(
        select(func.max(LookupHistory.looked_up_at))
        .where(LookupHistory.indicator_value == indicator)
    )

    # Unique clients
    clients_result = await db.execute(
        select(func.count(func.distinct(LookupHistory.client_id)))
        .where(
            LookupHistory.indicator_value == indicator,
            LookupHistory.looked_up_at >= since,
        )
    )
    unique_clients = clients_result.scalar_one() or 0

    # Recent timeline (last 20)
    timeline_result = await db.execute(
        select(LookupHistory)
        .where(LookupHistory.indicator_value == indicator)
        .order_by(desc(LookupHistory.looked_up_at))
        .limit(20)
    )
    timeline = [
        HistoricalLookup(
            indicator_value=row.indicator_value,
            indicator_type=row.indicator_type,
            risk_score=row.risk_score,
            threat_type=row.threat_type or "",
            looked_up_at=row.looked_up_at,
        )
        for row in timeline_result.scalars().all()
    ]

    return HistoricalStatsResponse(
        indicator=indicator,
        total_lookups=total,
        first_seen=first_result.scalar_one(),
        last_seen=last_result.scalar_one(),
        unique_clients=unique_clients,
        timeline=timeline,
    )


@router.get("/trending")
async def get_trending_threats(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(_require_key),
):
    """Get trending threats — most-looked-up indicators in the last N hours.

    Shows what AI agents worldwide are checking right now.
    Only available with API key.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(
            LookupHistory.indicator_value,
            LookupHistory.indicator_type,
            func.count(LookupHistory.id).label("lookup_count"),
            func.max(LookupHistory.risk_score).label("max_risk"),
            func.max(LookupHistory.threat_type).label("threat_type"),
        )
        .where(LookupHistory.looked_up_at >= since)
        .group_by(LookupHistory.indicator_value, LookupHistory.indicator_type)
        .order_by(desc("lookup_count"))
        .limit(limit)
    )

    return {
        "timeframe_hours": hours,
        "trending": [
            {
                "indicator": row[0],
                "type": row[1],
                "lookup_count": row[2],
                "max_risk_score": row[3],
                "threat_type": row[4] or "",
            }
            for row in result.all()
        ],
    }


# --- Webhooks (requires API key) ---

@router.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(
    body: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(_require_key),
):
    """Subscribe to real-time threat notifications via webhook.

    When a new threat matching your filter appears, we POST to your URL.
    Requires active API key — keeps you tied to our infrastructure.
    """
    webhook = Webhook(
        api_key=api_key.key,
        url=str(body.url),
        event_type=body.event_type,
        filter_tag=body.filter_tag or "",
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)

    return WebhookResponse(
        id=webhook.id,
        url=webhook.url,
        event_type=webhook.event_type,
        filter_tag=webhook.filter_tag,
        active=webhook.active,
        created_at=webhook.created_at,
    )


@router.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(_require_key),
):
    """List your webhook subscriptions."""
    result = await db.execute(
        select(Webhook).where(Webhook.api_key == api_key.key)
    )
    return [
        WebhookResponse(
            id=w.id,
            url=w.url,
            event_type=w.event_type,
            filter_tag=w.filter_tag,
            active=w.active,
            created_at=w.created_at,
        )
        for w in result.scalars().all()
    ]


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(_require_key),
):
    """Delete a webhook subscription."""
    result = await db.execute(
        select(Webhook).where(Webhook.id == webhook_id, Webhook.api_key == api_key.key)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(webhook)
    await db.commit()
    return {"deleted": webhook_id}
