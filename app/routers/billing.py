"""Read-only billing endpoints for SentinelX402.

Signup, checkout, and webhooks live in SentinelCorp — keys issued there work
here too because both services share the same Postgres `api_keys` table. This
module just exposes /billing/me and /billing/subscription so users can check
their X402-specific usage without having to flip between dashboards.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.services import auth as auth_service

logger = logging.getLogger(__name__)
router = APIRouter()


class KeyInfoResponse(BaseModel):
    prefix: str
    last4: str
    tier: str
    status: str
    email: str
    monthly_quota: int
    used_this_month: int
    remaining: int
    rate_limit_per_min: int
    product: str = "sentinelx402"


class SubscriptionInfo(BaseModel):
    rail: str
    plan: str
    status: str
    currency: str
    amount_minor: int
    current_period_start: Optional[str]
    current_period_end: Optional[str]
    cancel_at_period_end: bool


class DashboardData(BaseModel):
    key: KeyInfoResponse
    subscription: Optional[SubscriptionInfo] = None
    sibling_url: str = "https://sentinelcorp-production.up.railway.app/billing/dashboard"


async def _require_key(
    x_api_key: str = Header(default="", alias="X-API-Key"),
    authorization: str = Header(default=""),
    session: AsyncSession = Depends(get_db),
):
    raw = x_api_key.strip()
    if not raw and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    if not raw:
        raise HTTPException(status_code=401, detail="Provide X-API-Key header")
    api_key = await auth_service.lookup_key(session, raw)
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key


async def _latest_subscription(session: AsyncSession, api_key_id: int):
    from app.models.billing import Subscription

    result = await session.execute(
        select(Subscription)
        .where(Subscription.api_key_id == api_key_id)
        .order_by(desc(Subscription.created_at))
        .limit(1)
    )
    return result.scalar_one_or_none()


@router.get("/billing/me", response_model=KeyInfoResponse)
async def my_key_info(
    api_key=Depends(_require_key),
    session: AsyncSession = Depends(get_db),
):
    used = await auth_service.get_monthly_count(session, api_key.id, settings.BILLING_PRODUCT)
    return KeyInfoResponse(
        prefix=api_key.key_prefix,
        last4=api_key.key_last4,
        tier=api_key.tier,
        status=api_key.status,
        email=api_key.email,
        monthly_quota=api_key.monthly_quota,
        used_this_month=used,
        remaining=max(api_key.monthly_quota - used, 0),
        rate_limit_per_min=api_key.rate_limit_per_min,
    )


@router.get("/billing/subscription", response_model=DashboardData)
async def my_subscription(
    api_key=Depends(_require_key),
    session: AsyncSession = Depends(get_db),
):
    used = await auth_service.get_monthly_count(session, api_key.id, settings.BILLING_PRODUCT)
    key_info = KeyInfoResponse(
        prefix=api_key.key_prefix,
        last4=api_key.key_last4,
        tier=api_key.tier,
        status=api_key.status,
        email=api_key.email,
        monthly_quota=api_key.monthly_quota,
        used_this_month=used,
        remaining=max(api_key.monthly_quota - used, 0),
        rate_limit_per_min=api_key.rate_limit_per_min,
    )
    sub = await _latest_subscription(session, api_key.id)
    sub_info = None
    if sub is not None:
        sub_info = SubscriptionInfo(
            rail=sub.rail,
            plan=sub.plan,
            status=sub.status,
            currency=sub.currency,
            amount_minor=sub.amount_minor,
            current_period_start=sub.current_period_start.isoformat() if sub.current_period_start else None,
            current_period_end=sub.current_period_end.isoformat() if sub.current_period_end else None,
            cancel_at_period_end=sub.cancel_at_period_end,
        )
    return DashboardData(key=key_info, subscription=sub_info)


@router.get("/pricing.json")
async def pricing_json():
    from app.services.auth import ANON_DAILY_LIMIT, TIERS

    return {
        "tiers": [
            {
                "name": t.name,
                "display_name": t.display_name,
                "monthly_quota": t.monthly_quota,
                "rate_limit_per_min": t.rate_limit_per_min,
                "price_inr_monthly": t.price_inr_monthly,
                "price_usd_monthly": t.price_usd_monthly,
            }
            for t in TIERS.values()
        ],
        "anon_daily_limit": ANON_DAILY_LIMIT,
        "billing_enabled": settings.BILLING_ENABLED,
        "note": "Subscriptions are managed at sentinelcorp — your key works on both products",
        "signup_url": "https://sentinelcorp-production.up.railway.app/signup",
        "pricing_url": "https://sentinelcorp-production.up.railway.app/pricing",
        "dashboard_url": "https://sentinelcorp-production.up.railway.app/billing/dashboard",
    }


@router.get("/pricing", response_class=HTMLResponse, include_in_schema=False)
async def pricing_redirect():
    return """<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="0;url=https://sentinelcorp-production.up.railway.app/pricing">
<title>Redirecting to pricing</title>
</head><body>
Subscriptions are managed centrally. <a href="https://sentinelcorp-production.up.railway.app/pricing">Continue to pricing &rarr;</a>
</body></html>"""
