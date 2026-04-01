"""Threat intelligence service — domain lookup, IP reputation, feed."""

from __future__ import annotations

import json
import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_get, cache_set
from app.models.threat import ThreatIndicator
from app.schemas.threat import (
    DomainRiskResponse,
    IPReputationResponse,
    ThreatFeedItem,
    ThreatFeedResponse,
)
from app.services.scoring import compute_domain_risk

logger = logging.getLogger(__name__)


async def lookup_domain(domain: str, db: AsyncSession) -> DomainRiskResponse:
    cache_key = "threat:domain:{}".format(domain)
    try:
        cached = await cache_get(cache_key)
        if cached:
            return DomainRiskResponse(**cached)
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    # Check database for known indicator
    result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.value == domain,
            ThreatIndicator.indicator_type == "domain",
        )
    )
    indicator = result.scalar_one_or_none()

    if indicator:
        tags = json.loads(indicator.tags) if indicator.tags else []
        # Find related domains (usage flywheel)
        related_result = await db.execute(
            select(ThreatIndicator.value)
            .where(
                ThreatIndicator.indicator_type == "domain",
                ThreatIndicator.threat_type == indicator.threat_type,
                ThreatIndicator.value != domain,
            )
            .order_by(ThreatIndicator.risk_score.desc())
            .limit(5)
        )
        related = [r[0] for r in related_result.all()]

        response = DomainRiskResponse(
            domain=domain,
            risk_score=indicator.risk_score,
            threat_type=indicator.threat_type,
            confidence=0.95,
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen,
            related_domains=related,
            tags=tags,
        )
    else:
        risk = compute_domain_risk(domain)
        response = DomainRiskResponse(
            domain=domain,
            risk_score=risk.score,
            threat_type=risk.threat_type,
            confidence=risk.confidence,
            related_domains=[],
            tags=[],
        )

    try:
        await cache_set(cache_key, response.model_dump(), ttl=21600)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response


async def check_ip(ip: str, db: AsyncSession) -> IPReputationResponse:
    cache_key = "threat:ip:{}".format(ip)
    try:
        cached = await cache_get(cache_key)
        if cached:
            return IPReputationResponse(**cached)
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    result = await db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.value == ip,
            ThreatIndicator.indicator_type == "ip",
        )
    )
    indicator = result.scalar_one_or_none()

    if indicator:
        tags = json.loads(indicator.tags) if indicator.tags else []
        response = IPReputationResponse(
            ip=ip,
            risk_score=indicator.risk_score,
            threat_types=[indicator.threat_type],
            tags=tags,
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen,
        )
    else:
        response = IPReputationResponse(
            ip=ip,
            risk_score=5.0,
            threat_types=[],
            tags=["unknown"],
        )

    try:
        await cache_set(cache_key, response.model_dump(), ttl=21600)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response


async def get_threat_feed(
    db: AsyncSession, page: int = 1, page_size: int = 50
) -> ThreatFeedResponse:
    cache_key = "threat:feed:page:{}:size:{}".format(page, page_size)
    try:
        cached = await cache_get(cache_key)
        if cached:
            return ThreatFeedResponse(**cached)
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    offset = (page - 1) * page_size

    count_result = await db.execute(select(func.count(ThreatIndicator.id)))
    total = count_result.scalar_one()

    result = await db.execute(
        select(ThreatIndicator)
        .order_by(ThreatIndicator.last_seen.desc())
        .offset(offset)
        .limit(page_size)
    )
    indicators = result.scalars().all()

    items = [
        ThreatFeedItem(
            indicator_type=ind.indicator_type,
            value=ind.value,
            risk_score=ind.risk_score,
            threat_type=ind.threat_type,
            source=ind.source,
            tags=json.loads(ind.tags) if ind.tags else [],
            first_seen=ind.first_seen,
            last_seen=ind.last_seen,
        )
        for ind in indicators
    ]

    response = ThreatFeedResponse(
        indicators=items, total=total, page=page, page_size=page_size
    )
    try:
        await cache_set(cache_key, response.model_dump(), ttl=300)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response
