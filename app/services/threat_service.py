"""Threat intelligence service with flywheel features.

Each lookup:
1. Returns threat data
2. Is recorded in lookup_history (server-only moat)
3. Returns suggested follow-up lookups (drives more requests)
4. Returns related CERT-In advisories (proprietary data)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta
from typing import List

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_get, cache_set
from app.models.advisory import IndiaAdvisory
from app.models.lookup_history import LookupHistory
from app.models.threat import ThreatIndicator
from app.schemas.threat import (
    DomainRiskResponse,
    IPReputationResponse,
    SuggestedLookup,
    ThreatFeedItem,
    ThreatFeedResponse,
)
from app.services.scoring import compute_domain_risk
from app.services import threat_feeds

logger = logging.getLogger(__name__)


async def _record_lookup(
    db: AsyncSession,
    indicator_type: str,
    value: str,
    risk_score: float,
    threat_type: str,
    client_id: str = "",
) -> int:
    """Record lookup in history and return how many times this was looked up before."""
    try:
        # Count previous lookups
        count_result = await db.execute(
            select(func.count(LookupHistory.id))
            .where(
                and_(
                    LookupHistory.indicator_type == indicator_type,
                    LookupHistory.indicator_value == value,
                )
            )
        )
        prev_count = count_result.scalar_one() or 0

        # Record this lookup
        db.add(LookupHistory(
            indicator_type=indicator_type,
            indicator_value=value,
            risk_score=risk_score,
            threat_type=threat_type,
            client_id=client_id,
        ))
        await db.commit()
        return prev_count
    except Exception as e:
        logger.warning("Failed to record lookup: %s", e)
        return 0


async def _find_related_advisories(db: AsyncSession, domain_or_ip: str) -> List[str]:
    """Find CERT-In advisories mentioning this domain/IP (proprietary data)."""
    try:
        result = await db.execute(
            select(IndiaAdvisory.code)
            .where(
                or_(
                    IndiaAdvisory.extracted_domains.contains(domain_or_ip),
                    IndiaAdvisory.extracted_ips.contains(domain_or_ip),
                )
            )
            .limit(5)
        )
        return [r[0] for r in result.all()]
    except Exception:
        return []


def _build_suggested_lookups(
    indicator_type: str,
    value: str,
    threat_type: str,
    related_items: List[str],
    tags: List[str],
) -> List[SuggestedLookup]:
    """Generate suggested follow-up queries to drive more API calls."""
    suggestions = []

    # Suggest looking up related threats
    for item in related_items[:3]:
        suggestions.append(SuggestedLookup(
            type=indicator_type,
            value=item,
            reason="Similar {} in same threat campaign".format(indicator_type),
        ))

    # Suggest feed for this threat type
    if threat_type and threat_type != "benign":
        suggestions.append(SuggestedLookup(
            type="feed",
            value="/api/v1/threats/feed?page=1",
            reason="See all active {} threats".format(threat_type),
        ))

    # India-specific suggestions
    if "india" in tags or any(t in tags for t in ["banking", "upi", "aadhaar"]):
        suggestions.append(SuggestedLookup(
            type="india_advisories",
            value="/api/v1/india/advisories/list",
            reason="Check CERT-In for related India-specific threats",
        ))

    # If domain, suggest IP lookup of resolving address
    if indicator_type == "domain":
        suggestions.append(SuggestedLookup(
            type="cve",
            value="/api/v1/cves/recent",
            reason="Recent CVEs that may be exploited by this threat actor",
        ))

    return suggestions[:5]


async def lookup_domain(domain: str, db: AsyncSession, client_id: str = "") -> DomainRiskResponse:
    cache_key = "threat:domain:{}".format(domain)
    try:
        cached = await cache_get(cache_key)
        if cached:
            response = DomainRiskResponse(**cached)
            # Still record lookup even if cached (for historical tracking)
            await _record_lookup(db, "domain", domain, response.risk_score, response.threat_type, client_id)
            return response
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    start = time.time()

    # 1. Check live threat feeds first
    feed_hit = threat_feeds.check_domain(domain)
    if feed_hit:
        related_result = await db.execute(
            select(ThreatIndicator.value)
            .where(
                ThreatIndicator.indicator_type == "domain",
                ThreatIndicator.threat_type == feed_hit["threat_type"],
                ThreatIndicator.value != domain,
            )
            .order_by(ThreatIndicator.risk_score.desc())
            .limit(5)
        )
        related = [r[0] for r in related_result.all()]
        related_advisories = await _find_related_advisories(db, domain)
        tags = ["live-feed", feed_hit["source"]]

        response = DomainRiskResponse(
            domain=domain,
            risk_score=95.0,
            threat_type=feed_hit["threat_type"],
            confidence=feed_hit["confidence"],
            related_domains=related,
            tags=tags,
            related_advisories=related_advisories,
            suggested_lookups=_build_suggested_lookups("domain", domain, feed_hit["threat_type"], related, tags),
        )
    else:
        # 2. Check local database
        result = await db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.value == domain,
                ThreatIndicator.indicator_type == "domain",
            )
        )
        indicator = result.scalar_one_or_none()

        if indicator:
            tags = json.loads(indicator.tags) if indicator.tags else []
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
            related_advisories = await _find_related_advisories(db, domain)

            response = DomainRiskResponse(
                domain=domain,
                risk_score=indicator.risk_score,
                threat_type=indicator.threat_type,
                confidence=0.95,
                first_seen=indicator.first_seen,
                last_seen=indicator.last_seen,
                related_domains=related,
                tags=tags,
                related_advisories=related_advisories,
                suggested_lookups=_build_suggested_lookups("domain", domain, indicator.threat_type, related, tags),
            )
        else:
            # 3. Heuristic scoring fallback
            risk = compute_domain_risk(domain)
            response = DomainRiskResponse(
                domain=domain,
                risk_score=risk.score,
                threat_type=risk.threat_type,
                confidence=risk.confidence,
                related_domains=[],
                tags=["heuristic"],
                suggested_lookups=_build_suggested_lookups("domain", domain, risk.threat_type, [], ["heuristic"]),
            )

    # Record lookup in history
    historical = await _record_lookup(db, "domain", domain, response.risk_score, response.threat_type, client_id)
    response.historical_occurrences = historical

    _log_lookup("domain", domain, response.risk_score, time.time() - start)
    await _cache_safe(cache_key, response, ttl=21600)
    return response


async def check_ip(ip: str, db: AsyncSession, client_id: str = "") -> IPReputationResponse:
    cache_key = "threat:ip:{}".format(ip)
    try:
        cached = await cache_get(cache_key)
        if cached:
            response = IPReputationResponse(**cached)
            await _record_lookup(db, "ip", ip, response.risk_score, ",".join(response.threat_types), client_id)
            return response
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    start = time.time()

    # 1. Check live feeds
    feed_hit = threat_feeds.check_ip(ip)
    if feed_hit:
        related_advisories = await _find_related_advisories(db, ip)
        tags = ["live-feed", feed_hit["source"], "botnet-c2"]
        response = IPReputationResponse(
            ip=ip,
            risk_score=98.0,
            threat_types=[feed_hit["threat_type"]],
            tags=tags,
            related_advisories=related_advisories,
            suggested_lookups=_build_suggested_lookups("ip", ip, feed_hit["threat_type"], [], tags),
        )
    else:
        # 2. Check local database
        result = await db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.value == ip,
                ThreatIndicator.indicator_type == "ip",
            )
        )
        indicator = result.scalar_one_or_none()

        if indicator:
            tags = json.loads(indicator.tags) if indicator.tags else []
            related_advisories = await _find_related_advisories(db, ip)
            response = IPReputationResponse(
                ip=ip,
                risk_score=indicator.risk_score,
                threat_types=[indicator.threat_type],
                tags=tags,
                first_seen=indicator.first_seen,
                last_seen=indicator.last_seen,
                related_advisories=related_advisories,
                suggested_lookups=_build_suggested_lookups("ip", ip, indicator.threat_type, [], tags),
            )
        else:
            response = IPReputationResponse(
                ip=ip,
                risk_score=5.0,
                threat_types=[],
                tags=["unknown"],
                suggested_lookups=[
                    SuggestedLookup(
                        type="feed",
                        value="/api/v1/threats/feed",
                        reason="Browse known malicious IPs",
                    ),
                ],
            )

    historical = await _record_lookup(db, "ip", ip, response.risk_score, ",".join(response.threat_types), client_id)
    response.historical_occurrences = historical

    _log_lookup("ip", ip, response.risk_score, time.time() - start)
    await _cache_safe(cache_key, response, ttl=21600)
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

    # Suggest follow-ups for feed consumers
    suggestions = [
        SuggestedLookup(
            type="india_advisories",
            value="/api/v1/india/advisories/list",
            reason="India-specific threat advisories from CERT-In",
        ),
        SuggestedLookup(
            type="cve",
            value="/api/v1/cves/recent",
            reason="Recent critical CVEs (last 7 days)",
        ),
    ]

    response = ThreatFeedResponse(
        indicators=items, total=total, page=page, page_size=page_size,
        suggested_lookups=suggestions,
    )
    try:
        await cache_set(cache_key, response.model_dump(), ttl=300)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response


def _log_lookup(indicator_type: str, value: str, score: float, duration: float) -> None:
    if score >= 70:
        logger.info(
            "THREAT_DETECTED type=%s score=%.1f duration=%.1fms",
            indicator_type, score, duration * 1000,
        )


async def _cache_safe(key: str, response, ttl: int) -> None:
    try:
        await cache_set(key, response.model_dump(), ttl=ttl)
    except Exception:
        logger.warning("Cache write failed for %s", key)
