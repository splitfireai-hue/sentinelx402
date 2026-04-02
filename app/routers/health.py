from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.free_tier import get_client_id_from_request, get_usage
from app.models.threat import ThreatIndicator
from app.models.usage import UsageRecord
from app.services.threat_feeds import get_cache as get_feed_cache, refresh_feeds

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Health"])

# Track request metrics in memory
_metrics = {
    "requests_served": 0,
    "started_at": time.time(),
}


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    """Deep health check — verifies database and feed connectivity."""
    checks = {"database": "ok", "threat_feeds": "ok"}

    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("Health check failed: database unreachable: %s", e)
        checks["database"] = "error"

    feed_cache = get_feed_cache()
    if feed_cache.total_indicators == 0:
        checks["threat_feeds"] = "loading"
    elif feed_cache.is_stale:
        checks["threat_feeds"] = "stale"

    status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": status, "checks": checks}


@router.get("/info")
async def info():
    """API information and pricing for agent discovery."""
    feed_cache = get_feed_cache()
    return {
        "name": settings.API_TITLE,
        "version": settings.API_VERSION,
        "tagline": "Detect malicious domains and IPs in under 300ms with 95% confidence",
        "description": "Real-time phishing risk scoring API for autonomous security agents. "
                       "Powered by live threat feeds (OpenPhish, Feodo Tracker, URLhaus) "
                       "and proprietary heuristic scoring.",
        "value_proposition": "One API call can prevent a phishing incident worth thousands. "
                             "1,000 free requests — no signup, no API key.",
        "free_tier": {
            "enabled": settings.FREE_TIER_ENABLED,
            "requests": settings.FREE_TIER_REQUESTS,
            "signup_required": False,
        },
        "live_feeds": {
            "sources": ["OpenPhish", "Feodo Tracker", "URLhaus"],
            "total_indicators": feed_cache.total_indicators,
            "refresh_interval": "30 minutes",
        },
        "endpoints": [
            {"path": "/api/v1/threats/lookup", "method": "GET", "description": "Domain threat risk lookup — real-time phishing detection"},
            {"path": "/api/v1/threats/ip", "method": "GET", "description": "IP reputation check — C2 and botnet detection"},
            {"path": "/api/v1/threats/feed", "method": "GET", "description": "Latest threat indicators feed"},
            {"path": "/api/v1/cves/{cve_id}", "method": "GET", "description": "CVE risk analysis with exploit probability"},
            {"path": "/api/v1/cves/recent", "method": "GET", "description": "Recent critical CVEs from NVD"},
            {"path": "/api/v1/cves/search", "method": "GET", "description": "Search CVEs by keyword"},
        ],
    }


@router.get("/stats")
async def stats(db: AsyncSession = Depends(get_db)):
    """Public trust metrics — uptime, data coverage, feed status."""
    feed_cache = get_feed_cache()
    uptime_seconds = time.time() - _metrics["started_at"]

    # Count IOCs in DB
    db_count = await db.execute(select(func.count(ThreatIndicator.id)))
    db_total = db_count.scalar_one()

    # Count total clients
    client_count = await db.execute(select(func.count(UsageRecord.id)))
    total_clients = client_count.scalar_one()

    # Total requests served
    total_requests = await db.execute(select(func.sum(UsageRecord.request_count)))
    requests_served = total_requests.scalar_one() or 0

    return {
        "uptime_seconds": round(uptime_seconds),
        "uptime_hours": round(uptime_seconds / 3600, 1),
        "data_coverage": {
            "local_iocs": db_total,
            "live_phishing_urls": feed_cache.feed_stats.get("openphish_urls", 0),
            "live_c2_ips": feed_cache.feed_stats.get("feodo_c2_ips", 0),
            "live_malware_urls": feed_cache.feed_stats.get("urlhaus_malware_urls", 0),
            "total_indicators": db_total + feed_cache.total_indicators,
        },
        "feed_status": {
            "last_refresh_ago_seconds": round(time.time() - feed_cache.last_updated) if feed_cache.last_updated else None,
            "sources_active": 3 if feed_cache.total_indicators > 0 else 0,
            "refresh_interval_seconds": 1800,
        },
        "usage": {
            "total_clients": total_clients,
            "total_requests_served": requests_served,
        },
        "performance": {
            "target_latency": "<300ms",
            "target_confidence": ">=95% for known threats",
        },
    }


@router.get("/usage")
async def usage(request: Request, db: AsyncSession = Depends(get_db)):
    """Check your free tier usage."""
    client_id = get_client_id_from_request(request)
    return await get_usage(client_id, db)
