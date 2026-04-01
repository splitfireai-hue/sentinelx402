from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.free_tier import get_client_id_from_request, get_usage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Health"])


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    """Deep health check — verifies database connectivity."""
    checks = {"database": "ok"}
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("Health check failed: database unreachable: %s", e)
        checks["database"] = "error"
        return {"status": "degraded", "checks": checks}
    return {"status": "ok", "checks": checks}


@router.get("/info")
async def info():
    """API information and pricing for agent discovery."""
    return {
        "name": settings.API_TITLE,
        "version": settings.API_VERSION,
        "description": "Cyber threat intelligence APIs for AI agents, paid via x402 micropayments",
        "free_tier": {
            "enabled": settings.FREE_TIER_ENABLED,
            "requests": settings.FREE_TIER_REQUESTS,
        },
        "payment": {
            "protocol": "x402",
            "currency": "USDC",
            "network": "Base",
        },
        "endpoints": [
            {"path": "/api/v1/threats/lookup", "method": "GET", "price": "$0.10", "description": "Domain threat risk lookup"},
            {"path": "/api/v1/threats/ip", "method": "GET", "price": "$0.10", "description": "IP reputation check"},
            {"path": "/api/v1/threats/feed", "method": "GET", "price": "$0.10", "description": "Latest threat indicators feed"},
            {"path": "/api/v1/cves/{cve_id}", "method": "GET", "price": "$0.25", "description": "CVE risk analysis"},
            {"path": "/api/v1/cves/recent", "method": "GET", "price": "$0.10", "description": "Recent critical CVEs"},
            {"path": "/api/v1/cves/search", "method": "GET", "price": "$0.10", "description": "Search CVEs by keyword"},
        ],
    }


@router.get("/usage")
async def usage(request: Request, db: AsyncSession = Depends(get_db)):
    """Check your free tier usage."""
    client_id = get_client_id_from_request(request)
    return await get_usage(client_id, db)
