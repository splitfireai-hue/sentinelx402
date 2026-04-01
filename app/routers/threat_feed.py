from __future__ import annotations

import ipaddress
import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import check_free_tier
from app.schemas.threat import DomainRiskResponse, IPReputationResponse, ThreatFeedResponse
from app.services import threat_service

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(check_free_tier)])
limiter = Limiter(key_func=get_remote_address)

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return domain


def _validate_ip(ip: str) -> str:
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return ip


@router.get("/lookup", response_model=DomainRiskResponse)
@limiter.limit(settings.THREAT_RATE_LIMIT)
async def domain_lookup(
    request: Request,
    domain: str = Query(..., min_length=3, max_length=253, description="Domain to check for threats"),
    db: AsyncSession = Depends(get_db),
):
    """Look up threat risk score for a domain."""
    domain = _validate_domain(domain)
    return await threat_service.lookup_domain(domain, db)


@router.get("/ip", response_model=IPReputationResponse)
@limiter.limit(settings.THREAT_RATE_LIMIT)
async def ip_reputation(
    request: Request,
    ip: str = Query(..., description="IP address to check"),
    db: AsyncSession = Depends(get_db),
):
    """Check IP address reputation and threat associations."""
    ip = _validate_ip(ip)
    return await threat_service.check_ip(ip, db)


@router.get("/feed", response_model=ThreatFeedResponse)
@limiter.limit(settings.THREAT_RATE_LIMIT)
async def threat_feed(
    request: Request,
    page: int = Query(1, ge=1, le=1000),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Get latest threat indicators feed."""
    return await threat_service.get_threat_feed(db, page=page, page_size=page_size)
