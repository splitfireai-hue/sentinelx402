from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.dependencies import check_free_tier
from app.schemas.cve import CVERiskResponse, CVESearchResponse, RecentCVEsResponse
from app.services import cve_service

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(check_free_tier)])
limiter = Limiter(key_func=get_remote_address)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@router.get("/recent", response_model=RecentCVEsResponse)
@limiter.limit(settings.CVE_RATE_LIMIT)
async def recent_cves(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
):
    """Get recent critical CVEs with risk analysis."""
    return await cve_service.get_recent_cves(limit=limit)


@router.get("/search", response_model=CVESearchResponse)
@limiter.limit(settings.CVE_RATE_LIMIT)
async def search_cves(
    request: Request,
    keyword: str = Query(..., min_length=2, max_length=200, description="Search keyword"),
    limit: int = Query(20, ge=1, le=100),
):
    """Search CVEs by keyword with risk analysis."""
    keyword = keyword.strip()
    return await cve_service.search_cves(keyword, limit=limit)


@router.get("/{cve_id}", response_model=CVERiskResponse)
@limiter.limit(settings.CVE_RATE_LIMIT)
async def get_cve(
    request: Request,
    cve_id: str,
):
    """Get detailed CVE risk analysis."""
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Expected: CVE-YYYY-NNNNN")
    return await cve_service.get_cve(cve_id)
