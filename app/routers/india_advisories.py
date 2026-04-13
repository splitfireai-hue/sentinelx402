"""India-specific threat advisory endpoints — proprietary data source."""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import check_free_tier
from app.models.advisory import IndiaAdvisory

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(check_free_tier)])
limiter = Limiter(key_func=get_remote_address)


class AdvisoryResponse(BaseModel):
    code: str
    title: str
    source: str
    url: str
    published_date: Optional[str] = None
    severity: Optional[str] = None
    description: str = ""
    cve_refs: List[str] = []
    extracted_domains: List[str] = []


class AdvisoryListResponse(BaseModel):
    advisories: List[AdvisoryResponse]
    total: int
    sources: List[str] = ["cert-in", "csk"]


def _to_response(adv: IndiaAdvisory) -> AdvisoryResponse:
    def _parse(s: str) -> List[str]:
        try:
            return json.loads(s) if s else []
        except Exception:
            return []

    return AdvisoryResponse(
        code=adv.code,
        title=adv.title,
        source=adv.source,
        url=adv.url,
        published_date=adv.published_date,
        severity=adv.severity,
        description=adv.description,
        cve_refs=_parse(adv.cve_refs),
        extracted_domains=_parse(adv.extracted_domains),
    )


@router.get("/list", response_model=AdvisoryListResponse)
@limiter.limit(settings.THREAT_RATE_LIMIT)
async def list_advisories(
    request: Request,
    source: Optional[str] = Query(None, description="Filter by source: cert-in or csk"),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List recent Indian threat advisories from CERT-In and CSK."""
    stmt = select(IndiaAdvisory).order_by(desc(IndiaAdvisory.scraped_at))
    if source:
        stmt = stmt.where(IndiaAdvisory.source == source)
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    advisories = result.scalars().all()

    return AdvisoryListResponse(
        advisories=[_to_response(a) for a in advisories],
        total=len(advisories),
    )


@router.get("/{code}", response_model=AdvisoryResponse)
@limiter.limit(settings.THREAT_RATE_LIMIT)
async def get_advisory(
    request: Request,
    code: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific Indian threat advisory by code (e.g. CIAD-2026-0015)."""
    code = code.strip().upper()
    result = await db.execute(
        select(IndiaAdvisory).where(IndiaAdvisory.code == code)
    )
    adv = result.scalar_one_or_none()
    if not adv:
        raise HTTPException(status_code=404, detail="Advisory {} not found".format(code))
    return _to_response(adv)
