"""CVE Intelligence service — real NVD data with enhanced risk scoring."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict

import nvdlib
from fastapi import HTTPException

from app.cache import cache_get, cache_set
from app.config import settings
from app.schemas.cve import CVERiskResponse, CVESearchResponse, RecentCVEsResponse
from app.services.scoring import compute_cve_risk

logger = logging.getLogger(__name__)


def _nvd_kwargs() -> Dict[str, str]:
    kwargs = {}
    if settings.NVD_API_KEY:
        kwargs["key"] = settings.NVD_API_KEY
    return kwargs


async def _nvd_search(**kwargs):
    """Run nvdlib.searchCVE in a thread with timeout."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(nvdlib.searchCVE, **kwargs),
            timeout=settings.NVD_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.error("NVD API timeout after %ds", settings.NVD_TIMEOUT_SECONDS)
        raise HTTPException(status_code=504, detail="Upstream NVD API timed out")
    except Exception as e:
        logger.error("NVD API error: %s", e)
        raise HTTPException(status_code=502, detail="Upstream NVD API unavailable")


def _parse_cve(cve) -> CVERiskResponse:
    """Parse an nvdlib CVE object into our response schema."""
    cvss = 0.0
    if hasattr(cve, "score") and cve.score:
        score = cve.score
        if isinstance(score, (list, tuple)) and len(score) >= 2:
            cvss = float(score[1])
        else:
            cvss = float(score)

    cwe_id = ""
    if hasattr(cve, "cwe") and cve.cwe:
        cwe_data = cve.cwe
        if isinstance(cwe_data, list) and cwe_data:
            first = cwe_data[0]
            if isinstance(first, dict):
                cwe_id = first.get("value", "")
            else:
                cwe_id = str(first)
        elif isinstance(cwe_data, str):
            cwe_id = cwe_data

    has_exploit = False
    if hasattr(cve, "references"):
        for ref in cve.references or []:
            if isinstance(ref, dict):
                url = ref.get("url", "")
            elif hasattr(ref, "url"):
                url = ref.url
            else:
                url = str(ref)
            if "exploit" in url.lower() or "poc" in url.lower():
                has_exploit = True
                break

    risk = compute_cve_risk(cvss, has_exploit=has_exploit, cwe_id=cwe_id)

    products = []
    if hasattr(cve, "cpe") and cve.cpe:
        for cp in cve.cpe[:5]:
            if isinstance(cp, dict):
                cpe_name = cp.get("criteria", "")
            elif hasattr(cp, "criteria"):
                cpe_name = cp.criteria
            else:
                cpe_name = str(cp)
            parts = cpe_name.split(":")
            if len(parts) >= 5:
                products.append("{}:{}".format(parts[3], parts[4]))

    description = ""
    if hasattr(cve, "descriptions") and cve.descriptions:
        for desc in cve.descriptions:
            if isinstance(desc, dict):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            elif hasattr(desc, "lang") and desc.lang == "en":
                description = desc.value
                break
        if not description:
            first = cve.descriptions[0]
            if isinstance(first, dict):
                description = first.get("value", "")
            elif hasattr(first, "value"):
                description = first.value

    return CVERiskResponse(
        cve_id=cve.id,
        cvss=cvss,
        exploit_probability=risk.exploit_probability,
        risk=risk.risk_level,
        patch_urgency=risk.patch_urgency,
        ransomware_risk=risk.ransomware_risk,
        description=description,
        affected_products=products,
    )


async def get_cve(cve_id: str) -> CVERiskResponse:
    cache_key = "cve:id:{}".format(cve_id)
    try:
        cached = await cache_get(cache_key)
        if cached:
            return CVERiskResponse(**cached)
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    results = await _nvd_search(cveId=cve_id, **_nvd_kwargs())

    if not results:
        raise HTTPException(status_code=404, detail="CVE {} not found".format(cve_id))

    response = _parse_cve(results[0])
    try:
        await cache_set(cache_key, response.model_dump(), ttl=3600)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response


async def get_recent_cves(limit: int = 20) -> RecentCVEsResponse:
    cache_key = "cve:recent:limit:{}".format(limit)
    try:
        cached = await cache_get(cache_key)
        if cached:
            return RecentCVEsResponse(**cached)
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    end = datetime.utcnow()
    start = end - timedelta(days=7)

    results = await _nvd_search(
        pubStartDate=start,
        pubEndDate=end,
        cvssV3Severity="CRITICAL",
        **_nvd_kwargs(),
    )

    cves = [_parse_cve(cve) for cve in (results or [])[:limit]]

    response = RecentCVEsResponse(cves=cves, total=len(cves))
    try:
        await cache_set(cache_key, response.model_dump(), ttl=900)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response


async def search_cves(keyword: str, limit: int = 20) -> CVESearchResponse:
    cache_key = "cve:search:{}:limit:{}".format(keyword, limit)
    try:
        cached = await cache_get(cache_key)
        if cached:
            return CVESearchResponse(**cached)
    except Exception:
        logger.warning("Cache read failed for %s", cache_key)

    results = await _nvd_search(keywordSearch=keyword, **_nvd_kwargs())

    cves = [_parse_cve(cve) for cve in (results or [])[:limit]]

    response = CVESearchResponse(keyword=keyword, results=cves, total=len(cves))
    try:
        await cache_set(cache_key, response.model_dump(), ttl=900)
    except Exception:
        logger.warning("Cache write failed for %s", cache_key)
    return response
