"""Shared FastAPI dependencies."""

from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.free_tier import get_client_id_from_request, track_usage

logger = logging.getLogger(__name__)


async def check_free_tier(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    """Dependency that tracks free tier usage. Raises 402 when exhausted."""
    if not settings.FREE_TIER_ENABLED:
        return

    client_id = get_client_id_from_request(request)
    try:
        remaining = await track_usage(client_id, db)
    except Exception:
        logger.warning("Free tier tracking failed for %s, allowing request", client_id)
        return

    if remaining is None:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "free_tier_exhausted",
                "detail": "You have used all {} free requests. Enable x402 payments to continue.".format(
                    settings.FREE_TIER_REQUESTS
                ),
                "limit": settings.FREE_TIER_REQUESTS,
            },
        )

    # Store remaining count for response header injection
    request.state.free_tier_remaining = remaining
