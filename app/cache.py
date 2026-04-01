"""Caching layer — uses Redis if available, falls back to in-memory dict."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional, Tuple

from app.config import settings

# In-memory fallback cache: key -> (value_json, expire_timestamp)
_mem_cache: Dict[str, Tuple[str, float]] = {}

# Redis client (None if not using Redis)
_redis_client = None


async def init_redis() -> None:
    global _redis_client
    if settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await _redis_client.ping()
        except Exception:
            _redis_client = None


async def close_redis() -> None:
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None


async def cache_get(key: str) -> Optional[Any]:
    if _redis_client:
        data = await _redis_client.get(key)
        if data is not None:
            return json.loads(data)
        return None

    # In-memory fallback
    entry = _mem_cache.get(key)
    if entry is None:
        return None
    value_json, expires = entry
    if time.time() > expires:
        del _mem_cache[key]
        return None
    return json.loads(value_json)


async def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    serialized = json.dumps(value, default=str)
    if _redis_client:
        await _redis_client.setex(key, ttl, serialized)
    else:
        _mem_cache[key] = (serialized, time.time() + ttl)
