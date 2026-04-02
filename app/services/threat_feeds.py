"""Threat intelligence feed integration.

NOTE: This is a reference implementation with a single public feed.
The production SentinelX402 service uses multiple proprietary feed
sources, an extended safe-domain whitelist, and custom correlation
logic not included in this repository.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

import httpx

logger = logging.getLogger(__name__)

FEED_TTL = 1800  # 30 minutes


@dataclass
class ThreatFeedCache:
    phishing_urls: Set[str] = field(default_factory=set)
    phishing_domains: Set[str] = field(default_factory=set)
    c2_ips: Set[str] = field(default_factory=set)
    malware_urls: Set[str] = field(default_factory=set)
    malware_domains: Set[str] = field(default_factory=set)
    last_updated: float = 0
    feed_stats: Dict[str, int] = field(default_factory=dict)

    @property
    def is_stale(self) -> bool:
        return (time.time() - self.last_updated) > FEED_TTL

    @property
    def total_indicators(self) -> int:
        return len(self.phishing_urls) + len(self.c2_ips) + len(self.malware_urls)


_cache = ThreatFeedCache()
_lock = asyncio.Lock()


def _extract_domain(url: str) -> str:
    url = url.strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    return url.split("/")[0].split(":")[0].lower()


async def _fetch_openphish(client: httpx.AsyncClient) -> tuple:
    urls = set()
    domains = set()
    try:
        resp = await client.get(
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            timeout=20,
        )
        resp.raise_for_status()
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                urls.add(line)
                domains.add(_extract_domain(line))
        logger.info("OpenPhish: loaded %d phishing URLs", len(urls))
    except Exception as e:
        logger.warning("OpenPhish fetch failed: %s", e)
    return urls, domains


async def refresh_feeds() -> ThreatFeedCache:
    global _cache
    async with _lock:
        if not _cache.is_stale:
            return _cache
        logger.info("Refreshing threat intelligence feeds...")
        async with httpx.AsyncClient() as client:
            phish_urls, phish_domains = await _fetch_openphish(client)
        _cache.phishing_urls = phish_urls
        _cache.phishing_domains = phish_domains
        _cache.last_updated = time.time()
        _cache.feed_stats = {"openphish_urls": len(phish_urls), "total": len(phish_urls)}
        logger.info("Threat feeds refreshed: %d phishing URLs", len(phish_urls))
        return _cache


def get_cache() -> ThreatFeedCache:
    return _cache


def check_domain(domain: str) -> Optional[Dict]:
    domain = domain.lower()
    if domain in _cache.phishing_domains:
        return {"source": "openphish", "threat_type": "phishing", "confidence": 0.95}
    return None


def check_ip(ip: str) -> Optional[Dict]:
    if ip in _cache.c2_ips:
        return {"source": "feodo_tracker", "threat_type": "c2", "confidence": 0.98}
    return None
