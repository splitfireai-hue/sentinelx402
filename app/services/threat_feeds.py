"""Real threat intelligence feeds — OpenPhish, Feodo Tracker, URLhaus bulk data.

These feeds are free, public, and require no API keys. They are fetched
periodically and cached in memory for fast lookups.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

import httpx

logger = logging.getLogger(__name__)

# Feed URLs (all free, no auth required)
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

FEED_TTL = 1800  # 30 minutes


@dataclass
class ThreatFeedCache:
    """In-memory cache for threat feed data."""
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
        return (
            len(self.phishing_urls)
            + len(self.c2_ips)
            + len(self.malware_urls)
        )


_cache = ThreatFeedCache()
_lock = asyncio.Lock()


def _extract_domain(url: str) -> str:
    """Extract domain from a URL."""
    url = url.strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    return url.split("/")[0].split(":")[0].lower()


async def _fetch_openphish(client: httpx.AsyncClient) -> tuple:
    """Fetch OpenPhish community feed."""
    urls = set()
    domains = set()
    try:
        resp = await client.get(OPENPHISH_URL, timeout=20)
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


async def _fetch_feodo(client: httpx.AsyncClient) -> set:
    """Fetch Feodo Tracker C2 IP blocklist."""
    ips = set()
    try:
        resp = await client.get(FEODO_URL, timeout=20)
        resp.raise_for_status()
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    ipaddress.ip_address(line)
                    ips.add(line)
                except ValueError:
                    pass
        logger.info("Feodo Tracker: loaded %d C2 IPs", len(ips))
    except Exception as e:
        logger.warning("Feodo fetch failed: %s", e)
    return ips


async def _fetch_urlhaus(client: httpx.AsyncClient) -> tuple:
    """Fetch URLhaus recent malware URLs."""
    urls = set()
    domains = set()
    try:
        resp = await client.get(URLHAUS_RECENT_URL, timeout=30)
        resp.raise_for_status()
        for line in resp.text.strip().split("\n"):
            if line.startswith("#") or line.startswith('"id"'):
                continue
            parts = line.split('","')
            if len(parts) >= 3:
                url = parts[2].strip('"')
                if url.startswith("http"):
                    urls.add(url)
                    domains.add(_extract_domain(url))
        logger.info("URLhaus: loaded %d malware URLs", len(urls))
    except Exception as e:
        logger.warning("URLhaus fetch failed: %s", e)
    return urls, domains


async def refresh_feeds() -> ThreatFeedCache:
    """Refresh all threat feeds. Called on startup and periodically."""
    global _cache
    async with _lock:
        if not _cache.is_stale:
            return _cache

        logger.info("Refreshing threat intelligence feeds...")
        async with httpx.AsyncClient() as client:
            openphish_task = _fetch_openphish(client)
            feodo_task = _fetch_feodo(client)
            urlhaus_task = _fetch_urlhaus(client)

            (phish_urls, phish_domains), c2_ips, (mal_urls, mal_domains) = (
                await asyncio.gather(openphish_task, feodo_task, urlhaus_task)
            )

        _cache.phishing_urls = phish_urls
        _cache.phishing_domains = phish_domains
        _cache.c2_ips = c2_ips
        _cache.malware_urls = mal_urls
        _cache.malware_domains = mal_domains
        _cache.last_updated = time.time()
        _cache.feed_stats = {
            "openphish_urls": len(phish_urls),
            "feodo_c2_ips": len(c2_ips),
            "urlhaus_malware_urls": len(mal_urls),
            "total": len(phish_urls) + len(c2_ips) + len(mal_urls),
        }

        logger.info(
            "Threat feeds refreshed: %d phishing, %d C2 IPs, %d malware URLs",
            len(phish_urls), len(c2_ips), len(mal_urls),
        )
        return _cache


def get_cache() -> ThreatFeedCache:
    return _cache


def check_domain(domain: str) -> Optional[Dict]:
    """Check a domain against all live feeds."""
    domain = domain.lower()
    if domain in _cache.phishing_domains:
        return {"source": "openphish", "threat_type": "phishing", "confidence": 0.95}
    if domain in _cache.malware_domains:
        return {"source": "urlhaus", "threat_type": "malware", "confidence": 0.90}
    return None


def check_ip(ip: str) -> Optional[Dict]:
    """Check an IP against live feeds."""
    if ip in _cache.c2_ips:
        return {"source": "feodo_tracker", "threat_type": "c2", "confidence": 0.98}
    return None
