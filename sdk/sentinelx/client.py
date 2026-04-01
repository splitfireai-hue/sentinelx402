"""SentinelX API client — sync and async."""

from __future__ import annotations

from typing import Optional

import httpx

from sentinelx.models import (
    CVERisk,
    CVESearch,
    DomainRisk,
    IPReputation,
    RecentCVEs,
    ThreatFeed,
    Usage,
)


class SentinelXError(Exception):
    """Raised when the API returns an error response."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__("SentinelX API error {}: {}".format(status_code, detail))


class FreeTierExhausted(SentinelXError):
    """Raised when free tier requests are exhausted."""
    pass


def _handle_response(resp: httpx.Response) -> dict:
    if resp.status_code == 402:
        data = resp.json()
        raise FreeTierExhausted(402, data.get("detail", "Payment required"))
    if resp.status_code >= 400:
        try:
            data = resp.json()
            detail = data.get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise SentinelXError(resp.status_code, detail)
    return resp.json()


class SentinelX:
    """Synchronous client for SentinelX402 APIs.

    Usage:
        from sentinelx import SentinelX

        client = SentinelX()
        risk = client.domain_lookup("suspicious-site.com")
        print(risk.risk_score, risk.threat_type)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30.0,
        wallet_address: Optional[str] = None,
    ):
        headers = {}
        if wallet_address:
            headers["x-wallet-address"] = wallet_address
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            headers=headers,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # --- Threat Intelligence ---

    def domain_lookup(self, domain: str) -> DomainRisk:
        """Look up threat risk score for a domain."""
        resp = self._client.get("/api/v1/threats/lookup", params={"domain": domain})
        return DomainRisk.from_dict(_handle_response(resp))

    def ip_lookup(self, ip: str) -> IPReputation:
        """Check IP address reputation."""
        resp = self._client.get("/api/v1/threats/ip", params={"ip": ip})
        return IPReputation.from_dict(_handle_response(resp))

    def threat_feed(self, page: int = 1, page_size: int = 50) -> ThreatFeed:
        """Get latest threat indicators feed."""
        resp = self._client.get(
            "/api/v1/threats/feed",
            params={"page": page, "page_size": page_size},
        )
        return ThreatFeed.from_dict(_handle_response(resp))

    # --- CVE Intelligence ---

    def cve_lookup(self, cve_id: str) -> CVERisk:
        """Get detailed CVE risk analysis."""
        resp = self._client.get("/api/v1/cves/{}".format(cve_id))
        return CVERisk.from_dict(_handle_response(resp))

    def recent_cves(self, limit: int = 20) -> RecentCVEs:
        """Get recent critical CVEs."""
        resp = self._client.get("/api/v1/cves/recent", params={"limit": limit})
        return RecentCVEs.from_dict(_handle_response(resp))

    def search_cves(self, keyword: str, limit: int = 20) -> CVESearch:
        """Search CVEs by keyword."""
        resp = self._client.get(
            "/api/v1/cves/search",
            params={"keyword": keyword, "limit": limit},
        )
        return CVESearch.from_dict(_handle_response(resp))

    # --- Usage ---

    def usage(self) -> Usage:
        """Check free tier usage."""
        resp = self._client.get("/usage")
        return Usage.from_dict(_handle_response(resp))


class AsyncSentinelX:
    """Async client for SentinelX402 APIs.

    Usage:
        from sentinelx import AsyncSentinelX

        async with AsyncSentinelX() as client:
            risk = await client.domain_lookup("suspicious-site.com")
            print(risk.risk_score, risk.threat_type)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30.0,
        wallet_address: Optional[str] = None,
    ):
        headers = {}
        if wallet_address:
            headers["x-wallet-address"] = wallet_address
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            headers=headers,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # --- Threat Intelligence ---

    async def domain_lookup(self, domain: str) -> DomainRisk:
        """Look up threat risk score for a domain."""
        resp = await self._client.get("/api/v1/threats/lookup", params={"domain": domain})
        return DomainRisk.from_dict(_handle_response(resp))

    async def ip_lookup(self, ip: str) -> IPReputation:
        """Check IP address reputation."""
        resp = await self._client.get("/api/v1/threats/ip", params={"ip": ip})
        return IPReputation.from_dict(_handle_response(resp))

    async def threat_feed(self, page: int = 1, page_size: int = 50) -> ThreatFeed:
        """Get latest threat indicators feed."""
        resp = await self._client.get(
            "/api/v1/threats/feed",
            params={"page": page, "page_size": page_size},
        )
        return ThreatFeed.from_dict(_handle_response(resp))

    # --- CVE Intelligence ---

    async def cve_lookup(self, cve_id: str) -> CVERisk:
        """Get detailed CVE risk analysis."""
        resp = await self._client.get("/api/v1/cves/{}".format(cve_id))
        return CVERisk.from_dict(_handle_response(resp))

    async def recent_cves(self, limit: int = 20) -> RecentCVEs:
        """Get recent critical CVEs."""
        resp = await self._client.get("/api/v1/cves/recent", params={"limit": limit})
        return RecentCVEs.from_dict(_handle_response(resp))

    async def search_cves(self, keyword: str, limit: int = 20) -> CVESearch:
        """Search CVEs by keyword."""
        resp = await self._client.get(
            "/api/v1/cves/search",
            params={"keyword": keyword, "limit": limit},
        )
        return CVESearch.from_dict(_handle_response(resp))

    # --- Usage ---

    async def usage(self) -> Usage:
        """Check free tier usage."""
        resp = await self._client.get("/usage")
        return Usage.from_dict(_handle_response(resp))
