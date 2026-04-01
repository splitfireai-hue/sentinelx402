"""Response models for the SentinelX SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DomainRisk:
    domain: str
    risk_score: float
    threat_type: str
    confidence: float
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    related_domains: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DomainRisk:
        return cls(
            domain=data["domain"],
            risk_score=data["risk_score"],
            threat_type=data["threat_type"],
            confidence=data["confidence"],
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            related_domains=data.get("related_domains", []),
            tags=data.get("tags", []),
        )

    @property
    def is_malicious(self) -> bool:
        return self.risk_score >= 70


@dataclass
class IPReputation:
    ip: str
    risk_score: float
    threat_types: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IPReputation:
        return cls(
            ip=data["ip"],
            risk_score=data["risk_score"],
            threat_types=data.get("threat_types", []),
            tags=data.get("tags", []),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
        )

    @property
    def is_malicious(self) -> bool:
        return self.risk_score >= 70


@dataclass
class ThreatIndicator:
    indicator_type: str
    value: str
    risk_score: float
    threat_type: str
    source: str
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


@dataclass
class ThreatFeed:
    indicators: List[ThreatIndicator]
    total: int
    page: int
    page_size: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ThreatFeed:
        indicators = [
            ThreatIndicator(
                indicator_type=i["indicator_type"],
                value=i["value"],
                risk_score=i["risk_score"],
                threat_type=i["threat_type"],
                source=i["source"],
                tags=i.get("tags", []),
                first_seen=i.get("first_seen"),
                last_seen=i.get("last_seen"),
            )
            for i in data.get("indicators", [])
        ]
        return cls(
            indicators=indicators,
            total=data["total"],
            page=data["page"],
            page_size=data["page_size"],
        )


@dataclass
class CVERisk:
    cve_id: str
    cvss: float
    exploit_probability: float
    risk: str
    patch_urgency: str
    ransomware_risk: bool = False
    description: str = ""
    affected_products: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CVERisk:
        return cls(
            cve_id=data["cve_id"],
            cvss=data["cvss"],
            exploit_probability=data["exploit_probability"],
            risk=data["risk"],
            patch_urgency=data["patch_urgency"],
            ransomware_risk=data.get("ransomware_risk", False),
            description=data.get("description", ""),
            affected_products=data.get("affected_products", []),
        )

    @property
    def is_critical(self) -> bool:
        return self.risk == "critical"


@dataclass
class RecentCVEs:
    cves: List[CVERisk]
    total: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecentCVEs:
        return cls(
            cves=[CVERisk.from_dict(c) for c in data.get("cves", [])],
            total=data["total"],
        )


@dataclass
class CVESearch:
    keyword: str
    results: List[CVERisk]
    total: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CVESearch:
        return cls(
            keyword=data["keyword"],
            results=[CVERisk.from_dict(c) for c in data.get("results", [])],
            total=data["total"],
        )


@dataclass
class Usage:
    client_id: str
    used: int
    limit: int
    remaining: int
    free_tier_active: bool

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Usage:
        return cls(
            client_id=data["client_id"],
            used=data["used"],
            limit=data["limit"],
            remaining=data["remaining"],
            free_tier_active=data["free_tier_active"],
        )
