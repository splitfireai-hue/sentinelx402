from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SuggestedLookup(BaseModel):
    """A suggested follow-up query to drive deeper investigation."""
    type: str  # "domain", "ip", "cve"
    value: str
    reason: str  # why this is relevant


class DomainRiskResponse(BaseModel):
    domain: str
    risk_score: float = Field(ge=0, le=100)
    threat_type: str
    confidence: float = Field(ge=0, le=1)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_domains: List[str] = []
    tags: List[str] = []
    # Flywheel fields — each lookup surfaces more investigations
    suggested_lookups: List[SuggestedLookup] = []
    historical_occurrences: int = 0  # how many times this was seen before
    related_advisories: List[str] = []  # CERT-In advisory codes mentioning this


class IPReputationResponse(BaseModel):
    ip: str
    risk_score: float = Field(ge=0, le=100)
    threat_types: List[str] = []
    tags: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    # Flywheel fields
    suggested_lookups: List[SuggestedLookup] = []
    historical_occurrences: int = 0
    related_advisories: List[str] = []


class ThreatFeedItem(BaseModel):
    indicator_type: str
    value: str
    risk_score: float
    threat_type: str
    source: str
    tags: List[str] = []
    first_seen: datetime
    last_seen: datetime


class ThreatFeedResponse(BaseModel):
    indicators: List[ThreatFeedItem]
    total: int
    page: int
    page_size: int
    suggested_lookups: List[SuggestedLookup] = []
