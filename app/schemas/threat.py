from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class DomainRiskResponse(BaseModel):
    domain: str
    risk_score: float = Field(ge=0, le=100)
    threat_type: str
    confidence: float = Field(ge=0, le=1)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_domains: List[str] = []
    tags: List[str] = []


class IPReputationResponse(BaseModel):
    ip: str
    risk_score: float = Field(ge=0, le=100)
    threat_types: List[str] = []
    tags: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


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
