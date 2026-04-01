from typing import List

from pydantic import BaseModel, Field


class CVERiskResponse(BaseModel):
    cve_id: str
    cvss: float = Field(ge=0, le=10)
    exploit_probability: float = Field(ge=0, le=1)
    risk: str
    patch_urgency: str
    ransomware_risk: bool = False
    description: str = ""
    affected_products: List[str] = []


class RecentCVEsResponse(BaseModel):
    cves: List[CVERiskResponse]
    total: int


class CVESearchResponse(BaseModel):
    keyword: str
    results: List[CVERiskResponse]
    total: int
