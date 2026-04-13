from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IndiaAdvisory(Base):
    """India-specific threat advisories from CERT-In and CSK."""
    __tablename__ = "india_advisories"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(20), index=True)  # cert-in, csk
    code: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    url: Mapped[str] = mapped_column(String(500))
    published_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cve_refs: Mapped[str] = mapped_column(Text, default="")  # JSON array
    extracted_domains: Mapped[str] = mapped_column(Text, default="")  # JSON array
    extracted_ips: Mapped[str] = mapped_column(Text, default="")  # JSON array
    scraped_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
