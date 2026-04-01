from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator_type: Mapped[str] = mapped_column(String(50), index=True)
    value: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    threat_type: Mapped[str] = mapped_column(String(100))
    source: Mapped[str] = mapped_column(String(100), default="sentinelx402")
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_threat_type_score", "threat_type", "risk_score"),
    )
