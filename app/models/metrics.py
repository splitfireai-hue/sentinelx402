from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class RequestMetric(Base):
    __tablename__ = "request_metrics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(256), index=True)
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    duration_ms: Mapped[float] = mapped_column(Float)
    client_id: Mapped[str] = mapped_column(String(256), default="")


class HourlyStats(Base):
    __tablename__ = "hourly_stats"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    hour_key: Mapped[str] = mapped_column(String(20), unique=True, index=True)  # "2026-04-03 14"
    request_count: Mapped[int] = mapped_column(Integer, default=0)
