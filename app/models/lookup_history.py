from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class LookupHistory(Base):
    """Every indicator lookup is recorded — builds server-only historical data.

    This is a moat: over time, you have month/year-long history of which
    indicators clients are checking. Useful for:
    - "This domain has been checked 847 times in the past 30 days"
    - Trending threats
    - Premium 'historical intelligence' tier
    """
    __tablename__ = "lookup_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator_type: Mapped[str] = mapped_column(String(20), index=True)  # domain, ip, cve
    indicator_value: Mapped[str] = mapped_column(String(512), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    threat_type: Mapped[str] = mapped_column(String(100), default="")
    looked_up_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    client_id: Mapped[str] = mapped_column(String(256), default="")

    __table_args__ = (
        Index("ix_indicator_lookup", "indicator_type", "indicator_value"),
    )


class Webhook(Base):
    """Client-registered webhook subscriptions — premium dependency.

    Clients subscribe to notifications about specific indicators.
    Requires them to stay connected to YOUR infrastructure.
    """
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    api_key: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(String(500))
    event_type: Mapped[str] = mapped_column(String(50), default="new_threat")
    filter_tag: Mapped[str] = mapped_column(String(100), default="")  # e.g. "india,banking"
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_triggered: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(default=True)


class APIKey(Base):
    """Optional API keys — free tier stays open, but keyed clients get benefits.

    Benefits:
    - Higher rate limits
    - Historical data access
    - Webhook subscriptions
    - Priority support
    """
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    tier: Mapped[str] = mapped_column(String(20), default="free")  # free, pro, enterprise
    email: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(default=True)
    monthly_quota: Mapped[int] = mapped_column(default=10000)
