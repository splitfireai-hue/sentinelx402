from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class UsageRecord(Base):
    __tablename__ = "usage_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(256), index=True)  # wallet address or IP
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    first_request: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_request: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
