"""Seed the threat_indicators table with mock IOC data."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.database import async_session, engine
from app.models import Base
from app.models.threat import ThreatIndicator


def _parse_dt(s: str) -> datetime:
    """Parse ISO datetime string to naive UTC datetime (works with both SQLite and PostgreSQL)."""
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    # Convert to naive UTC (strip timezone info)
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt


async def seed() -> None:
    # Create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Load all threat data files
    indicators = []
    for filename in ["threat_indicators.json", "india_threats.json"]:
        data_path = Path(__file__).parent / filename
        if data_path.exists():
            with open(data_path) as f:
                indicators.extend(json.load(f))

    added = 0
    async with async_session() as session:
        for item in indicators:
            try:
                exists = await session.execute(
                    select(ThreatIndicator).where(ThreatIndicator.value == item["value"])
                )
                if exists.scalar_one_or_none():
                    continue

                record = ThreatIndicator(
                    indicator_type=item["indicator_type"],
                    value=item["value"],
                    risk_score=item["risk_score"],
                    threat_type=item["threat_type"],
                    source=item.get("source", "sentinelx402"),
                    tags=json.dumps(item.get("tags", [])),
                    first_seen=_parse_dt(item["first_seen"]),
                    last_seen=_parse_dt(item["last_seen"]),
                )
                session.add(record)
                added += 1
            except Exception as e:
                print("Warning: skipped {} — {}".format(item.get("value", "?"), e))
                continue

        await session.commit()
        print("Seeded {} new threat indicators ({} total in dataset).".format(added, len(indicators)))


if __name__ == "__main__":
    asyncio.run(seed())
