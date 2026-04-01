"""Seed the threat_indicators table with mock IOC data."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from app.database import async_session, engine
from app.models import Base
from app.models.threat import ThreatIndicator


async def seed() -> None:
    # Create tables if they don't exist (for SQLite)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    indicators = []
    for filename in ["threat_indicators.json", "india_threats.json"]:
        data_path = Path(__file__).parent / filename
        if data_path.exists():
            with open(data_path) as f:
                indicators.extend(json.load(f))

    added = 0
    async with async_session() as session:
        for item in indicators:
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
                first_seen=datetime.fromisoformat(item["first_seen"].replace("Z", "+00:00")),
                last_seen=datetime.fromisoformat(item["last_seen"].replace("Z", "+00:00")),
            )
            session.add(record)
            added += 1

        await session.commit()
        print("Seeded {} new threat indicators ({} total in dataset).".format(added, len(indicators)))


if __name__ == "__main__":
    asyncio.run(seed())
