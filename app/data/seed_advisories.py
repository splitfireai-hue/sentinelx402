"""Seed India advisories table from scraped data."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from sqlalchemy import select

from app.database import async_session, engine
from app.models import Base
from app.models.advisory import IndiaAdvisory


async def seed() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Read scraped data — check multiple locations
    candidates = [
        Path(__file__).parent / "india_advisories.json",  # app/data (public, may be stub)
        Path(__file__).parent.parent.parent / ".production" / "india_advisories.json",  # private
        Path(__file__).parent.parent.parent / "agents" / "india_advisories.json",  # scraper output
    ]
    data_file = None
    for candidate in candidates:
        if candidate.exists():
            data_file = candidate
            break
    if not data_file:
        print("No scraped data yet. Run: python -m agents.certin_scraper")
        return

    with open(data_file) as f:
        data = json.load(f)

    added = 0
    async with async_session() as session:
        # CERT-In advisories (enriched)
        for adv in data.get("cert_in_advisories", []):
            exists = await session.execute(
                select(IndiaAdvisory).where(IndiaAdvisory.code == adv["code"])
            )
            if exists.scalar_one_or_none():
                continue

            record = IndiaAdvisory(
                source=adv["source"],
                code=adv["code"],
                title=adv.get("title", "")[:500],
                url=adv.get("url", ""),
                published_date=adv.get("published_date"),
                severity=adv.get("severity"),
                description=adv.get("description", "")[:5000],
                cve_refs=json.dumps(adv.get("cve_refs", [])),
                extracted_domains=json.dumps(adv.get("extracted_domains", [])),
                extracted_ips=json.dumps(adv.get("extracted_ips", [])),
            )
            session.add(record)
            added += 1

        # CERT-In list-only advisories
        for adv in data.get("cert_in_list_only", []):
            exists = await session.execute(
                select(IndiaAdvisory).where(IndiaAdvisory.code == adv["code"])
            )
            if exists.scalar_one_or_none():
                continue
            record = IndiaAdvisory(
                source=adv["source"],
                code=adv["code"],
                title=adv.get("title", "")[:500],
                url=adv.get("url", ""),
                published_date=adv.get("published_date"),
                cve_refs="[]",
                extracted_domains="[]",
                extracted_ips="[]",
            )
            session.add(record)
            added += 1

        # CSK alerts
        for i, alert in enumerate(data.get("csk_alerts", [])):
            code = "CSK-{}".format(alert["name"][:40].replace(" ", "-"))[:50]
            exists = await session.execute(
                select(IndiaAdvisory).where(IndiaAdvisory.code == code)
            )
            if exists.scalar_one_or_none():
                continue
            record = IndiaAdvisory(
                source="csk",
                code=code,
                title=alert["name"][:500],
                url=alert.get("url", ""),
                cve_refs="[]",
                extracted_domains="[]",
                extracted_ips="[]",
            )
            session.add(record)
            added += 1

        await session.commit()
        print("Seeded {} new India advisories.".format(added))


if __name__ == "__main__":
    asyncio.run(seed())
