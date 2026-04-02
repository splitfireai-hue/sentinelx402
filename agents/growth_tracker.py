"""
Growth Tracker Agent — Tracks business metrics daily.

Monitors:
- New clients (first-time users)
- Total requests served
- Most-used endpoints
- Feed health
- Error rates

Run:
    python -m agents.growth_tracker

Outputs a daily summary. Flags important events like new clients.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GrowthAgent] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

API_URL = "https://sentinelx402-production.up.railway.app"
STATE_FILE = Path(__file__).parent / "growth_state.json"


def _load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"last_clients": 0, "last_requests": 0, "last_check": None}


def _save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))


async def main():
    state = _load_state()
    logger.info("Growth Tracker — daily check")

    async with httpx.AsyncClient(timeout=15) as client:
        # Get stats
        resp = await client.get("{}/stats".format(API_URL))
        stats = resp.json()

    coverage = stats.get("data_coverage", {})
    usage = stats.get("usage", {})
    feed = stats.get("feed_status", {})

    current_clients = usage.get("total_clients", 0)
    current_requests = usage.get("total_requests_served", 0)
    prev_clients = state.get("last_clients", 0)
    prev_requests = state.get("last_requests", 0)

    new_clients = current_clients - prev_clients
    new_requests = current_requests - prev_requests

    print("\n" + "=" * 50)
    print("DAILY GROWTH REPORT — {}".format(datetime.utcnow().strftime("%Y-%m-%d")))
    print("=" * 50)

    print("\nClients:    {} total ({} new since last check)".format(current_clients, new_clients))
    print("Requests:   {} total ({} new since last check)".format(current_requests, new_requests))
    print("Indicators: {} live".format(coverage.get("total_indicators", 0)))
    print("Feeds:      {} sources active".format(feed.get("sources_active", 0)))
    print("Uptime:     {}h".format(stats.get("uptime_hours", 0)))

    # Alerts
    alerts = []
    if new_clients > 0:
        alerts.append("NEW CLIENTS: {} new clients detected!".format(new_clients))
    if feed.get("last_refresh_ago_seconds", 0) > 7200:
        alerts.append("WARNING: Feeds stale ({}s ago)".format(feed.get("last_refresh_ago_seconds")))
    if coverage.get("total_indicators", 0) < 100:
        alerts.append("WARNING: Low indicator count")

    if alerts:
        print("\nALERTS:")
        for a in alerts:
            print("  >>> {}".format(a))
    else:
        print("\nNo alerts. System healthy.")

    print("=" * 50)

    # Save state
    state["last_clients"] = current_clients
    state["last_requests"] = current_requests
    state["last_check"] = datetime.utcnow().isoformat()
    _save_state(state)
    logger.info("State saved")


if __name__ == "__main__":
    asyncio.run(main())
