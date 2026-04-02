"""
Health Monitor Agent — SRE replacement.

Checks the live API every 5 minutes. If anything is wrong, prints
an alert with details. Can be extended to send notifications via
webhook, email, or Slack.

Run manually:
    python -m agents.health_monitor

Run continuously:
    python -m agents.health_monitor --loop

Run on schedule:
    Add to cron: */5 * * * * python -m agents.health_monitor
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from datetime import datetime

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HealthAgent] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

API_URL = "https://sentinelx402-production.up.railway.app"

CHECKS = [
    {"name": "health", "path": "/health", "expect_status": 200},
    {"name": "info", "path": "/info", "expect_status": 200},
    {"name": "domain_lookup", "path": "/api/v1/threats/lookup?domain=test.com", "expect_status": 200},
    {"name": "stats", "path": "/stats", "expect_status": 200},
]


async def run_checks() -> dict:
    """Run all health checks and return results."""
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "healthy",
        "checks": {},
        "alerts": [],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        for check in CHECKS:
            name = check["name"]
            url = "{}{}".format(API_URL, check["path"])
            start = time.time()

            try:
                resp = await client.get(url)
                duration_ms = (time.time() - start) * 1000

                if resp.status_code != check["expect_status"]:
                    results["checks"][name] = {
                        "status": "FAIL",
                        "http_code": resp.status_code,
                        "expected": check["expect_status"],
                        "latency_ms": round(duration_ms, 1),
                    }
                    results["alerts"].append(
                        "ALERT: {} returned {} (expected {})".format(
                            name, resp.status_code, check["expect_status"]
                        )
                    )
                elif duration_ms > 5000:
                    results["checks"][name] = {
                        "status": "SLOW",
                        "latency_ms": round(duration_ms, 1),
                    }
                    results["alerts"].append(
                        "ALERT: {} is slow ({:.0f}ms)".format(name, duration_ms)
                    )
                else:
                    results["checks"][name] = {
                        "status": "OK",
                        "latency_ms": round(duration_ms, 1),
                    }

            except httpx.TimeoutException:
                results["checks"][name] = {"status": "TIMEOUT"}
                results["alerts"].append("CRITICAL: {} timed out".format(name))

            except Exception as e:
                results["checks"][name] = {"status": "ERROR", "error": str(e)}
                results["alerts"].append("CRITICAL: {} — {}".format(name, e))

    # Check feed freshness from stats
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            stats_resp = await client.get("{}/stats".format(API_URL))
            if stats_resp.status_code == 200:
                stats = stats_resp.json()
                feed_age = stats.get("feed_status", {}).get("last_refresh_ago_seconds")
                if feed_age and feed_age > 7200:  # 2 hours
                    results["alerts"].append(
                        "WARNING: Threat feeds are stale ({}s since last refresh)".format(feed_age)
                    )
                indicators = stats.get("data_coverage", {}).get("total_indicators", 0)
                if indicators < 100:
                    results["alerts"].append(
                        "WARNING: Low indicator count ({})".format(indicators)
                    )
    except Exception:
        pass

    if results["alerts"]:
        results["status"] = "unhealthy"

    return results


async def main():
    results = await run_checks()

    if results["status"] == "healthy":
        latencies = [c["latency_ms"] for c in results["checks"].values() if "latency_ms" in c]
        avg_ms = sum(latencies) / len(latencies) if latencies else 0
        logger.info("All checks passed (avg latency: %.0fms)", avg_ms)
    else:
        logger.error("ISSUES DETECTED:")
        for alert in results["alerts"]:
            logger.error("  %s", alert)
        # Print full results for debugging
        print(json.dumps(results, indent=2))

    return results


async def loop():
    """Run checks every 5 minutes continuously."""
    logger.info("Health Monitor running in loop mode (every 5 minutes)")
    while True:
        await main()
        await asyncio.sleep(300)


if __name__ == "__main__":
    if "--loop" in sys.argv:
        asyncio.run(loop())
    else:
        asyncio.run(main())
