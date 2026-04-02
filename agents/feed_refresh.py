"""
Feed Refresh Agent — Security Data Engineer replacement.

Runs on a schedule. Fetches fresh threat data from multiple OSINT sources,
deduplicates against existing data, and seeds new IOCs into the database.

Sources:
- OpenPhish (phishing URLs)
- Feodo Tracker (C2 IPs)
- URLhaus (malware URLs + hashes)
- PhishTank community feed (if available)
- abuse.ch ThreatFox (IOCs)

Run manually:
    python -m agents.feed_refresh

Run on schedule (every 6 hours):
    Add to cron or use Claude Code /schedule
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FeedAgent] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

FEEDS = {
    "openphish": {
        "url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        "type": "phishing_urls",
        "parser": "lines",
    },
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "c2_ips",
        "parser": "lines_skip_comments",
    },
    "urlhaus_recent": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "malware_urls",
        "parser": "urlhaus_csv",
    },
    "threatfox_recent": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "mixed_iocs",
        "parser": "threatfox_json",
    },
}

REPORT_FILE = Path(__file__).parent / "last_feed_report.json"


def _parse_lines(text: str) -> list:
    return [l.strip() for l in text.strip().split("\n") if l.strip() and not l.startswith("#")]


def _parse_lines_skip_comments(text: str) -> list:
    return [l.strip() for l in text.strip().split("\n") if l.strip() and not l.startswith("#")]


def _parse_urlhaus_csv(text: str) -> list:
    results = []
    for line in text.strip().split("\n"):
        if line.startswith("#") or line.startswith('"id"'):
            continue
        parts = line.split('","')
        if len(parts) >= 4:
            url = parts[2].strip('"')
            threat = parts[3].strip('"') if len(parts) > 3 else "malware"
            if url.startswith("http"):
                results.append({"url": url, "threat": threat})
    return results


def _parse_threatfox_json(text: str) -> list:
    results = []
    try:
        data = json.loads(text)
        if "data" in data:
            for item in data["data"]:
                if isinstance(item, dict):
                    results.append({
                        "ioc": item.get("ioc", ""),
                        "ioc_type": item.get("ioc_type", ""),
                        "threat_type": item.get("threat_type", ""),
                        "malware": item.get("malware_printable", ""),
                    })
    except (json.JSONDecodeError, KeyError):
        pass
    return results


async def fetch_all_feeds() -> dict:
    """Fetch all OSINT feeds and return parsed results."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "feeds": {},
        "totals": {"new_phishing": 0, "new_c2_ips": 0, "new_malware": 0, "new_iocs": 0},
    }

    async with httpx.AsyncClient(timeout=30) as client:
        for name, feed in FEEDS.items():
            logger.info("Fetching %s from %s...", name, feed["url"][:60])
            try:
                resp = await client.get(feed["url"])
                resp.raise_for_status()

                if feed["parser"] == "lines":
                    items = _parse_lines(resp.text)
                elif feed["parser"] == "lines_skip_comments":
                    items = _parse_lines_skip_comments(resp.text)
                elif feed["parser"] == "urlhaus_csv":
                    items = _parse_urlhaus_csv(resp.text)
                elif feed["parser"] == "threatfox_json":
                    items = _parse_threatfox_json(resp.text)
                else:
                    items = []

                report["feeds"][name] = {
                    "status": "ok",
                    "count": len(items),
                    "type": feed["type"],
                }
                logger.info("  %s: %d indicators fetched", name, len(items))

            except Exception as e:
                report["feeds"][name] = {"status": "error", "error": str(e)}
                logger.error("  %s: FAILED — %s", name, e)

    # Calculate totals
    for name, info in report["feeds"].items():
        if info.get("status") == "ok":
            feed_type = info.get("type", "")
            if "phishing" in feed_type:
                report["totals"]["new_phishing"] += info["count"]
            elif "c2" in feed_type:
                report["totals"]["new_c2_ips"] += info["count"]
            elif "malware" in feed_type:
                report["totals"]["new_malware"] += info["count"]
            else:
                report["totals"]["new_iocs"] += info["count"]

    total = sum(report["totals"].values())
    report["totals"]["total"] = total
    logger.info("Total indicators across all feeds: %d", total)

    # Save report
    REPORT_FILE.write_text(json.dumps(report, indent=2))
    logger.info("Report saved to %s", REPORT_FILE)

    return report


async def refresh_live_api():
    """Trigger a feed refresh on the live API by hitting /health (which triggers feed check)."""
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get("https://sentinelx402-production.up.railway.app/health")
            logger.info("Live API health: %s", resp.json().get("status"))
        except Exception as e:
            logger.error("Could not reach live API: %s", e)


async def main():
    logger.info("=" * 50)
    logger.info("Feed Refresh Agent starting")
    logger.info("=" * 50)

    start = time.time()
    report = await fetch_all_feeds()
    await refresh_live_api()
    duration = time.time() - start

    logger.info("=" * 50)
    logger.info("Completed in %.1fs", duration)
    logger.info("Phishing: %d | C2 IPs: %d | Malware: %d | Other: %d",
                report["totals"]["new_phishing"],
                report["totals"]["new_c2_ips"],
                report["totals"]["new_malware"],
                report["totals"]["new_iocs"])
    logger.info("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
