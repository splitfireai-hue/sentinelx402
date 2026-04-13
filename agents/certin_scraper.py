"""
CERT-In India Advisory Scraper — proprietary data source.

Scrapes official CERT-In (Indian Computer Emergency Response Team) advisories
and CSK (Cyber Swachhta Kendra) malware alerts.

This is SentinelX402's proprietary moat — nobody else has Indian government
threat intelligence in their agent-native API.

Sources:
- CERT-In Advisories: https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST
- CERT-In Vulnerability Notes: https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES
- CSK Malware Alerts: https://www.csk.gov.in/alerts.html

Run:
    python -m agents.certin_scraper

Output: agents/india_advisories.json
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CERTinScraper] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

USER_AGENT = "SentinelX402-ThreatIntel/1.0 (security research; contact: github.com/splitfireai-hue/sentinelx402)"

CERTIN_LIST_URL = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year={year}"
CERTIN_DETAIL_URL = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE={code}"
CSK_ALERTS_URL = "https://www.csk.gov.in/alerts.html"

OUTPUT_FILE = Path(__file__).parent / "india_advisories.json"


@dataclass
class Advisory:
    source: str  # "cert-in" or "csk"
    code: str  # e.g. "CIAD-2025-0046"
    title: str
    url: str
    published_date: Optional[str] = None
    severity: Optional[str] = None
    description: str = ""
    affected_software: List[str] = field(default_factory=list)
    cve_refs: List[str] = field(default_factory=list)
    extracted_domains: List[str] = field(default_factory=list)
    extracted_ips: List[str] = field(default_factory=list)
    scraped_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Regex patterns
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CIAD_PATTERN = re.compile(r"CIAD-\d{4}-\d{4}", re.IGNORECASE)
CIVN_PATTERN = re.compile(r"CIVN-\d{4}-\d{4}", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,}\b"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Filter out common non-threat domains
BENIGN_DOMAINS = {
    "cert-in.org.in", "nist.gov", "cve.org", "mitre.org",
    "www.cert-in.org.in", "incibe.es", "microsoft.com",
    "apple.com", "google.com", "adobe.com", "mozilla.org",
    "github.com", "cisco.com", "oracle.com", "redhat.com",
    "ubuntu.com", "debian.org", "linux.org", "vmware.com",
    "ibm.com", "nvd.nist.gov",
}


def _extract_iocs(text: str) -> tuple:
    """Extract CVEs, domains, and IPs from advisory text."""
    cves = list(set(CVE_PATTERN.findall(text)))
    domains = [d.lower() for d in DOMAIN_PATTERN.findall(text)]
    domains = list(set(d for d in domains if d not in BENIGN_DOMAINS and "." in d))
    ips = list(set(IP_PATTERN.findall(text)))
    # Filter private/reserved IPs
    ips = [
        ip for ip in ips
        if not any(ip.startswith(p) for p in ("10.", "192.168.", "127.", "0.", "255."))
        and not (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
    ]
    return cves, domains, ips


async def scrape_certin_list(client: httpx.AsyncClient, limit: int = 30) -> List[Advisory]:
    """Scrape the CERT-In advisory list page (current year)."""
    advisories: List[Advisory] = []
    current_year = datetime.utcnow().year
    try:
        resp = await client.get(
            CERTIN_LIST_URL.format(year=current_year),
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        resp.raise_for_status()
        html = resp.text

        # Find all CIAD/CIVN codes with surrounding context
        # The page lists advisories as links with the code near a date and title
        ciad_matches = CIAD_PATTERN.findall(html)
        civn_matches = CIVN_PATTERN.findall(html)
        codes = list(dict.fromkeys(ciad_matches + civn_matches))[:limit]

        logger.info("Found %d unique advisory codes", len(codes))

        # For each code, try to find a title context
        for code in codes:
            # Locate the code in the HTML and extract the surrounding text block
            idx = html.find(code)
            if idx == -1:
                continue
            # Grab 300 chars around the code for context
            context = html[max(0, idx - 200): idx + 400]
            # Strip HTML tags crudely
            context_text = re.sub(r"<[^>]+>", " ", context)
            context_text = re.sub(r"\s+", " ", context_text).strip()

            # Extract title: text after the code, before next date/code
            title = ""
            after_code = context_text.split(code, 1)[-1].strip()
            # Cut at next code or "Original Issue Date"
            for stop in ["CIAD-", "CIVN-", "Original Issue", "Severity", "CERT-In"]:
                if stop in after_code:
                    after_code = after_code.split(stop)[0]
            title = after_code.strip()[:200]

            # Extract date from context
            date_match = re.search(
                r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}",
                context_text,
            )
            published_date = date_match.group(0) if date_match else None

            advisories.append(Advisory(
                source="cert-in",
                code=code,
                title=title,
                url=CERTIN_DETAIL_URL.format(code=code),
                published_date=published_date,
            ))

        logger.info("Scraped %d advisories from CERT-In list", len(advisories))
    except Exception as e:
        logger.error("Failed to scrape CERT-In list: %s", e)

    return advisories


async def enrich_advisory(client: httpx.AsyncClient, adv: Advisory) -> Advisory:
    """Fetch the detail page for an advisory and extract IOCs."""
    try:
        resp = await client.get(
            adv.url,
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        if resp.status_code != 200:
            return adv

        html = resp.text
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text)

        cves, domains, ips = _extract_iocs(text)
        adv.cve_refs = cves
        adv.extracted_domains = domains[:20]  # cap to avoid noise
        adv.extracted_ips = ips[:20]

        # Extract severity
        sev_match = re.search(r"Severity Rating[:\s]+(High|Medium|Low|Critical)", text, re.IGNORECASE)
        if sev_match:
            adv.severity = sev_match.group(1).capitalize()

        # Extract description (first 500 chars after "Description")
        desc_match = re.search(r"Description[:\s]+(.{50,500}?)(?:Solution|Vendor|Reference)", text, re.IGNORECASE | re.DOTALL)
        if desc_match:
            adv.description = desc_match.group(1).strip()[:500]

        # Extract affected software
        affected_match = re.search(r"Software Affected[:\s]+(.{20,500}?)(?:Overview|Description|Impact)", text, re.IGNORECASE | re.DOTALL)
        if affected_match:
            affected_text = affected_match.group(1).strip()
            # Split by common delimiters
            items = re.split(r"[•·\*]|(?<=\w)\s{2,}", affected_text)
            adv.affected_software = [i.strip() for i in items if 5 < len(i.strip()) < 200][:10]

    except Exception as e:
        logger.warning("Failed to enrich %s: %s", adv.code, e)

    return adv


async def scrape_csk_alerts(client: httpx.AsyncClient) -> List[dict]:
    """Scrape CSK (Cyber Swachhta Kendra) malware alerts."""
    alerts = []
    try:
        resp = await client.get(
            CSK_ALERTS_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        resp.raise_for_status()
        html = resp.text

        # CSK alerts are in an HTML list — extract link text
        # Pattern: <a href="...">Threat Name</a>
        link_pattern = re.compile(r'<a\s+[^>]*href="([^"]+)"[^>]*>([^<]{10,150})</a>', re.IGNORECASE)
        for match in link_pattern.finditer(html):
            href, name = match.group(1), match.group(2).strip()
            # Filter for likely threat names (contains keywords)
            if any(kw in name.lower() for kw in ["ransomware", "trojan", "malware", "botnet", "phishing", "worm", "backdoor", "banker", "stealer", "rat"]):
                alerts.append({
                    "name": name,
                    "url": href if href.startswith("http") else "https://www.csk.gov.in/" + href.lstrip("/"),
                    "source": "csk",
                    "scraped_at": datetime.utcnow().isoformat(),
                })

        # Dedupe
        seen = set()
        unique = []
        for a in alerts:
            key = a["name"].lower()
            if key not in seen:
                seen.add(key)
                unique.append(a)

        logger.info("Scraped %d CSK malware alerts", len(unique))
        return unique[:50]
    except Exception as e:
        logger.warning("Failed to scrape CSK: %s", e)
        return []


async def main():
    logger.info("=" * 60)
    logger.info("CERT-In India Advisory Scraper starting")
    logger.info("=" * 60)

    start = time.time()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Scrape CERT-In advisory list
        advisories = await scrape_certin_list(client, limit=20)

        # Enrich each with detail page (rate-limited)
        logger.info("Enriching %d advisories with detail pages...", len(advisories))
        enriched = []
        for adv in advisories[:10]:  # limit detail fetches
            await asyncio.sleep(1.5)  # rate limit
            adv = await enrich_advisory(client, adv)
            enriched.append(adv)
            logger.info("  %s: %d CVEs, %d domains, %d IPs",
                        adv.code, len(adv.cve_refs), len(adv.extracted_domains), len(adv.extracted_ips))

        # Scrape CSK
        csk_alerts = await scrape_csk_alerts(client)

    duration = time.time() - start

    # Save output
    output = {
        "scraped_at": datetime.utcnow().isoformat(),
        "duration_seconds": round(duration, 2),
        "cert_in_advisories": [asdict(a) for a in enriched],
        "cert_in_list_only": [asdict(a) for a in advisories[10:]],
        "csk_alerts": csk_alerts,
        "totals": {
            "advisories_enriched": len(enriched),
            "advisories_listed": len(advisories),
            "csk_alerts": len(csk_alerts),
            "total_cves": sum(len(a.cve_refs) for a in enriched),
            "total_domains": sum(len(a.extracted_domains) for a in enriched),
            "total_ips": sum(len(a.extracted_ips) for a in enriched),
        },
    }

    OUTPUT_FILE.write_text(json.dumps(output, indent=2))

    logger.info("=" * 60)
    logger.info("Completed in %.1fs", duration)
    logger.info("CERT-In: %d advisories (%d fully enriched)", len(advisories), len(enriched))
    logger.info("CSK: %d malware alerts", len(csk_alerts))
    logger.info("Extracted: %d CVEs, %d domains, %d IPs",
                output["totals"]["total_cves"],
                output["totals"]["total_domains"],
                output["totals"]["total_ips"])
    logger.info("Saved to %s", OUTPUT_FILE)
    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
