"""
Async Security Agent — High-performance concurrent threat scanning.

Demonstrates using the async client to scan multiple indicators
concurrently, as an autonomous agent would.

Usage:
    pip install sentinelx
    python async_agent.py
"""

import asyncio
import sys
sys.path.insert(0, "../sdk")

from sentinelx import AsyncSentinelX

API_URL = "https://sentinelx402-production.up.railway.app"

# Indicators to scan concurrently
DOMAINS = [
    "login-secure-paypal.com",
    "google.com",
    "chase-security-alert.net",
    "github.com",
    "sbi-online-banking-verify.com",
]

IPS = [
    "185.220.101.42",
    "8.8.8.8",
    "103.224.182.250",
]


async def main():
    async with AsyncSentinelX(base_url=API_URL) as client:
        print("Async Security Agent — Concurrent Threat Scan")
        print("=" * 50)

        # Scan all domains concurrently
        domain_tasks = [client.domain_lookup(d) for d in DOMAINS]
        ip_tasks = [client.ip_lookup(ip) for ip in IPS]

        # Execute all at once
        domain_results = await asyncio.gather(*domain_tasks)
        ip_results = await asyncio.gather(*ip_tasks)

        print("\n--- Domains ---")
        threats = 0
        for result in domain_results:
            status = "THREAT" if result.is_malicious else "SAFE  "
            print(f"  [{status}] {result.domain} — score: {result.risk_score}")
            if result.is_malicious:
                threats += 1

        print("\n--- IPs ---")
        for result in ip_results:
            status = "THREAT" if result.is_malicious else "SAFE  "
            print(f"  [{status}] [redacted] — score: {result.risk_score}")
            if result.is_malicious:
                threats += 1

        print(f"\n{threats} threats detected across {len(DOMAINS) + len(IPS)} indicators")

        usage = await client.usage()
        print(f"Free tier: {usage.remaining}/{usage.limit} remaining")


if __name__ == "__main__":
    asyncio.run(main())
