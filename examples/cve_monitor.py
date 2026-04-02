"""
CVE Monitor — Track critical vulnerabilities and prioritize patching.

Fetches recent critical CVEs, scores them for exploit probability
and ransomware risk, and generates a prioritized patch list.

Usage:
    pip install sentinelx
    python cve_monitor.py
"""

import sys
sys.path.insert(0, "../sdk")

from sentinelx import SentinelX

API_URL = "https://sentinelx402-production.up.railway.app"


def main():
    client = SentinelX(base_url=API_URL)

    # 1. Look up a specific high-profile CVE
    print("CVE Vulnerability Monitor")
    print("=" * 60)
    print("\n--- Specific CVE Lookup ---")

    cve = client.cve_lookup("CVE-2024-3400")
    print(f"  {cve.cve_id}")
    print(f"  CVSS: {cve.cvss} | Risk: {cve.risk}")
    print(f"  Exploit probability: {cve.exploit_probability}")
    print(f"  Patch urgency: {cve.patch_urgency}")
    print(f"  Ransomware risk: {cve.ransomware_risk}")
    print(f"  Products: {', '.join(cve.affected_products[:3])}")
    print(f"  {cve.description[:120]}...")

    # 2. Search for CVEs by keyword
    print("\n--- Search: 'apache' ---")

    results = client.search_cves("apache", limit=5)
    print(f"  Found {results.total} CVEs")
    for c in results.results:
        emoji = "!!" if c.is_critical else " >"
        print(f"  {emoji} {c.cve_id} | CVSS {c.cvss} | {c.risk} | exploit prob: {c.exploit_probability}")

    # 3. Prioritized patch list
    print("\n--- Patch Priority (from search results) ---")
    prioritized = sorted(results.results, key=lambda c: c.exploit_probability, reverse=True)
    for i, c in enumerate(prioritized, 1):
        print(f"  {i}. [{c.patch_urgency.upper():8}] {c.cve_id} — exploit prob {c.exploit_probability}")

    print("\n" + "=" * 60)
    usage = client.usage()
    print(f"Free tier: {usage.remaining}/{usage.limit} requests remaining")

    client.close()


if __name__ == "__main__":
    main()
