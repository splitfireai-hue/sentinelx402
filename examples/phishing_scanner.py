"""
Phishing Scanner — Scan a list of URLs and flag malicious ones.

Usage:
    pip install sentinelx
    python phishing_scanner.py
"""

import sys
sys.path.insert(0, "../sdk")

from sentinelx import SentinelX

API_URL = "https://sentinelx402-production.up.railway.app"

# URLs to scan (could come from emails, chat logs, web scraping, etc.)
urls_to_check = [
    "login-secure-paypal.com",
    "google.com",
    "amaz0n-verify.com",
    "github.com",
    "hdfc-netbanking-secure.xyz",
    "upi-paytm-cashback-claim.com",
    "stackoverflow.com",
    "metamask-wallet-sync.com",
]


def main():
    client = SentinelX(base_url=API_URL)

    print("SentinelX402 Phishing Scanner")
    print("=" * 50)

    malicious_count = 0

    for domain in urls_to_check:
        risk = client.domain_lookup(domain)

        if risk.is_malicious:
            malicious_count += 1
            print(f"  THREAT  {domain}")
            print(f"          Score: {risk.risk_score} | Type: {risk.threat_type} | Confidence: {risk.confidence}")
            if risk.related_domains:
                print(f"          Related: {', '.join(risk.related_domains[:3])}")
        else:
            print(f"  SAFE    {domain} (score: {risk.risk_score})")

    print("=" * 50)
    print(f"Scanned {len(urls_to_check)} domains | {malicious_count} threats found")

    # Check usage
    usage = client.usage()
    print(f"Free tier: {usage.remaining}/{usage.limit} requests remaining")

    client.close()


if __name__ == "__main__":
    main()
