# SentinelX Python SDK

Python client for [SentinelX402](https://github.com/sentinelx402) — cyber threat intelligence APIs for AI agents.

## Install

```bash
pip install sentinelx
```

## Quickstart

```python
from sentinelx import SentinelX

client = SentinelX()  # defaults to http://localhost:8000

# Domain risk lookup
risk = client.domain_lookup("suspicious-site.xyz")
print(risk.risk_score)      # 87.5
print(risk.threat_type)     # "phishing"
print(risk.is_malicious)    # True
print(risk.related_domains) # ["similar-phish.com", ...]

# IP reputation
ip = client.ip_lookup("185.220.101.42")
print(ip.risk_score)        # 95.0
print(ip.threat_types)      # ["c2"]

# CVE analysis
cve = client.cve_lookup("CVE-2024-3400")
print(cve.cvss)              # 10.0
print(cve.exploit_probability)  # 1.0
print(cve.is_critical)      # True
print(cve.ransomware_risk)  # False

# Threat feed
feed = client.threat_feed(page=1, page_size=10)
for indicator in feed.indicators:
    print(indicator.value, indicator.risk_score)

# Check free tier usage
usage = client.usage()
print(usage.remaining)  # 95
```

## Async Usage

```python
import asyncio
from sentinelx import AsyncSentinelX

async def main():
    async with AsyncSentinelX() as client:
        risk = await client.domain_lookup("suspicious-site.xyz")
        print(risk.risk_score, risk.threat_type)

asyncio.run(main())
```

## Configuration

```python
client = SentinelX(
    base_url="https://api.sentinelx402.com",  # production URL
    timeout=30.0,
    wallet_address="0xYourWallet",  # for free tier tracking
)
```

## Error Handling

```python
from sentinelx.client import SentinelXError, FreeTierExhausted

try:
    risk = client.domain_lookup("example.com")
except FreeTierExhausted:
    print("Free tier exhausted — enable x402 payments")
except SentinelXError as e:
    print(f"API error {e.status_code}: {e.detail}")
```

## API Methods

| Method | Description |
|--------|-------------|
| `domain_lookup(domain)` | Domain threat risk score |
| `ip_lookup(ip)` | IP reputation check |
| `threat_feed(page, page_size)` | Latest IOC feed |
| `cve_lookup(cve_id)` | CVE risk analysis |
| `recent_cves(limit)` | Recent critical CVEs |
| `search_cves(keyword, limit)` | Search CVEs |
| `usage()` | Check free tier usage |

1,000 free requests. No signup, no API key.
