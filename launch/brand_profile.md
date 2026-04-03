# SentinelX402 Brand Profiles

## LinkedIn — Amy @ SentinelX402

### Profile Setup

**Name:** Amy @ SentinelX402

**Headline:** Threat Intelligence for AI Agents | Free API — 22K+ Live Indicators | Phishing Detection in <300ms

**About:**
SentinelX402 provides free threat intelligence APIs for AI agents and security automation.

We monitor 22,000+ live threat indicators across OpenPhish, Feodo Tracker, and URLhaus — and make that data available via simple API calls. No signup, no API key.

What we detect:
- Phishing domains (real-time, from live feeds)
- C2 servers and botnet IPs
- CVE vulnerabilities with exploit probability scoring
- India-focused threats: UPI fraud, bank phishing, Aadhaar scams

Built for developers building security agents with LangChain, CrewAI, OpenAI, and MCP.

1,000 free requests: https://sentinelx402-production.up.railway.app
GitHub: https://github.com/splitfireai-hue/sentinelx402

**Location:** India

**Industry:** Computer & Network Security

**Website:** https://sentinelx402-production.up.railway.app

---

## Twitter/X — @SentinelX402

### Profile Setup

**Name:** SentinelX402

**Handle:** @SentinelX402 (or closest available)

**Bio:**
Free threat intelligence API for AI agents. 22K+ live indicators. Phishing detection in <300ms. No signup needed.

Built for LangChain, CrewAI, OpenAI, MCP.

https://sentinelx402-production.up.railway.app

**Location:** India

**Pinned Tweet:**
```
We built a free threat intelligence API for AI agents.

22,000+ live indicators. Real-time phishing detection. CVE risk analysis.

No signup. No API key. Just call the API:

curl "https://sentinelx402-production.up.railway.app/api/v1/threats/lookup?domain=login-secure-paypal.com"

1,000 free requests.

GitHub: https://github.com/splitfireai-hue/sentinelx402
```

---

## Content Strategy

### What to Post (weekly rotation)

**Monday — Threat Alert**
Share top phishing domains detected that week. Use data from:
```bash
python3 -m agents.marketing --platform twitter
```

**Wednesday — Builder Tip**
Show a code snippet: how to integrate with LangChain/CrewAI/OpenAI.
Example: "Add phishing detection to your LangChain agent in 2 lines..."

**Friday — Stat Drop**
Share weekly numbers: indicators monitored, threats detected, new CVEs.
Use data from:
```bash
python3 -m agents.threat_report
```

### Engagement Rules

1. Reply to anyone asking about threat intelligence APIs, MCP tools, or agent security
2. Quote-tweet any x402, MCP, or LangChain security discussions with a relevant demo
3. Never pretend to be a person — always speak as the brand
4. Always include the API URL or GitHub link

### Hashtags

LinkedIn: #cybersecurity #threatintelligence #AI #agents #phishing #infosec
Twitter: #cybersecurity #AI #infosec #LangChain #MCP

---

## Content Generator

Run this anytime you need fresh content:

```bash
# All platforms
python3 -m agents.marketing --all

# LinkedIn only
python3 -m agents.marketing --platform linkedin

# Twitter only
python3 -m agents.marketing --platform twitter
```

Content is auto-generated from live API data — always current, always authentic.
