# Show HN: Threat intelligence API for AI agents, paid per request via HTTP 402

**Title:** Show HN: Threat intelligence API for AI agents, paid per request via HTTP 402

**URL:** https://github.com/splitfireai-hue/sentinelx402

**Text (paste in the text box):**

I built a cyber threat intelligence API designed for autonomous AI agents. It detects phishing domains, malicious IPs, and CVE risks — and accepts micropayments via the x402 protocol (USDC on Base).

The problem: AI agents need real-time threat data, but existing APIs require API key signups, subscriptions, and human checkout. That doesn't work for autonomous systems.

SentinelX402 solves this with:

- Real-time phishing detection using live feeds (OpenPhish, Feodo Tracker, URLhaus)
- CVE risk analysis with exploit probability scoring (from NVD data)
- India-focused threat data (UPI fraud, bank spoofing domains)
- HTTP-native payments via x402 — no signup, no API key, just pay per request
- First 1,000 requests free

Example:

    curl "https://sentinelx402-production.up.railway.app/api/v1/threats/lookup?domain=login-secure-paypal.com"

Returns risk score, threat type, confidence, and related suspicious domains in <300ms.

Tech stack: FastAPI, SQLite, live OSINT feeds, x402 (Coinbase), Python SDK included.

Looking for feedback from anyone building security agents or agent-to-agent commerce tools.

GitHub: https://github.com/splitfireai-hue/sentinelx402
Live API: https://sentinelx402-production.up.railway.app/info
