# Show HN: Free threat intelligence API for AI agents — phishing detection in <300ms

**Title:** Show HN: Free threat intelligence API for AI agents — phishing detection in <300ms

**URL:** https://github.com/splitfireai-hue/sentinelx402

**Text (paste in the text box):**

I built a threat intelligence API designed for AI agents. It detects phishing domains, malicious IPs, and CVE risks using live threat feeds.

The problem: AI agents need real-time threat data, but existing APIs require account creation, API key management, and subscriptions. That friction kills autonomous workflows.

SentinelX402 is free to use — 1,000 requests, no signup, no API key:

- Real-time phishing detection using live feeds (OpenPhish, Feodo Tracker, URLhaus)
- CVE risk analysis with exploit probability scoring (from NVD data)
- IP reputation checking (C2/botnet detection)
- Drop-in integrations for LangChain, CrewAI, OpenAI function calling, and MCP
- Python SDK included

Example:

    curl "https://sentinelx402-production.up.railway.app/api/v1/threats/lookup?domain=login-secure-paypal.com"

Returns risk score, threat type, confidence, and related suspicious domains in <300ms.

Looking for feedback from anyone building security agents or automation tools.

GitHub: https://github.com/splitfireai-hue/sentinelx402
Live API: https://sentinelx402-production.up.railway.app
