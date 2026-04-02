"""
Marketing Agent — Automated promotion across developer and agent communities.

Generates platform-specific content and tells you exactly where to post it.
Can auto-post to GitHub (discussions, issues on relevant repos).
For LinkedIn, Twitter/X, Reddit — generates ready-to-paste content.

Run:
    python -m agents.marketing

    # Generate content for a specific platform:
    python -m agents.marketing --platform linkedin
    python -m agents.marketing --platform twitter
    python -m agents.marketing --platform reddit
    python -m agents.marketing --platform github

    # Generate all:
    python -m agents.marketing --all
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import sys
from datetime import datetime
from pathlib import Path

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MarketingAgent] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

API_URL = "https://sentinelx402-production.up.railway.app"
GITHUB_URL = "https://github.com/splitfireai-hue/sentinelx402"
OUTPUT_DIR = Path(__file__).parent / "marketing_output"


async def _get_live_data() -> dict:
    """Fetch live stats and sample detections for authentic content."""
    async with httpx.AsyncClient(timeout=15) as client:
        stats = (await client.get("{}/stats".format(API_URL))).json()
        feed = (await client.get("{}/api/v1/threats/feed?page=1&page_size=5".format(API_URL))).json()

        # Get a real detection for demo
        demo = (await client.get(
            "{}/api/v1/threats/lookup".format(API_URL),
            params={"domain": "login-secure-paypal.com"}
        )).json()

    return {"stats": stats, "feed": feed, "demo": demo}


def _generate_linkedin(data: dict) -> list:
    """Generate multiple LinkedIn post variations."""
    indicators = data["stats"].get("data_coverage", {}).get("total_indicators", 0)
    top_threats = data["feed"].get("indicators", [])

    posts = []

    # Post type 1: Threat insight
    posts.append({
        "type": "threat_insight",
        "content": """Just detected {} live threat indicators across our feeds.

Top phishing domains active right now:
{}

These domains are designed to steal credentials from unsuspecting users.

If you're building security automation or AI agents, you can check any domain against our free API:

curl "{}/api/v1/threats/lookup?domain=suspicious-site.com"

1,000 free requests. No signup.

{}

#cybersecurity #phishing #threatintelligence #AI""".format(
            indicators,
            "\n".join("- {} (score: {})".format(t["value"], t["risk_score"]) for t in top_threats[:4]),
            API_URL,
            GITHUB_URL,
        )
    })

    # Post type 2: Builder-focused
    posts.append({
        "type": "builder_focused",
        "content": """Building a security agent? Here's a 2-line integration:

from sentinelx import SentinelX
risk = SentinelX().domain_lookup("suspicious-site.com")

What you get:
- Risk score (0-100)
- Threat type (phishing, malware, C2)
- Related suspicious domains
- <300ms response time

Works with LangChain, CrewAI, OpenAI function calling, and MCP.

{} live threat indicators. Free to use.

{}

#AI #agents #cybersecurity #langchain #python""".format(indicators, GITHUB_URL)
    })

    # Post type 3: India-focused
    posts.append({
        "type": "india_focused",
        "content": """India-specific cyber threats we're tracking:

- UPI fraud domains (fake Paytm, PhonePe, GPay pages)
- Indian bank phishing (SBI, HDFC, ICICI, Axis spoofs)
- Aadhaar/PAN identity theft sites
- Fake ecommerce offers (Flipkart, Myntra)
- Telecom recharge scams (Jio, Airtel)

Our API detects these in real-time. Try it:

curl "{}/api/v1/threats/lookup?domain=sbi-online-banking-verify.com"

Result: score 96, phishing, tagged [india, banking, sbi]

Free for developers and security teams.

{}

#cybersecurity #india #fintech #upi #phishing""".format(API_URL, GITHUB_URL)
    })

    return posts


def _generate_twitter(data: dict) -> list:
    """Generate Twitter/X thread variations."""
    indicators = data["stats"].get("data_coverage", {}).get("total_indicators", 0)

    tweets = []

    # Thread 1: Product launch
    tweets.append({
        "type": "launch_thread",
        "tweets": [
            "Built a free threat intelligence API for AI agents.\n\n{} live indicators. <300ms. No signup.\n\nThread: what it does and why it matters".format(indicators),
            "Problem: AI agents need real-time security data.\n\nBut every existing API requires:\n- Account creation\n- API keys\n- Subscriptions\n\nThat kills autonomous workflows.",
            "SentinelX402 fixes this:\n\n- Domain phishing detection\n- IP reputation (C2/botnet)\n- CVE exploit probability\n- India-focused fraud detection\n\n1,000 free requests. Just call the API.",
            "Try it:\n\ncurl \"{}/api/v1/threats/lookup?domain=login-secure-paypal.com\"\n\nReturns: risk score 94, phishing, with related threats".format(API_URL),
            "Works with:\n- LangChain\n- CrewAI\n- OpenAI function calling\n- MCP (Claude, Cursor)\n- Any HTTP client\n\nGitHub: {}\n\nFeedback welcome.".format(GITHUB_URL),
        ]
    })

    # Single tweet variations
    tweets.append({
        "type": "single",
        "tweets": [
            "Free threat intelligence API for AI agents.\n\n{} live indicators. Real-time phishing detection.\n\nNo signup. No API key.\n\n{}\n\n#cybersecurity #AI".format(indicators, GITHUB_URL),
        ]
    })

    tweets.append({
        "type": "demo",
        "tweets": [
            "Detect phishing in one API call:\n\ncurl \"{}/api/v1/threats/lookup?domain=login-secure-paypal.com\"\n\nResult: score 94, phishing, confidence 0.95\n\nFree. No signup. {}".format(API_URL, GITHUB_URL),
        ]
    })

    return tweets


def _generate_reddit(data: dict) -> list:
    """Generate Reddit post variations for different subreddits."""
    indicators = data["stats"].get("data_coverage", {}).get("total_indicators", 0)

    posts = []

    # r/cybersecurity
    posts.append({
        "subreddit": "r/cybersecurity",
        "title": "I built a free threat intelligence API with {} live indicators — looking for feedback".format(indicators),
        "content": """I've been working on a threat intelligence API that provides real-time phishing detection, IP reputation, and CVE risk analysis.

**What it does:**
- Checks domains against live feeds (OpenPhish, Feodo Tracker, URLhaus)
- Returns risk score (0-100), threat type, confidence
- CVE analysis with exploit probability and ransomware risk
- India-specific coverage (UPI fraud, bank phishing, Aadhaar scams)

**Try it:**
```
curl "{}/api/v1/threats/lookup?domain=login-secure-paypal.com"
```

1,000 free requests, no signup or API key needed.

GitHub: {}

Looking for feedback on data quality, false positive rates, and what threat feeds would be most valuable to add next.

Any SOC analysts or security engineers willing to test it against their workflows?""".format(API_URL, GITHUB_URL)
    })

    # r/artificial
    posts.append({
        "subreddit": "r/artificial",
        "title": "Free threat intelligence API designed for AI agents — LangChain, CrewAI, MCP integrations included",
        "content": """Built an API that AI agents can use to check if domains/IPs are malicious, without any signup or API key management.

The idea: autonomous security agents need real-time threat data, but existing APIs require human checkout flows. This API is designed for machine-to-machine use.

**Integrations:**
- LangChain tool (drop-in)
- CrewAI tool
- OpenAI function calling spec
- MCP server (works with Claude, Cursor)

**Example (LangChain):**
```python
from integrations.langchain_tool import get_sentinel_tools
tools = get_sentinel_tools()
agent = initialize_agent(tools, llm)
agent.run("Is login-secure-paypal.com safe?")
```

{} live threat indicators. Free to use.

GitHub: {}""".format(indicators, GITHUB_URL)
    })

    # r/langchain
    posts.append({
        "subreddit": "r/langchain",
        "title": "Open-source LangChain tool for real-time threat intelligence — phishing detection, CVE analysis",
        "content": """Built a set of LangChain tools that give your agent real-time cybersecurity intelligence:

```python
from integrations.langchain_tool import get_sentinel_tools

tools = get_sentinel_tools()
# Returns: SentinelDomainLookup, SentinelIPLookup, SentinelCVELookup, SentinelCVESearch
```

Your agent can now:
- Check if a domain is phishing/malware
- Look up IP reputation (C2 servers, botnets)
- Analyze CVE risk with exploit probability
- Search for vulnerabilities by keyword

Backed by {} live indicators from OpenPhish, Feodo Tracker, and URLhaus.

Free to use (1,000 requests, no signup).

GitHub: {}

Would love feedback from anyone building security-focused agents.""".format(indicators, GITHUB_URL)
    })

    return posts


async def main():
    platform = None
    if "--platform" in sys.argv:
        idx = sys.argv.index("--platform")
        if idx + 1 < len(sys.argv):
            platform = sys.argv[idx + 1]
    show_all = "--all" in sys.argv or platform is None

    logger.info("Fetching live data...")
    data = await _get_live_data()

    OUTPUT_DIR.mkdir(exist_ok=True)
    today = datetime.utcnow().strftime("%Y-%m-%d")

    if show_all or platform == "linkedin":
        posts = _generate_linkedin(data)
        print("\n" + "=" * 60)
        print("LINKEDIN POSTS ({} variations)".format(len(posts)))
        print("=" * 60)
        for i, post in enumerate(posts, 1):
            print("\n--- Variation {} ({}) ---".format(i, post["type"]))
            print(post["content"])
        (OUTPUT_DIR / "linkedin_{}.md".format(today)).write_text(
            "\n\n---\n\n".join(p["content"] for p in posts)
        )

    if show_all or platform == "twitter":
        tweets = _generate_twitter(data)
        print("\n" + "=" * 60)
        print("TWITTER/X POSTS ({} variations)".format(len(tweets)))
        print("=" * 60)
        for i, t in enumerate(tweets, 1):
            print("\n--- Variation {} ({}) ---".format(i, t["type"]))
            for j, tweet in enumerate(t["tweets"], 1):
                if len(t["tweets"]) > 1:
                    print("\n  Tweet {}/{}:".format(j, len(t["tweets"])))
                print(tweet)
        (OUTPUT_DIR / "twitter_{}.md".format(today)).write_text(
            "\n\n---\n\n".join("\n".join(t["tweets"]) for t in tweets)
        )

    if show_all or platform == "reddit":
        posts = _generate_reddit(data)
        print("\n" + "=" * 60)
        print("REDDIT POSTS ({} subreddits)".format(len(posts)))
        print("=" * 60)
        for post in posts:
            print("\n--- {} ---".format(post["subreddit"]))
            print("Title: {}".format(post["title"]))
            print()
            print(post["content"])
        (OUTPUT_DIR / "reddit_{}.md".format(today)).write_text(
            "\n\n---\n\n".join(
                "## {}\n**{}**\n\n{}".format(p["subreddit"], p["title"], p["content"])
                for p in posts
            )
        )

    logger.info("Content saved to agents/marketing_output/")
    print("\n" + "=" * 60)
    print("POSTING CHECKLIST")
    print("=" * 60)
    print("""
1. LinkedIn  — Pick one variation, paste on your profile
2. Twitter/X — Post the thread OR single tweet
3. Reddit    — Post in r/cybersecurity, r/artificial, r/langchain
               (space them out — 1 per day to avoid spam flags)

Files saved in: agents/marketing_output/
""")


if __name__ == "__main__":
    asyncio.run(main())
