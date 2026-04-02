"""
SentinelX402 LangChain Tools — Drop-in threat intelligence for any LangChain agent.

Usage:
    pip install langchain sentinelx

    from integrations.langchain_tool import SentinelDomainLookup, SentinelIPLookup, SentinelCVELookup

    # Add to your agent
    tools = [SentinelDomainLookup(), SentinelIPLookup(), SentinelCVELookup()]
    agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
    agent.run("Is login-secure-paypal.com a phishing site?")
"""

from __future__ import annotations

import json
from typing import Optional

import httpx

try:
    from langchain.tools import BaseTool
except ImportError:
    raise ImportError("Install langchain: pip install langchain")

API_URL = "https://sentinelx402-production.up.railway.app"


class SentinelDomainLookup(BaseTool):
    name: str = "sentinel_domain_lookup"
    description: str = (
        "Check if a domain is malicious (phishing, malware, C2). "
        "Input: a domain name like 'example.com'. "
        "Returns risk score (0-100), threat type, confidence, and related suspicious domains. "
        "Use this when you need to verify if a URL or domain is safe."
    )

    def _run(self, domain: str) -> str:
        domain = domain.strip().strip("'\"").lower()
        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]
        resp = httpx.get(
            "{}/api/v1/threats/lookup".format(API_URL),
            params={"domain": domain},
            timeout=10,
        )
        if resp.status_code != 200:
            return "Error: {}".format(resp.text)
        data = resp.json()
        result = "Domain: {}\nRisk Score: {}/100\nThreat Type: {}\nConfidence: {}".format(
            data["domain"], data["risk_score"], data["threat_type"], data["confidence"]
        )
        if data.get("related_domains"):
            result += "\nRelated Threats: {}".format(", ".join(data["related_domains"][:3]))
        if data["risk_score"] >= 70:
            result += "\n⚠ WARNING: This domain is likely MALICIOUS"
        else:
            result += "\n✓ This domain appears safe"
        return result

    async def _arun(self, domain: str) -> str:
        return self._run(domain)


class SentinelIPLookup(BaseTool):
    name: str = "sentinel_ip_lookup"
    description: str = (
        "Check if an IP address is malicious (C2 server, botnet, scanner). "
        "Input: an IP address like '185.220.101.42'. "
        "Returns risk score, threat types, and tags. "
        "Use this when you need to check if an IP is associated with threats."
    )

    def _run(self, ip: str) -> str:
        ip = ip.strip().strip("'\"")
        resp = httpx.get(
            "{}/api/v1/threats/ip".format(API_URL),
            params={"ip": ip},
            timeout=10,
        )
        if resp.status_code != 200:
            return "Error: {}".format(resp.text)
        data = resp.json()
        result = "IP: {}\nRisk Score: {}/100\nThreat Types: {}\nTags: {}".format(
            data["ip"], data["risk_score"],
            ", ".join(data["threat_types"]) or "none",
            ", ".join(data["tags"]),
        )
        if data["risk_score"] >= 70:
            result += "\n⚠ WARNING: This IP is likely MALICIOUS"
        else:
            result += "\n✓ This IP appears safe"
        return result

    async def _arun(self, ip: str) -> str:
        return self._run(ip)


class SentinelCVELookup(BaseTool):
    name: str = "sentinel_cve_lookup"
    description: str = (
        "Get detailed risk analysis for a CVE vulnerability. "
        "Input: a CVE ID like 'CVE-2024-3400'. "
        "Returns CVSS score, exploit probability, patch urgency, ransomware risk. "
        "Use this when you need to assess the risk of a specific vulnerability."
    )

    def _run(self, cve_id: str) -> str:
        cve_id = cve_id.strip().strip("'\"").upper()
        resp = httpx.get(
            "{}/api/v1/cves/{}".format(API_URL, cve_id),
            timeout=15,
        )
        if resp.status_code != 200:
            return "Error: {}".format(resp.text)
        data = resp.json()
        result = "CVE: {}\nCVSS: {}\nRisk: {}\nExploit Probability: {}\nPatch Urgency: {}\nRansomware Risk: {}".format(
            data["cve_id"], data["cvss"], data["risk"],
            data["exploit_probability"], data["patch_urgency"], data["ransomware_risk"],
        )
        if data.get("description"):
            result += "\nDescription: {}".format(data["description"][:200])
        return result

    async def _arun(self, cve_id: str) -> str:
        return self._run(cve_id)


class SentinelCVESearch(BaseTool):
    name: str = "sentinel_cve_search"
    description: str = (
        "Search for CVE vulnerabilities by keyword. "
        "Input: a keyword like 'apache' or 'remote code execution'. "
        "Returns matching CVEs with risk scores and exploit probabilities. "
        "Use this when you need to find vulnerabilities affecting a specific technology."
    )

    def _run(self, keyword: str) -> str:
        keyword = keyword.strip().strip("'\"")
        resp = httpx.get(
            "{}/api/v1/cves/search".format(API_URL),
            params={"keyword": keyword, "limit": 5},
            timeout=15,
        )
        if resp.status_code != 200:
            return "Error: {}".format(resp.text)
        data = resp.json()
        if not data["results"]:
            return "No CVEs found for '{}'".format(keyword)
        lines = ["Found {} CVEs for '{}':".format(data["total"], keyword)]
        for cve in data["results"]:
            lines.append("  {} | CVSS {} | {} | exploit prob: {}".format(
                cve["cve_id"], cve["cvss"], cve["risk"], cve["exploit_probability"]
            ))
        return "\n".join(lines)

    async def _arun(self, keyword: str) -> str:
        return self._run(keyword)


# Convenience: get all tools at once
def get_sentinel_tools():
    """Return all SentinelX402 tools for LangChain agent initialization."""
    return [
        SentinelDomainLookup(),
        SentinelIPLookup(),
        SentinelCVELookup(),
        SentinelCVESearch(),
    ]
