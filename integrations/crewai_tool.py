"""
SentinelX402 CrewAI Tools — Threat intelligence for CrewAI security agents.

Usage:
    pip install crewai sentinelx

    from integrations.crewai_tool import SentinelDomainTool, SentinelIPTool, SentinelCVETool

    security_agent = Agent(
        role="Security Analyst",
        goal="Detect and report threats",
        tools=[SentinelDomainTool(), SentinelIPTool(), SentinelCVETool()],
    )
"""

from __future__ import annotations

import httpx

try:
    from crewai.tools import BaseTool
except ImportError:
    try:
        from crewai_tools import BaseTool
    except ImportError:
        raise ImportError("Install crewai: pip install crewai")

API_URL = "https://sentinelx402-production.up.railway.app"


class SentinelDomainTool(BaseTool):
    name: str = "Sentinel Domain Risk Checker"
    description: str = (
        "Check if a domain is a phishing or malware site. "
        "Provide a domain name and get a risk score (0-100), threat classification, "
        "and related suspicious domains. Scores above 70 indicate a likely threat."
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
            return "Error checking domain: {}".format(resp.text)
        d = resp.json()
        verdict = "MALICIOUS" if d["risk_score"] >= 70 else "SAFE"
        result = "[{}] {} — score: {}/100, type: {}, confidence: {}".format(
            verdict, d["domain"], d["risk_score"], d["threat_type"], d["confidence"]
        )
        if d.get("related_domains"):
            result += " | related: {}".format(", ".join(d["related_domains"][:3]))
        return result


class SentinelIPTool(BaseTool):
    name: str = "Sentinel IP Reputation Checker"
    description: str = (
        "Check if an IP address is associated with C2 servers, botnets, or malicious activity. "
        "Provide an IP address and get a risk score and threat classification."
    )

    def _run(self, ip: str) -> str:
        ip = ip.strip().strip("'\"")
        resp = httpx.get(
            "{}/api/v1/threats/ip".format(API_URL),
            params={"ip": ip},
            timeout=10,
        )
        if resp.status_code != 200:
            return "Error checking IP: {}".format(resp.text)
        d = resp.json()
        verdict = "MALICIOUS" if d["risk_score"] >= 70 else "SAFE"
        return "[{}] {} — score: {}/100, threats: {}, tags: {}".format(
            verdict, d["ip"], d["risk_score"],
            ", ".join(d["threat_types"]) or "none",
            ", ".join(d["tags"]),
        )


class SentinelCVETool(BaseTool):
    name: str = "Sentinel CVE Analyzer"
    description: str = (
        "Analyze a CVE vulnerability for exploit probability, patch urgency, and ransomware risk. "
        "Provide a CVE ID like CVE-2024-3400 and get detailed risk analysis beyond raw CVSS."
    )

    def _run(self, cve_id: str) -> str:
        cve_id = cve_id.strip().strip("'\"").upper()
        resp = httpx.get(
            "{}/api/v1/cves/{}".format(API_URL, cve_id),
            timeout=15,
        )
        if resp.status_code != 200:
            return "Error analyzing CVE: {}".format(resp.text)
        d = resp.json()
        return "{} | CVSS: {} | risk: {} | exploit prob: {} | patch: {} | ransomware: {} | {}".format(
            d["cve_id"], d["cvss"], d["risk"], d["exploit_probability"],
            d["patch_urgency"], d["ransomware_risk"],
            d["description"][:150] if d.get("description") else "",
        )
