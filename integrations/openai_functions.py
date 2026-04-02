"""
SentinelX402 OpenAI Function Calling — Use with GPT-4, GPT-3.5, or any OpenAI-compatible model.

Usage:
    import openai
    from integrations.openai_functions import SENTINEL_FUNCTIONS, handle_sentinel_call

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Is login-secure-paypal.com safe?"}],
        functions=SENTINEL_FUNCTIONS,
        function_call="auto",
    )

    # If the model calls a function, execute it:
    if response.choices[0].message.get("function_call"):
        result = handle_sentinel_call(response.choices[0].message["function_call"])
"""

from __future__ import annotations

import json

import httpx

API_URL = "https://sentinelx402-production.up.railway.app"

# OpenAI function definitions
SENTINEL_FUNCTIONS = [
    {
        "name": "check_domain_threat",
        "description": "Check if a domain is malicious (phishing, malware, C2 server). Returns risk score 0-100, threat type, confidence, and related suspicious domains. Use when you need to verify if a URL or domain is safe.",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain name to check, e.g. 'suspicious-site.com'"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "check_ip_reputation",
        "description": "Check if an IP address is associated with malicious activity (C2 servers, botnets, scanners). Returns risk score and threat classifications.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IP address to check, e.g. '185.220.101.42'"
                }
            },
            "required": ["ip"]
        }
    },
    {
        "name": "analyze_cve",
        "description": "Get detailed risk analysis for a CVE vulnerability including exploit probability, patch urgency, and ransomware risk. Goes beyond raw CVSS scoring.",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier, e.g. 'CVE-2024-3400'"
                }
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "search_cves",
        "description": "Search for CVE vulnerabilities by keyword. Find vulnerabilities affecting specific technologies, vendors, or attack types.",
        "parameters": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search keyword, e.g. 'apache', 'remote code execution', 'sql injection'"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default 5)",
                    "default": 5
                }
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "get_threat_feed",
        "description": "Get the latest threat indicators (malicious domains, IPs, hashes). Use when you need a batch of recent threats for monitoring or blocklist updates.",
        "parameters": {
            "type": "object",
            "properties": {
                "page": {
                    "type": "integer",
                    "description": "Page number (default 1)",
                    "default": 1
                },
                "page_size": {
                    "type": "integer",
                    "description": "Number of indicators per page (default 20, max 100)",
                    "default": 20
                }
            }
        }
    }
]


def handle_sentinel_call(function_call) -> str:
    """Execute a SentinelX402 function call from OpenAI's response."""
    name = function_call["name"] if isinstance(function_call, dict) else function_call.name
    args_str = function_call["arguments"] if isinstance(function_call, dict) else function_call.arguments
    args = json.loads(args_str)

    if name == "check_domain_threat":
        resp = httpx.get(
            "{}/api/v1/threats/lookup".format(API_URL),
            params={"domain": args["domain"]},
            timeout=10,
        )
    elif name == "check_ip_reputation":
        resp = httpx.get(
            "{}/api/v1/threats/ip".format(API_URL),
            params={"ip": args["ip"]},
            timeout=10,
        )
    elif name == "analyze_cve":
        resp = httpx.get(
            "{}/api/v1/cves/{}".format(API_URL, args["cve_id"]),
            timeout=15,
        )
    elif name == "search_cves":
        resp = httpx.get(
            "{}/api/v1/cves/search".format(API_URL),
            params={"keyword": args["keyword"], "limit": args.get("limit", 5)},
            timeout=15,
        )
    elif name == "get_threat_feed":
        resp = httpx.get(
            "{}/api/v1/threats/feed".format(API_URL),
            params={"page": args.get("page", 1), "page_size": args.get("page_size", 20)},
            timeout=10,
        )
    else:
        return json.dumps({"error": "Unknown function: {}".format(name)})

    return resp.text


# OpenAI tools format (for newer API)
SENTINEL_TOOLS = [{"type": "function", "function": f} for f in SENTINEL_FUNCTIONS]
