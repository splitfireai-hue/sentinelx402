"""
SentinelX402 MCP Server — Model Context Protocol server for AI agent discovery.

This server exposes SentinelX402 tools via the MCP protocol, allowing
any MCP-compatible AI agent (Claude, GPT, etc.) to discover and use
threat intelligence capabilities automatically.

Usage (stdio transport):
    python integrations/mcp_server.py

Usage (SSE transport for remote agents):
    python integrations/mcp_server.py --sse --port 3000

Then add to your MCP client config:
    {
      "mcpServers": {
        "sentinelx402": {
          "command": "python",
          "args": ["integrations/mcp_server.py"]
        }
      }
    }
"""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx

API_URL = "https://sentinelx402-production.up.railway.app"

# MCP Tool definitions
TOOLS = [
    {
        "name": "domain_risk_lookup",
        "description": "Check if a domain is malicious (phishing, malware, C2). Returns risk score 0-100, threat type, confidence, and related suspicious domains. Scores above 70 indicate a likely threat. Powered by live feeds from OpenPhish, URLhaus, and proprietary scoring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name to check, e.g. 'suspicious-site.com'"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "ip_reputation",
        "description": "Check if an IP address is associated with C2 servers, botnets, or malicious scanning. Powered by Feodo Tracker live feed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address to check, e.g. '185.220.101.42'"
                }
            },
            "required": ["ip"]
        }
    },
    {
        "name": "cve_risk_analysis",
        "description": "Get detailed CVE risk analysis including exploit probability, patch urgency, and ransomware risk. Goes beyond raw CVSS with proprietary scoring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier, e.g. 'CVE-2024-3400'"
                }
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "cve_search",
        "description": "Search for CVE vulnerabilities by keyword. Find vulnerabilities affecting specific technologies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search keyword, e.g. 'apache', 'remote code execution'"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10)",
                    "default": 10
                }
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "threat_feed",
        "description": "Get latest threat indicators — phishing domains, malicious IPs, malware hashes. Use for blocklist updates or monitoring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "page": {"type": "integer", "default": 1},
                "page_size": {"type": "integer", "default": 20}
            }
        }
    },
]


def _call_api(path: str, params: dict = None) -> dict:
    """Call SentinelX402 API."""
    resp = httpx.get("{}{}".format(API_URL, path), params=params or {}, timeout=15)
    return resp.json()


def handle_tool_call(name: str, arguments: dict) -> Any:
    """Execute a tool call and return the result."""
    if name == "domain_risk_lookup":
        return _call_api("/api/v1/threats/lookup", {"domain": arguments["domain"]})
    elif name == "ip_reputation":
        return _call_api("/api/v1/threats/ip", {"ip": arguments["ip"]})
    elif name == "cve_risk_analysis":
        return _call_api("/api/v1/cves/{}".format(arguments["cve_id"]))
    elif name == "cve_search":
        return _call_api("/api/v1/cves/search", {
            "keyword": arguments["keyword"],
            "limit": arguments.get("limit", 10),
        })
    elif name == "threat_feed":
        return _call_api("/api/v1/threats/feed", {
            "page": arguments.get("page", 1),
            "page_size": arguments.get("page_size", 20),
        })
    else:
        return {"error": "Unknown tool: {}".format(name)}


def run_stdio():
    """Run MCP server over stdio (JSON-RPC)."""
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            request = json.loads(line.strip())
        except (json.JSONDecodeError, KeyboardInterrupt):
            break

        method = request.get("method", "")
        req_id = request.get("id")

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "sentinelx402",
                        "version": "0.1.0",
                    },
                    "capabilities": {
                        "tools": {},
                    },
                },
            }
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS},
            }
        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            result = handle_tool_call(tool_name, tool_args)
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2),
                        }
                    ],
                },
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "Method not found"},
            }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_stdio()
