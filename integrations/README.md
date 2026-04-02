# SentinelX402 Agent Integrations

Drop-in threat intelligence for any AI agent framework.

## LangChain

```python
from integrations.langchain_tool import get_sentinel_tools

tools = get_sentinel_tools()
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
agent.run("Is login-secure-paypal.com a phishing site?")
```

## CrewAI

```python
from integrations.crewai_tool import SentinelDomainTool, SentinelIPTool, SentinelCVETool

security_agent = Agent(
    role="Security Analyst",
    goal="Detect and report threats",
    tools=[SentinelDomainTool(), SentinelIPTool(), SentinelCVETool()],
)
```

## OpenAI Function Calling

```python
from integrations.openai_functions import SENTINEL_FUNCTIONS, handle_sentinel_call

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Analyze CVE-2024-3400"}],
    functions=SENTINEL_FUNCTIONS,
)
result = handle_sentinel_call(response.choices[0].message.function_call)
```

## MCP Server (Claude, Cursor, etc.)

Add to your MCP client config:

```json
{
  "mcpServers": {
    "sentinelx402": {
      "command": "python",
      "args": ["integrations/mcp_server.py"]
    }
  }
}
```

The agent will automatically discover 5 threat intelligence tools:
- `domain_risk_lookup` — phishing detection
- `ip_reputation` — C2/botnet detection
- `cve_risk_analysis` — exploit probability scoring
- `cve_search` — find vulnerabilities by keyword
- `threat_feed` — latest IOC feed

All tools use the live API at `https://sentinelx402-production.up.railway.app`.
First 1,000 requests free.
