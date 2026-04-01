# SentinelX402

**Cyber threat intelligence APIs for AI agents, paid via x402 micropayments.**

Real-time phishing detection, CVE risk analysis, and malicious domain/IP reputation scoring — accessible to autonomous agents via HTTP-native micropayments on Base (USDC).

## Quickstart

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env with your settings (defaults work out of the box)
```

### 2. Install dependencies

```bash
pip install -e .
```

### 3. Seed threat data & start

```bash
python -m app.data.seed_threats
uvicorn app.main:app --reload
```

Visit `http://localhost:8000/docs` for interactive API docs.

---

## Production Deployment

### Docker (recommended)

```bash
docker compose up -d
```

This starts the API server with PostgreSQL, Redis, gunicorn (4 workers), health checks, and auto-restart.

### Manual

```bash
pip install ".[production]"
# Set DATABASE_URL, REDIS_URL, ENVIRONMENT=production in .env
gunicorn app.main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --workers 4
```

---

## API Reference

| Endpoint | Method | Price | Description |
|----------|--------|-------|-------------|
| `/api/v1/threats/lookup?domain=` | GET | $0.10 | Domain threat risk lookup |
| `/api/v1/threats/ip?ip=` | GET | $0.10 | IP reputation check |
| `/api/v1/threats/feed` | GET | $0.10 | Latest threat indicators feed |
| `/api/v1/cves/{cve_id}` | GET | $0.25 | CVE risk analysis |
| `/api/v1/cves/recent` | GET | $0.10 | Recent critical CVEs |
| `/api/v1/cves/search?keyword=` | GET | $0.10 | Search CVEs by keyword |
| `/health` | GET | Free | Health check (DB connectivity) |
| `/info` | GET | Free | API info and pricing |

---

## Usage Examples

### Python

```python
import httpx

client = httpx.Client(base_url="http://localhost:8000")

# Domain risk lookup
resp = client.get("/api/v1/threats/lookup", params={"domain": "login-secure-paypal.com"})
print(resp.json())
# {
#   "domain": "login-secure-paypal.com",
#   "risk_score": 94.0,
#   "threat_type": "phishing",
#   "confidence": 0.95,
#   "related_domains": ["secure-paypa1-login.com", "paypal-auth-secure.net"]
# }

# CVE risk analysis
resp = client.get("/api/v1/cves/CVE-2024-3400")
print(resp.json())
# {
#   "cve_id": "CVE-2024-3400",
#   "cvss": 10.0,
#   "exploit_probability": 1.0,
#   "risk": "critical",
#   "patch_urgency": "critical",
#   "ransomware_risk": false
# }
```

### curl

```bash
curl "http://localhost:8000/api/v1/threats/lookup?domain=suspicious-site.xyz"
curl "http://localhost:8000/api/v1/threats/ip?ip=185.220.101.42"
curl "http://localhost:8000/api/v1/threats/feed?page=1&page_size=10"
curl "http://localhost:8000/api/v1/cves/CVE-2024-3400"
curl "http://localhost:8000/api/v1/cves/recent?limit=5"
curl "http://localhost:8000/api/v1/cves/search?keyword=apache"
```

---

## x402 Payment Flow

When `X402_ENABLED=true`, intelligence endpoints require payment:

```
Agent sends GET /api/v1/threats/lookup?domain=example.com
       |
Server returns HTTP 402 + payment requirements (USDC amount, wallet, network)
       |
Agent wallet signs USDC payment via EIP-3009
       |
Agent retries request with PAYMENT-SIGNATURE header
       |
Server verifies payment via facilitator, returns intelligence response
```

Set `X402_ENABLED=false` for development/testing without payments.

---

## Production Features

- **Input validation** — domain format, IP address format, CVE ID format validation
- **Rate limiting** — configurable per-endpoint via `THREAT_RATE_LIMIT` / `CVE_RATE_LIMIT`
- **Security headers** — X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Cache-Control
- **CORS** — configurable via `ALLOWED_ORIGINS`
- **Structured logging** — request method, path, status, duration (ms)
- **Error handling** — graceful 400/404/502/504 responses, no stack traces exposed
- **NVD timeout** — configurable via `NVD_TIMEOUT_SECONDS` (default 15s)
- **Cache resilience** — cache failures are logged but don't block requests
- **Health checks** — deep health check verifies database connectivity
- **Docker** — multi-stage build, non-root user, health checks, gunicorn with 4 workers

---

## Architecture

```
sentinelx402/
├── app/
│   ├── main.py           # FastAPI app + middleware stack
│   ├── config.py          # Environment configuration
│   ├── database.py        # Async SQLAlchemy engine
│   ├── cache.py           # Redis / in-memory cache layer
│   ├── x402_setup.py      # Payment route configuration
│   ├── models/            # SQLAlchemy ORM models
│   ├── schemas/           # Pydantic request/response models
│   ├── routers/           # API route handlers + validation
│   ├── services/          # Business logic + scoring + NVD integration
│   └── data/              # Mock threat data + seed scripts
├── tests/                 # 31 tests (unit + integration)
├── docker-compose.yml     # Production: API + PostgreSQL + Redis
├── docker-compose.dev.yml # Dev: just PostgreSQL + Redis
├── Dockerfile             # Multi-stage, non-root, health checks
└── mcp.json               # Agent discovery metadata
```

---

## Configuration

All settings via environment variables (or `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./sentinelx402.db` | Database connection string |
| `REDIS_URL` | (empty) | Redis URL, empty = in-memory cache |
| `X402_ENABLED` | `false` | Enable x402 payment middleware |
| `WALLET_ADDRESS` | — | Your USDC receiving wallet |
| `FACILITATOR_URL` | `https://x402.org/facilitator` | x402 facilitator endpoint |
| `NETWORK_ID` | `eip155:84532` | Base Sepolia (testnet) |
| `NVD_API_KEY` | (empty) | NVD API key for higher rate limits |
| `ENVIRONMENT` | `development` | `development` / `production` |
| `LOG_LEVEL` | `INFO` | Logging level |
| `ALLOWED_ORIGINS` | (empty) | CORS origins, comma-separated |
| `THREAT_RATE_LIMIT` | `60/minute` | Rate limit for threat endpoints |
| `CVE_RATE_LIMIT` | `30/minute` | Rate limit for CVE endpoints |
| `NVD_TIMEOUT_SECONDS` | `15` | NVD API request timeout |

---

## Testing

```bash
pip install ".[dev]"
pytest -v
```

31 tests covering scoring algorithms, input validation, API endpoints, security headers, and error handling.

---

## Tech Stack

- **Backend**: FastAPI + Uvicorn (dev) / Gunicorn (prod)
- **Database**: SQLite (dev) / PostgreSQL 16 (prod)
- **Cache**: In-memory (dev) / Redis 7 (prod)
- **Payments**: x402 protocol (USDC on Base)
- **CVE Data**: NVD API via nvdlib
- **Rate Limiting**: slowapi

---

## License

MIT
