from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.cache import close_redis, init_redis
from app.config import settings, setup_logging
from app.database import engine
from app.metrics import metrics
from app.models import Base
from app.routers import admin, cve_intelligence, health, threat_feed

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Starting SentinelX402 (env=%s)", settings.ENVIRONMENT)

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready")

    # Init cache
    await init_redis()
    logger.info("Cache layer initialized (redis=%s)", bool(settings.REDIS_URL))

    # Load live threat feeds
    from app.services.threat_feeds import refresh_feeds
    try:
        feeds = await refresh_feeds()
        logger.info("Threat feeds loaded: %d total indicators", feeds.total_indicators)
    except Exception as e:
        logger.warning("Threat feed initial load failed (will retry on first request): %s", e)

    yield

    await close_redis()
    logger.info("SentinelX402 shutdown complete")


app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Cyber threat intelligence APIs for AI agents, paid via x402 micropayments",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# --- Middleware (order matters: last added = first executed) ---

# Rate limiting
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    max_age=86400,
)


# Security headers + request logging
@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    start = time.time()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled error: %s %s", request.method, request.url.path)
        response = JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": "An unexpected error occurred"},
        )

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"

    # Request logging + metrics (exclude admin paths)
    duration_ms = (time.time() - start) * 1000
    path = request.url.path
    if not path.startswith("/admin"):
        metrics.record(
            method=request.method,
            path=path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
    logger.info(
        "%s %s %d %.1fms",
        request.method,
        path,
        response.status_code,
        duration_ms,
    )

    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": "An unexpected error occurred"},
    )


# x402 payment middleware (conditional)
if settings.X402_ENABLED:
    try:
        from x402.http.middleware.fastapi import PaymentMiddlewareASGI
        from app.x402_setup import create_x402_server, get_routes_config

        server = create_x402_server()
        routes = get_routes_config()
        app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)
    except ImportError:
        import sys
        print("ERROR: x402 package not installed. Install with: pip install 'x402[fastapi,evm]'", file=sys.stderr)
        raise

# --- Discovery endpoints (for crawlers and agents) ---

@app.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
async def robots_txt():
    return "User-agent: *\nAllow: /\nSitemap: https://sentinelx402-production.up.railway.app/info\n"


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/sitemap.xml", response_class=PlainTextResponse, include_in_schema=False)
async def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://sentinelx402-production.up.railway.app/info</loc></url>
  <url><loc>https://sentinelx402-production.up.railway.app/docs</loc></url>
  <url><loc>https://sentinelx402-production.up.railway.app/stats</loc></url>
</urlset>"""


@app.get("/.well-known/security.txt", response_class=PlainTextResponse, include_in_schema=False)
async def security_txt():
    return "Contact: https://github.com/splitfireai-hue/sentinelx402/issues\nPreferred-Languages: en\n"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelX402 — Threat Intelligence API</title>
<meta name="description" content="Free threat intelligence API for AI agents. Real-time phishing detection, CVE risk analysis, IP reputation.">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:640px;padding:40px 24px;text-align:center}
h1{font-size:36px;font-weight:700;margin-bottom:8px;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.tagline{font-size:18px;color:#888;margin-bottom:32px}
.stats{display:flex;gap:24px;justify-content:center;margin-bottom:32px}
.stat{background:#161616;border:1px solid #222;border-radius:8px;padding:16px 24px}
.stat .num{font-size:24px;font-weight:700;color:#4ade80}
.stat .label{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}
.try{background:#161616;border:1px solid #222;border-radius:8px;padding:20px;margin-bottom:32px;text-align:left}
.try code{display:block;background:#0d0d0d;padding:12px;border-radius:4px;font-family:'SF Mono',Monaco,monospace;font-size:13px;color:#60a5fa;overflow-x:auto;margin-top:8px;word-break:break-all}
.try .label{font-size:13px;color:#888}
.links{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.links a{display:inline-block;padding:10px 24px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:600;transition:all .2s}
.primary{background:#3b82f6;color:#fff}
.primary:hover{background:#2563eb}
.secondary{background:#161616;color:#e0e0e0;border:1px solid #333}
.secondary:hover{background:#222}
.free{margin-top:24px;font-size:13px;color:#4ade80}
.footer{margin-top:32px;font-size:12px;color:#444}
.footer a{color:#666;text-decoration:none}
</style>
</head>
<body>
<div class="container">
<h1>SentinelX402</h1>
<p class="tagline">Detect malicious domains and IPs in under 300ms with 95% confidence</p>

<div class="stats">
<div class="stat"><div class="num">22K+</div><div class="label">Live Indicators</div></div>
<div class="stat"><div class="num">&lt;300ms</div><div class="label">Latency</div></div>
<div class="stat"><div class="num">FREE</div><div class="label">1,000 Requests</div></div>
</div>

<div class="try">
<span class="label">Try it now:</span>
<code>curl "https://sentinelx402-production.up.railway.app/api/v1/threats/lookup?domain=login-secure-paypal.com"</code>
</div>

<div class="links">
<a href="/docs" class="primary">API Docs</a>
<a href="/info" class="secondary">Endpoints</a>
<a href="/stats" class="secondary">Live Stats</a>
<a href="https://github.com/splitfireai-hue/sentinelx402" class="secondary">GitHub</a>
</div>

<p class="free">1,000 free requests — no signup, no API key, no credit card</p>

<div class="footer">
Powered by OpenPhish, Feodo Tracker, URLhaus, NVD
</div>
</div>
</body>
</html>"""


@app.get("/api", include_in_schema=False)
@app.get("/api/v1", include_in_schema=False)
async def api_root():
    return {"name": "SentinelX402", "docs": "/docs", "info": "/info"}


@app.get("/.well-known/mcp", include_in_schema=False)
async def well_known_mcp():
    return {
        "name": "SentinelX402",
        "url": "https://sentinelx402-production.up.railway.app",
        "metadata": "https://sentinelx402-production.up.railway.app/info",
        "mcp_config": "https://github.com/splitfireai-hue/sentinelx402/blob/main/mcp.json",
    }


@app.get("/.well-known/agent.json", include_in_schema=False)
async def well_known_agent():
    return {
        "name": "SentinelX402",
        "description": "Free threat intelligence API for AI agents. Real-time phishing detection, CVE risk analysis, IP reputation.",
        "url": "https://sentinelx402-production.up.railway.app",
        "capabilities": ["domain_risk_lookup", "ip_reputation", "threat_feed", "cve_risk_analysis", "recent_critical_cves", "cve_search"],
        "free_tier": {"requests": 1000, "signup_required": False},
        "docs": "https://sentinelx402-production.up.railway.app/docs",
    }


# --- Routers ---
app.include_router(admin.router)
app.include_router(health.router)
app.include_router(
    threat_feed.router,
    prefix="/api/v1/threats",
    tags=["Threat Intelligence"],
)
app.include_router(
    cve_intelligence.router,
    prefix="/api/v1/cves",
    tags=["CVE Intelligence"],
)
