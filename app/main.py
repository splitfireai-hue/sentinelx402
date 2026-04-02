from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
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


@app.get("/", include_in_schema=False)
@app.get("/api", include_in_schema=False)
@app.get("/api/v1", include_in_schema=False)
async def api_root():
    return {"name": "SentinelX402", "tagline": "Detect malicious domains and IPs in under 300ms", "docs": "/docs", "info": "/info", "health": "/health"}


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
        "description": "Real-time phishing detection and CVE risk analysis API for AI agents",
        "url": "https://sentinelx402-production.up.railway.app",
        "capabilities": ["domain_risk_lookup", "ip_reputation", "threat_feed", "cve_risk_analysis", "recent_critical_cves", "cve_search"],
        "payment": {"protocol": "x402", "currency": "USDC", "network": "Base"},
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
