from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.cache import close_redis, init_redis
from app.config import settings, setup_logging
from app.database import engine
from app.models import Base
from app.routers import cve_intelligence, health, threat_feed

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

    yield

    await close_redis()
    logger.info("SentinelX402 shutdown complete")


app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Cyber threat intelligence APIs for AI agents, paid via x402 micropayments",
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
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

    # Request logging
    duration_ms = (time.time() - start) * 1000
    logger.info(
        "%s %s %d %.1fms",
        request.method,
        request.url.path,
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

# --- Routers ---
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
