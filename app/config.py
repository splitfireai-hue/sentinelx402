from __future__ import annotations

import logging
from typing import List, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:////app/data/sentinelx402.db"

    # Redis (optional — leave empty to use in-memory cache)
    REDIS_URL: str = ""

    # x402 Payment
    WALLET_ADDRESS: str = "0x0000000000000000000000000000000000000000"
    FACILITATOR_URL: str = "https://x402.org/facilitator"
    NETWORK_ID: str = "eip155:84532"
    X402_ENABLED: bool = False

    # NVD
    NVD_API_KEY: str = ""

    # App
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    ALLOWED_ORIGINS: str = ""  # comma-separated, e.g. "https://example.com,https://app.example.com"
    API_TITLE: str = "SentinelX402"
    API_VERSION: str = "0.1.0"

    # Rate Limiting
    THREAT_RATE_LIMIT: str = "60/minute"
    CVE_RATE_LIMIT: str = "30/minute"

    # Free Tier
    FREE_TIER_ENABLED: bool = True
    FREE_TIER_REQUESTS: int = 1000  # free requests per client

    # Admin Dashboard
    ADMIN_SECRET: str = ""  # set in env to enable admin dashboard

    # Timeouts
    NVD_TIMEOUT_SECONDS: int = 15

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def origins_list(self) -> List[str]:
        if not self.ALLOWED_ORIGINS:
            return ["*"] if not self.is_production else []
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "env_ignore_empty": True}


settings = Settings()


def setup_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
