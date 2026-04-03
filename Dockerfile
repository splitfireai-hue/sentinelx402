FROM python:3.11-slim AS builder

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install . && \
    pip install --no-cache-dir --prefix=/install gunicorn greenlet asyncpg && \
    pip install --no-cache-dir --prefix=/install "x402[fastapi,evm]" || true

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

# Remove dev files from image
RUN rm -rf tests/ .env .env.example .gitignore alembic/ docker-compose.dev.yml sdk/

# Defaults (Railway overrides DATABASE_URL with PostgreSQL)
ENV PORT=8000
ENV DATABASE_URL=sqlite+aiosqlite:////app/data/sentinelx402.db
ENV ENVIRONMENT=production
ENV X402_ENABLED=false
ENV WALLET_ADDRESS=0x37E59eeF69A26Bf790434f8d28AF68817E30Ec8A
ENV NETWORK_ID=eip155:8453
ENV FREE_TIER_ENABLED=true
ENV FREE_TIER_REQUESTS=1000
ENV ADMIN_SECRET=""

CMD python -m app.data.seed_threats && python -m gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --workers 2 --timeout 60 --access-logfile - --error-logfile -
