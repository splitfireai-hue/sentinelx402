FROM python:3.11-slim AS builder

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install . && \
    pip install --no-cache-dir --prefix=/install gunicorn greenlet

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

# Remove dev files from image
RUN rm -rf tests/ .env .env.example .gitignore alembic/ docker-compose.dev.yml sdk/

# Writable data directory for SQLite
RUN mkdir -p /app/data && chmod 777 /app/data

# Defaults (Railway can override via env vars)
ENV PORT=8000
ENV DATABASE_URL=sqlite+aiosqlite:////app/data/sentinelx402.db
ENV ENVIRONMENT=production
ENV X402_ENABLED=false
ENV FREE_TIER_ENABLED=true

CMD python -m app.data.seed_threats && python -m gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --workers 2 --timeout 60 --access-logfile - --error-logfile -
