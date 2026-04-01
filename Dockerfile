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

# Ensure writable data directory for SQLite
RUN mkdir -p /app/data && chmod 777 /app/data

ENV PORT=8000

# Railway overrides CMD via startCommand in railway.toml
CMD python -m app.data.seed_threats && python -m gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --workers 2 --timeout 30 --access-logfile - --error-logfile -
