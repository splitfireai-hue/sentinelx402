FROM python:3.11-slim AS builder

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install . && \
    pip install --no-cache-dir --prefix=/install gunicorn greenlet

FROM python:3.11-slim

# Security: non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -s /sbin/nologin sentinel

WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

# Remove dev files from image
RUN rm -rf tests/ .env .env.example .gitignore alembic/ docker-compose.dev.yml sdk/

RUN chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["python", "-m", "gunicorn", "app.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
