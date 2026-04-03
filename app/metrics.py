"""Persistent metrics collection for admin dashboard.

Uses SQLite for persistence (survives restarts) with an in-memory
buffer for fast writes. Flushes to DB in batches.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Dict, List, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

IST_OFFSET = 19800  # UTC+5:30 in seconds


@dataclass
class RequestLog:
    timestamp: float
    method: str
    path: str
    status_code: int
    duration_ms: float
    client_id: str


class MetricsCollector:
    """Collects metrics in memory and flushes to DB periodically."""

    def __init__(self, max_logs: int = 5000):
        self._lock = Lock()
        self._started_at = time.time()
        self._logs: deque = deque(maxlen=max_logs)
        self._pending_writes: List[RequestLog] = []
        self._endpoint_latencies: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._session_requests = 0  # requests since last restart

    def record(self, method: str, path: str, status_code: int, duration_ms: float, client_id: str = "") -> None:
        with self._lock:
            self._session_requests += 1
            self._endpoint_latencies[path].append(duration_ms)

            log = RequestLog(
                timestamp=time.time(),
                method=method,
                path=path,
                status_code=status_code,
                duration_ms=round(duration_ms, 1),
                client_id=client_id,
            )
            self._logs.append(log)
            self._pending_writes.append(log)

    def get_pending_writes(self) -> List[RequestLog]:
        """Get and clear pending writes for DB flush."""
        with self._lock:
            writes = self._pending_writes.copy()
            self._pending_writes.clear()
            return writes

    def get_latency_stats(self) -> dict:
        """Get in-memory latency stats (current session only)."""
        with self._lock:
            stats = {}
            for path, latencies in self._endpoint_latencies.items():
                if latencies:
                    sorted_lat = sorted(latencies)
                    stats[path] = {
                        "avg_ms": round(sum(sorted_lat) / len(sorted_lat), 1),
                        "p50_ms": round(sorted_lat[len(sorted_lat) // 2], 1),
                        "p95_ms": round(sorted_lat[int(len(sorted_lat) * 0.95)], 1) if len(sorted_lat) >= 2 else round(sorted_lat[-1], 1),
                        "max_ms": round(sorted_lat[-1], 1),
                    }
            return stats

    def get_recent_logs_from_memory(self, limit: int = 50) -> list:
        """Get recent logs from in-memory buffer (fast, current session)."""
        with self._lock:
            logs = list(self._logs)[-limit:]
            logs.reverse()
            return [
                {
                    "time": time.strftime("%H:%M:%S", time.gmtime(log.timestamp + IST_OFFSET)),
                    "method": log.method,
                    "path": log.path,
                    "status": log.status_code,
                    "ms": log.duration_ms,
                    "client": log.client_id[:20] if log.client_id else "",
                }
                for log in logs
            ]

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._started_at


# Global singleton
metrics = MetricsCollector()


async def flush_metrics_to_db(db: AsyncSession) -> int:
    """Flush pending metrics from memory to database. Returns count flushed."""
    from app.models.metrics import HourlyStats, RequestMetric

    pending = metrics.get_pending_writes()
    if not pending:
        return 0

    hourly_updates: Dict[str, int] = defaultdict(int)

    for log in pending:
        # Insert request metric
        record = RequestMetric(
            timestamp=datetime.utcfromtimestamp(log.timestamp),
            method=log.method,
            path=log.path,
            status_code=log.status_code,
            duration_ms=log.duration_ms,
            client_id=log.client_id,
        )
        db.add(record)

        # Aggregate hourly
        hour_key = time.strftime("%Y-%m-%d %H", time.gmtime(log.timestamp + IST_OFFSET))
        hourly_updates[hour_key] += 1

    # Upsert hourly stats
    for hour_key, count in hourly_updates.items():
        result = await db.execute(
            select(HourlyStats).where(HourlyStats.hour_key == hour_key)
        )
        hourly = result.scalar_one_or_none()
        if hourly:
            hourly.request_count += count
        else:
            db.add(HourlyStats(hour_key=hour_key, request_count=count))

    await db.commit()
    return len(pending)


async def get_db_summary(db: AsyncSession) -> dict:
    """Get full metrics summary from database (survives restarts)."""
    from app.models.metrics import RequestMetric

    # Total requests all time
    total_q = await db.execute(select(func.count(RequestMetric.id)))
    total_requests = total_q.scalar_one()

    # Status code breakdown
    status_q = await db.execute(
        select(RequestMetric.status_code, func.count(RequestMetric.id))
        .group_by(RequestMetric.status_code)
    )
    status_codes = {str(row[0]): row[1] for row in status_q.all()}

    # Error rate
    error_count = sum(c for s, c in status_codes.items() if int(s) >= 400)
    error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0

    # Endpoint stats from DB
    endpoint_q = await db.execute(
        select(
            RequestMetric.path,
            func.count(RequestMetric.id),
            func.avg(RequestMetric.duration_ms),
        )
        .group_by(RequestMetric.path)
    )
    # Error counts per endpoint
    error_q = await db.execute(
        select(RequestMetric.path, func.count(RequestMetric.id))
        .where(RequestMetric.status_code >= 400)
        .group_by(RequestMetric.path)
    )
    error_counts = {row[0]: row[1] for row in error_q.all()}

    endpoint_stats = {}
    latency_stats = metrics.get_latency_stats()
    for row in endpoint_q.all():
        path = row[0]
        mem_stats = latency_stats.get(path, {})
        endpoint_stats[path] = {
            "calls": row[1],
            "errors": error_counts.get(path, 0),
            "avg_ms": round(row[2], 1) if row[2] else 0,
            "p50_ms": mem_stats.get("p50_ms", 0),
            "p95_ms": mem_stats.get("p95_ms", 0),
            "max_ms": mem_stats.get("max_ms", 0),
        }

    # First request timestamp (for true uptime)
    first_q = await db.execute(
        select(func.min(RequestMetric.timestamp))
    )
    first_request = first_q.scalar_one()

    return {
        "uptime_seconds": round(metrics.uptime_seconds),
        "tracking_since": first_request.isoformat() if first_request else None,
        "total_requests": total_requests,
        "error_rate_percent": round(error_rate, 2),
        "status_codes": status_codes,
        "endpoints": endpoint_stats,
    }


async def get_db_hourly(db: AsyncSession) -> dict:
    """Get hourly traffic from database."""
    from app.models.metrics import HourlyStats

    result = await db.execute(
        select(HourlyStats.hour_key, HourlyStats.request_count)
        .order_by(desc(HourlyStats.hour_key))
        .limit(48)
    )
    rows = result.all()
    rows.reverse()
    return {row[0]: row[1] for row in rows}


async def get_db_recent_logs(db: AsyncSession, limit: int = 50) -> list:
    """Get recent request logs from database."""
    from app.models.metrics import RequestMetric

    result = await db.execute(
        select(RequestMetric)
        .order_by(desc(RequestMetric.timestamp))
        .limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "time": time.strftime("%H:%M:%S", time.gmtime(log.timestamp.timestamp() + IST_OFFSET)) if log.timestamp else "",
            "method": log.method,
            "path": log.path,
            "status": log.status_code,
            "ms": log.duration_ms,
            "client": log.client_id[:20] if log.client_id else "",
        }
        for log in logs
    ]


async def get_db_recent_errors(db: AsyncSession, limit: int = 20) -> list:
    """Get recent errors from database."""
    from app.models.metrics import RequestMetric

    result = await db.execute(
        select(RequestMetric)
        .where(RequestMetric.status_code >= 400)
        .order_by(desc(RequestMetric.timestamp))
        .limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "time": time.strftime("%H:%M:%S", time.gmtime(log.timestamp.timestamp() + IST_OFFSET)) if log.timestamp else "",
            "path": log.path,
            "status": log.status_code,
            "ms": log.duration_ms,
        }
        for log in logs
    ]
