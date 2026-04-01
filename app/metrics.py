"""In-memory metrics collection for admin dashboard."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List


@dataclass
class RequestLog:
    timestamp: float
    method: str
    path: str
    status_code: int
    duration_ms: float
    client_id: str


class MetricsCollector:
    """Collects request-level metrics in memory. Not persistent — resets on restart."""

    def __init__(self, max_logs: int = 5000):
        self._lock = Lock()
        self._started_at = time.time()
        self._logs: deque = deque(maxlen=max_logs)
        self._endpoint_counts: Dict[str, int] = defaultdict(int)
        self._endpoint_errors: Dict[str, int] = defaultdict(int)
        self._endpoint_latencies: Dict[str, List[float]] = defaultdict(lambda: deque(maxlen=200))
        self._status_counts: Dict[int, int] = defaultdict(int)
        self._total_requests = 0
        self._hourly_counts: Dict[str, int] = defaultdict(int)  # "YYYY-MM-DD HH" -> count

    def record(self, method: str, path: str, status_code: int, duration_ms: float, client_id: str = "") -> None:
        with self._lock:
            self._total_requests += 1
            self._endpoint_counts[path] += 1
            self._status_counts[status_code] += 1
            self._endpoint_latencies[path].append(duration_ms)

            if status_code >= 400:
                self._endpoint_errors[path] += 1

            hour_key = time.strftime("%Y-%m-%d %H", time.gmtime())
            self._hourly_counts[hour_key] += 1

            self._logs.append(RequestLog(
                timestamp=time.time(),
                method=method,
                path=path,
                status_code=status_code,
                duration_ms=round(duration_ms, 1),
                client_id=client_id,
            ))

    def get_summary(self) -> dict:
        with self._lock:
            uptime = time.time() - self._started_at

            # Calculate latency stats per endpoint
            endpoint_stats = {}
            for path, latencies in self._endpoint_latencies.items():
                if latencies:
                    sorted_lat = sorted(latencies)
                    endpoint_stats[path] = {
                        "calls": self._endpoint_counts.get(path, 0),
                        "errors": self._endpoint_errors.get(path, 0),
                        "avg_ms": round(sum(sorted_lat) / len(sorted_lat), 1),
                        "p50_ms": round(sorted_lat[len(sorted_lat) // 2], 1),
                        "p95_ms": round(sorted_lat[int(len(sorted_lat) * 0.95)], 1) if len(sorted_lat) >= 2 else round(sorted_lat[-1], 1),
                        "max_ms": round(sorted_lat[-1], 1),
                    }

            # Error rate
            error_count = sum(c for s, c in self._status_counts.items() if s >= 400)
            error_rate = (error_count / self._total_requests * 100) if self._total_requests > 0 else 0

            # Requests per minute
            rpm = (self._total_requests / uptime * 60) if uptime > 0 else 0

            return {
                "uptime_seconds": round(uptime),
                "total_requests": self._total_requests,
                "requests_per_minute": round(rpm, 2),
                "error_rate_percent": round(error_rate, 2),
                "status_codes": dict(self._status_counts),
                "endpoints": endpoint_stats,
            }

    def get_hourly_traffic(self) -> dict:
        with self._lock:
            # Last 24 entries
            items = sorted(self._hourly_counts.items())[-24:]
            return {k: v for k, v in items}

    def get_recent_logs(self, limit: int = 50) -> list:
        with self._lock:
            logs = list(self._logs)[-limit:]
            logs.reverse()
            return [
                {
                    "time": time.strftime("%H:%M:%S", time.gmtime(log.timestamp)),
                    "method": log.method,
                    "path": log.path,
                    "status": log.status_code,
                    "ms": log.duration_ms,
                    "client": log.client_id[:20] if log.client_id else "",
                }
                for log in logs
            ]

    def get_recent_errors(self, limit: int = 20) -> list:
        with self._lock:
            errors = [l for l in self._logs if l.status_code >= 400]
            errors = list(errors)[-limit:]
            errors.reverse()
            return [
                {
                    "time": time.strftime("%H:%M:%S", time.gmtime(log.timestamp)),
                    "path": log.path,
                    "status": log.status_code,
                    "ms": log.duration_ms,
                }
                for log in errors
            ]


# Global singleton
metrics = MetricsCollector()
