"""Admin dashboard — private, password-protected, founder-only."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.metrics import metrics
from app.models.threat import ThreatIndicator
from app.models.usage import UsageRecord
from app.services.threat_feeds import get_cache as get_feed_cache

router = APIRouter(tags=["Admin"])


def _require_admin(key: str = Query(..., alias="key")) -> None:
    """Simple secret key auth for admin endpoints."""
    if not settings.ADMIN_SECRET:
        raise HTTPException(status_code=404, detail="Not found")
    if key != settings.ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _auth=Depends(_require_admin),
):
    """Full admin dashboard UI."""
    summary = metrics.get_summary()
    hourly = metrics.get_hourly_traffic()
    recent = metrics.get_recent_logs(limit=30)
    errors = metrics.get_recent_errors(limit=15)
    feed_cache = get_feed_cache()

    # DB stats
    db_count = await db.execute(select(func.count(ThreatIndicator.id)))
    db_total = db_count.scalar_one()
    client_count = await db.execute(select(func.count(UsageRecord.id)))
    total_clients = client_count.scalar_one()
    total_req = await db.execute(select(func.sum(UsageRecord.request_count)))
    total_requests_db = total_req.scalar_one() or 0

    # Top clients
    top_clients_q = await db.execute(
        select(UsageRecord.client_id, UsageRecord.request_count)
        .order_by(UsageRecord.request_count.desc())
        .limit(10)
    )
    top_clients = [{"id": r[0], "requests": r[1]} for r in top_clients_q.all()]

    uptime_h = summary["uptime_seconds"] / 3600
    feed_age = round(time.time() - feed_cache.last_updated) if feed_cache.last_updated else None

    # Build endpoint rows
    endpoint_rows = ""
    for path, stats in sorted(summary["endpoints"].items()):
        err_class = "red" if stats["errors"] > 0 else "green"
        endpoint_rows += "<tr><td>{}</td><td>{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            path, stats["calls"], err_class, stats["errors"],
            stats["avg_ms"], stats["p95_ms"], stats["max_ms"]
        )

    # Build recent logs rows
    log_rows = ""
    for log in recent:
        status_class = "green" if log["status"] < 400 else "red"
        log_rows += "<tr><td>{}</td><td>{}</td><td class='{}'>{}</td><td>{}</td></tr>".format(
            log["time"], log["path"], status_class, log["status"], log["ms"]
        )

    # Build error rows
    error_rows = ""
    for err in errors:
        error_rows += "<tr><td>{}</td><td>{}</td><td class='red'>{}</td><td>{}</td></tr>".format(
            err["time"], err["path"], err["status"], err["ms"]
        )
    if not error_rows:
        error_rows = "<tr><td colspan='4' style='text-align:center;color:#666'>No errors</td></tr>"

    # Build hourly chart data
    chart_labels = list(hourly.keys())[-12:]
    chart_values = [hourly.get(k, 0) for k in chart_labels]
    chart_labels_short = [k.split(" ")[1] + ":00" for k in chart_labels]

    # Top clients rows
    client_rows = ""
    for c in top_clients:
        client_rows += "<tr><td>{}</td><td>{}</td></tr>".format(c["id"][:30], c["requests"])
    if not client_rows:
        client_rows = "<tr><td colspan='2' style='text-align:center;color:#666'>No clients yet</td></tr>"

    # Status codes
    status_pills = ""
    for code, count in sorted(summary["status_codes"].items()):
        color = "#4ade80" if int(code) < 400 else "#f87171"
        status_pills += "<span class='pill' style='background:{}'>{}:{}</span> ".format(color, code, count)

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelX402 Admin</title>
<meta name="robots" content="noindex,nofollow">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:20px}}
h1{{font-size:24px;margin-bottom:4px}}
h2{{font-size:16px;color:#888;margin-bottom:20px;font-weight:normal}}
h3{{font-size:14px;color:#aaa;margin:20px 0 10px;text-transform:uppercase;letter-spacing:1px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:#161616;border:1px solid #222;border-radius:8px;padding:16px}}
.card .label{{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.5px}}
.card .value{{font-size:28px;font-weight:700;margin-top:4px}}
.card .sub{{font-size:12px;color:#666;margin-top:2px}}
.green{{color:#4ade80}}
.red{{color:#f87171}}
.yellow{{color:#fbbf24}}
.blue{{color:#60a5fa}}
.purple{{color:#a78bfa}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px}}
th{{text-align:left;padding:8px 12px;background:#161616;color:#888;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #222}}
td{{padding:6px 12px;border-bottom:1px solid #1a1a1a}}
tr:hover{{background:#1a1a1a}}
.pill{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;color:#000;font-weight:600}}
.two-col{{display:grid;grid-template-columns:2fr 1fr;gap:20px}}
.bar-chart{{display:flex;align-items:flex-end;gap:4px;height:80px;margin-top:8px}}
.bar{{background:#3b82f6;border-radius:2px 2px 0 0;min-width:20px;flex:1;position:relative}}
.bar:hover{{background:#60a5fa}}
.bar-label{{font-size:9px;color:#666;text-align:center;margin-top:4px}}
.section{{background:#161616;border:1px solid #222;border-radius:8px;padding:16px;margin-bottom:20px}}
.refresh{{color:#666;font-size:12px;margin-top:10px}}
.refresh a{{color:#3b82f6;text-decoration:none}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr}}.grid{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<h1>SentinelX402 Admin</h1>
<h2>Private dashboard — real-time system overview</h2>

<div class="grid">
  <div class="card">
    <div class="label">Uptime</div>
    <div class="value blue">{uptime_h:.1f}h</div>
    <div class="sub">{uptime_s:,}s</div>
  </div>
  <div class="card">
    <div class="label">Total Requests</div>
    <div class="value green">{total_req}</div>
    <div class="sub">{rpm:.1f} req/min</div>
  </div>
  <div class="card">
    <div class="label">Error Rate</div>
    <div class="value {err_class}">{error_rate}%</div>
    <div class="sub">{status_pills}</div>
  </div>
  <div class="card">
    <div class="label">Clients</div>
    <div class="value purple">{total_clients}</div>
    <div class="sub">{total_requests_db} total API calls</div>
  </div>
  <div class="card">
    <div class="label">Live Feed Indicators</div>
    <div class="value blue">{feed_total:,}</div>
    <div class="sub">refreshed {feed_age}s ago</div>
  </div>
  <div class="card">
    <div class="label">Local IOCs</div>
    <div class="value">{db_total}</div>
    <div class="sub">seeded dataset</div>
  </div>
</div>

<h3>Feed Status</h3>
<div class="grid" style="grid-template-columns:repeat(3,1fr)">
  <div class="card">
    <div class="label">OpenPhish</div>
    <div class="value green">{openphish}</div>
    <div class="sub">phishing URLs</div>
  </div>
  <div class="card">
    <div class="label">Feodo Tracker</div>
    <div class="value green">{feodo}</div>
    <div class="sub">C2 IPs</div>
  </div>
  <div class="card">
    <div class="label">URLhaus</div>
    <div class="value green">{urlhaus}</div>
    <div class="sub">malware URLs</div>
  </div>
</div>

<div class="two-col">
  <div>
    <h3>Endpoint Performance</h3>
    <div class="section">
      <table>
        <tr><th>Endpoint</th><th>Calls</th><th>Errors</th><th>Avg ms</th><th>P95 ms</th><th>Max ms</th></tr>
        {endpoint_rows}
      </table>
    </div>

    <h3>Recent Requests</h3>
    <div class="section">
      <table>
        <tr><th>Time (IST)</th><th>Path</th><th>Status</th><th>Latency</th></tr>
        {log_rows}
      </table>
    </div>
  </div>

  <div>
    <h3>Hourly Traffic</h3>
    <div class="section">
      <div class="bar-chart">
        {bar_chart}
      </div>
      <div style="display:flex;gap:4px;margin-top:4px">
        {bar_labels}
      </div>
    </div>

    <h3>Top Clients</h3>
    <div class="section">
      <table>
        <tr><th>Client</th><th>Requests</th></tr>
        {client_rows}
      </table>
    </div>

    <h3>Recent Errors</h3>
    <div class="section">
      <table>
        <tr><th>Time</th><th>Path</th><th>Status</th><th>ms</th></tr>
        {error_rows}
      </table>
    </div>
  </div>
</div>

<div class="refresh">
  Auto-refreshes disabled. <a href="?key={admin_key}">Refresh now</a> |
  <a href="?key={admin_key}" target="_blank">Open in new tab</a>
</div>

</body>
</html>"""

    # Build bar chart
    max_val = max(chart_values) if chart_values else 1
    bar_chart = ""
    bar_labels = ""
    for i, val in enumerate(chart_values):
        height = max(int(val / max_val * 70), 2) if max_val > 0 else 2
        bar_chart += "<div class='bar' style='height:{}px' title='{}: {} requests'></div>".format(
            height, chart_labels_short[i], val
        )
        bar_labels += "<div class='bar-label' style='flex:1;min-width:20px'>{}</div>".format(
            chart_labels_short[i] if i % 2 == 0 else ""
        )

    return html.format(
        uptime_h=uptime_h,
        uptime_s=summary["uptime_seconds"],
        total_req=summary["total_requests"],
        rpm=summary["requests_per_minute"],
        error_rate=summary["error_rate_percent"],
        err_class="green" if summary["error_rate_percent"] < 5 else "red",
        status_pills=status_pills,
        total_clients=total_clients,
        total_requests_db=total_requests_db,
        feed_total=feed_cache.total_indicators,
        feed_age=feed_age if feed_age else "N/A",
        db_total=db_total,
        openphish=feed_cache.feed_stats.get("openphish_urls", 0),
        feodo=feed_cache.feed_stats.get("feodo_c2_ips", 0),
        urlhaus=feed_cache.feed_stats.get("urlhaus_malware_urls", 0),
        endpoint_rows=endpoint_rows if endpoint_rows else "<tr><td colspan='6' style='text-align:center;color:#666'>No requests yet</td></tr>",
        log_rows=log_rows if log_rows else "<tr><td colspan='4' style='text-align:center;color:#666'>No requests yet</td></tr>",
        error_rows=error_rows,
        bar_chart=bar_chart if bar_chart else "<div style='color:#666'>No traffic data yet</div>",
        bar_labels=bar_labels,
        client_rows=client_rows,
        admin_key=settings.ADMIN_SECRET,
    )


@router.get("/admin/api/metrics")
async def admin_metrics(_auth=Depends(_require_admin)):
    """Raw metrics JSON for programmatic access."""
    return metrics.get_summary()


@router.get("/admin/api/logs")
async def admin_logs(
    limit: int = Query(50, ge=1, le=200),
    _auth=Depends(_require_admin),
):
    """Recent request logs."""
    return metrics.get_recent_logs(limit=limit)
