"""Overview metrics endpoints."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends

from database import db
from deps import get_current_user, tenant_filter

router = APIRouter(tags=["metrics"])


@router.get("/metrics/overview")
async def metrics_overview(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    total_threats = await db.threats.count_documents(filt)
    open_incidents = await db.incidents.count_documents({**filt, "status": {"$ne": "resolved"}})
    critical = await db.threats.count_documents({**filt, "severity": "critical"})
    high = await db.threats.count_documents({**filt, "severity": "high"})

    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    trend_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()

    cursor = db.threats.find(
        filt,
        {"timestamp": 1, "severity": 1, "_id": 0},
    )
    async for threat in cursor:
        severity = threat.get("severity")
        if isinstance(severity, str) and severity:
            severity_counts[severity] += 1

        timestamp = threat.get("timestamp")
        if isinstance(timestamp, str) and timestamp >= since:
            day = timestamp[:10]
            if len(day) == 10:
                trend_counts[day] += 1

    trend = [
        {"_id": day, "count": count}
        for day, count in sorted(trend_counts.items())
    ]

    return {
        "total_threats": total_threats,
        "open_incidents": open_incidents,
        "critical": critical,
        "high": high,
        "trend": trend,
        "severity_distribution": dict(severity_counts),
    }
