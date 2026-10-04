"""Overview metrics endpoints."""
from __future__ import annotations

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
    trend = await db.threats.aggregate([
        {"$match": {**filt, "timestamp": {"$gte": since}}},
        {"$group": {"_id": {"$substr": ["$timestamp", 0, 10]}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]).to_list(10)
    sev_dist = await db.threats.aggregate([
        {"$match": filt}, {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]).to_list(10)
    return {
        "total_threats": total_threats,
        "open_incidents": open_incidents,
        "critical": critical,
        "high": high,
        "trend": trend,
        "severity_distribution": {d["_id"]: d["count"] for d in sev_dist},
    }
