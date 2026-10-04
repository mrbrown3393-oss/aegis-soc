"""Threat listing and live simulation endpoints."""
from __future__ import annotations

import secrets
import random
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query

from database import db
from deps import get_current_user, require_role, tenant_filter

router = APIRouter(tags=["threats"])


@router.get("/threats")
async def list_threats(
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    tenant: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    filt = tenant_filter(user, tenant)
    if severity:
        filt["severity"] = severity
    return await db.threats.find(filt, {"_id": 0}).sort("timestamp", -1).to_list(limit)


@router.get("/threats/live")
async def threats_live(user: dict = Depends(require_role("owner", "admin", "analyst"))):
    """Simulates & inserts a new live threat (demo telemetry)."""
    now = datetime.now(timezone.utc)
    threat = {
        "id": secrets.token_hex(8),
        "tenant": user["tenant"],
        "severity": secrets.choice(["critical", "high", "medium", "low"]),
        "title": f"Live simulated event {secrets.token_hex(4)}",
        "description": "Simulated live telemetry — not a real attack.",
        "source_ip": f"{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}",
        "geo": secrets.choice(["RU", "CN", "KP", "IR", "US", "DE"]),
        "confidence": round(random.uniform(0.5, 0.99), 2),
        "affected_asset": f"asset-{secrets.randbelow(60)+1:03d}",
        "timestamp": now.isoformat(),
    }
    await db.threats.insert_one(threat)
    threat.pop("_id", None)
    return threat
