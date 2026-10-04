"""Incident listing and status update endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from database import db
from deps import get_current_user, require_role, tenant_filter, write_audit
from step_up import require_step_up
from models import IncidentUpdate

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
async def list_incidents(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.incidents.find(filt, {"_id": 0}).sort("created_at", -1).to_list(100)


@router.patch("/incidents/{incident_id}")
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    request: Request,
    user: dict = Depends(require_step_up),
):
    filt = {"id": incident_id, **tenant_filter(user)}
    result = await db.incidents.update_one(
        filt,
        {"$set": {"status": body.status, "updated_at": datetime.now(timezone.utc).isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await write_audit(user["email"], "incident_update", incident_id, request, user.get("tenant", ""))
    return {"message": "Incident updated", "id": incident_id, "status": body.status}
