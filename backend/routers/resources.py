"""Assets, compliance, and audit-log endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from database import db
from deps import get_current_user, tenant_filter

router = APIRouter(tags=["resources"])


@router.get("/assets")
async def list_assets(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.assets.find(filt, {"_id": 0}).sort("risk_score", -1).to_list(100)


@router.get("/compliance")
async def list_compliance(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.compliance.find(filt, {"_id": 0}).to_list(50)


@router.get("/audit-logs")
async def list_audit_logs(
    tenant: Optional[str] = None,
    limit: int = Query(100, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    filt = tenant_filter(user, tenant)
    return await db.audit_logs.find(filt, {"_id": 0}).sort("created_at", -1).to_list(limit)
