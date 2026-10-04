"""Vulnerability listing and patch endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from database import db
from deps import get_current_user, require_role, tenant_filter, write_audit

router = APIRouter(tags=["vulnerabilities"])


@router.get("/vulnerabilities")
async def list_vulns(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.vulnerabilities.find(filt, {"_id": 0}).sort("cvss", -1).to_list(100)


@router.post("/vulnerabilities/{vuln_id}/patch")
async def patch_vuln(
    vuln_id: str,
    request: Request,
    user: dict = Depends(require_role("owner", "admin", "analyst")),
):
    filt = {"id": vuln_id, **tenant_filter(user)}
    result = await db.vulnerabilities.update_one(filt, {"$set": {"status": "patched"}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    await write_audit(user["email"], "vuln_patch", vuln_id, request, user.get("tenant", ""))
    return {"message": "Marked as patched", "id": vuln_id}
