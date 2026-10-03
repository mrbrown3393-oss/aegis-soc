"""
Aegis SOC — security operations API: tracing + quarantine.

Mounted by backend/security_setup.py. Role rules:
  - Tracing: any authenticated analyst+ (tenant-scoped via tenant_filter)
  - Quarantine / release / review: owner/admin only (+ PEP step-up on mutations)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .threat_tracer import ThreatTracer
from .quarantine import QuarantineEngine


class TraceRequest(BaseModel):
    source_ip: Optional[str] = None
    asset_id: Optional[str] = None
    technique: Optional[str] = None
    account: Optional[str] = None
    lookback_hours: int = Field(default=336, ge=1, le=8760)


class QuarantineRequest(BaseModel):
    action: str
    target: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)
    trace_id: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    auto: bool = False


def build_security_router(db, get_current_user, require_role, tenant_filter, write_audit) -> APIRouter:
    router = APIRouter(prefix="/api/security", tags=["security-ops"])
    tracer = ThreatTracer(db)
    engine = QuarantineEngine(db)

    @router.post("/trace")
    async def run_trace(body: TraceRequest, request: Request, user: dict = Depends(get_current_user)):
        result = await tracer.trace(
            tenant_filter=tenant_filter(user),
            source_ip=body.source_ip,
            asset_id=body.asset_id,
            technique=body.technique,
            account=body.account,
            lookback_hours=body.lookback_hours,
        )
        await write_audit(user["email"], "threat_trace", result["id"], request, user["tenant"])

        # Zero-trust loop: auto-quarantine on very high confidence
        auto_actions = []
        if result["summary"]["confidence"] >= 0.9:
            for ip in result["summary"]["unique_source_ips"]:
                try:
                    rec = await engine.quarantine(
                        action="block_ip", target=ip, tenant=user["tenant"],
                        reason=f"Auto: trace {result['id']} confidence {result['summary']['confidence']}",
                        actor="aegis-automation", trace_id=result["id"],
                        confidence=result["summary"]["confidence"], auto=True,
                    )
                    auto_actions.append(rec)
                except ValueError:
                    pass
            if auto_actions:
                await write_audit("aegis-automation", "auto_quarantine",
                                  ",".join(r["id"] for r in auto_actions), request, user["tenant"])

        return {"trace": result, "auto_quarantines": auto_actions}

    @router.get("/traces")
    async def list_traces(user: dict = Depends(get_current_user)):
        return await db.threat_traces.find(tenant_filter(user), {"_id": 0, "graph": 0}).sort("created_at", -1).to_list(100)

    @router.get("/quarantines")
    async def list_quarantines(user: dict = Depends(get_current_user)):
        return await db.quarantines.find(tenant_filter(user), {"_id": 0}).sort("created_at", -1).to_list(100)

    @router.post("/quarantine")
    async def quarantine(body: QuarantineRequest, request: Request,
                         user: dict = Depends(require_role("owner", "admin"))):
        try:
            rec = await engine.quarantine(
                action=body.action, target=body.target, tenant=user["tenant"],
                reason=body.reason, actor=user["email"], trace_id=body.trace_id,
                confidence=body.confidence, auto=body.auto,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        await write_audit(user["email"], "quarantine", rec["id"], request, user["tenant"])
        return rec

    @router.post("/quarantine/{quarantine_id}/release")
    async def release(quarantine_id: str, request: Request,
                      user: dict = Depends(require_role("owner", "admin"))):
        try:
            rec = await engine.release(quarantine_id=quarantine_id, actor=user["email"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        await write_audit(user["email"], "quarantine_release", quarantine_id, request, user["tenant"])
        return rec

    @router.post("/quarantine/{quarantine_id}/review")
    async def review(quarantine_id: str, request: Request,
                     user: dict = Depends(require_role("owner", "admin"))):
        await engine.mark_reviewed(quarantine_id=quarantine_id, reviewer=user["email"])
        await write_audit(user["email"], "quarantine_review", quarantine_id, request, user["tenant"])
        return {"message": "Reviewed"}

    return router
