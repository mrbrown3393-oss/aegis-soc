from __future__ import annotations
import math, secrets
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from server import db, get_current_user, require_role, tenant_filter, write_audit

anomaly_router = APIRouter(prefix="/api/security", tags=["security-analytics"])

class TelemetryPoint(BaseModel):
    sensor_id: str = Field(min_length=1, max_length=128)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    timestamp: datetime
    signal_strength: float = Field(ge=0, le=1)
    source_ip: Optional[str] = Field(default=None, max_length=64)
    event_type: str = Field(min_length=1, max_length=100)

class QuarantineRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)

def _distance_km(a: TelemetryPoint, b: TelemetryPoint) -> float:
    r=6371.0
    p1,p2=math.radians(a.latitude),math.radians(b.latitude)
    dp=math.radians(b.latitude-a.latitude); dl=math.radians(b.longitude-a.longitude)
    h=math.sin(dp/2)**2+math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*r*math.asin(math.sqrt(h))

@anomaly_router.post("/telemetry/fuse")
async def fuse_telemetry(
    points: list[TelemetryPoint],
    request: Request,
    user: dict = Depends(require_role("owner", "admin", "analyst")),
):
    if not points: raise HTTPException(400, "At least one telemetry point is required")
    ids=[]
    for point in points:
        doc={"id":secrets.token_hex(12),"tenant":user["tenant"],"sensor_id":point.sensor_id,
             "latitude":point.latitude,"longitude":point.longitude,
             "timestamp":point.timestamp.astimezone(timezone.utc).isoformat(),
             "signal_strength":point.signal_strength,"source_ip":point.source_ip,
             "event_type":point.event_type,"created_at":datetime.now(timezone.utc).isoformat()}
        result=await db.security_telemetry.insert_one(doc); ids.append(str(result.inserted_id))
    weight=max(sum(p.signal_strength for p in points),1e-9)
    lat=sum(p.latitude*p.signal_strength for p in points)/weight
    lon=sum(p.longitude*p.signal_strength for p in points)/weight
    spread=max((_distance_km(points[0],p) for p in points[1:]),default=0.0)
    score=min(1.0,(len(points)/5)*0.35+(1-min(spread/1000,1))*0.25+(1-min(sum(p.signal_strength for p in points)/len(points),1))*0.4)
    await write_audit(user["email"],"telemetry_fusion","security_telemetry",request,user["tenant"])
    return {"event_ids":ids,"centroid":{"latitude":lat,"longitude":lon},"spread_km":round(spread,3),"anomaly_score":round(score,3)}

@anomaly_router.post("/quarantine")
async def quarantine_asset(body: QuarantineRequest, request: Request, user: dict = Depends(get_current_user)):
    if user["role"] not in ("owner","admin","analyst"): raise HTTPException(403,"Insufficient permissions")
    filt={"id":body.asset_id,**tenant_filter(user)}
    asset=await db.assets.find_one(filt)
    if not asset: raise HTTPException(404,"Asset not found")
    now=datetime.now(timezone.utc).isoformat()
    record={"id":secrets.token_hex(12),"asset_id":body.asset_id,"tenant":asset["tenant"],
            "status":"quarantine_requested","reason":body.reason,"severity":body.severity,
            "evidence_ids":body.evidence_ids,"requested_by":user["email"],"created_at":now,"auditable":True}
    await db.quarantine_actions.insert_one(record)
    await db.assets.update_one(filt,{"$set":{"security_state":"quarantine_requested","security_state_at":now}})
    await write_audit(user["email"],"asset_quarantine_requested",body.asset_id,request,asset["tenant"])
    record.pop("_id",None)
    return record

@anomaly_router.get("/quarantine")
async def list_quarantine(user: dict = Depends(get_current_user)):
    return await db.quarantine_actions.find(tenant_filter(user),{"_id":0}).sort("created_at",-1).to_list(200)
