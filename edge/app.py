"""Aegis SOC remote security edge admission service."""
from __future__ import annotations
import ipaddress, os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from edge.policy import EdgePolicy

app = FastAPI(title="Aegis SOC Security Edge", version="1.1.0")
policy = EdgePolicy()

class AdmissionRequest(BaseModel):
    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2048)
    client_ip: str = Field(min_length=1, max_length=64)

class AdmissionResponse(BaseModel):
    allow: bool
    risk_score: int
    reason: str
    decision_id: str
    issued_at: int
    expires_at: int
    method: str
    path: str
    client_ip: str
    audience: str
    nonce: str
    signature: str

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/v1/admission", response_model=AdmissionResponse)
async def admission(payload: AdmissionRequest, authorization: str | None = Header(default=None)) -> AdmissionResponse:
    expected_token = os.getenv("EDGE_INGRESS_TOKEN", "")
    if expected_token and authorization != f"Bearer {expected_token}":
        raise HTTPException(status_code=401, detail="Edge caller authentication failed")
    try:
        ipaddress.ip_address(payload.client_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid client IP") from exc
    decision = policy.decide(method=payload.method, path=payload.path, client_key=payload.client_ip)
    return AdmissionResponse(**decision.__dict__)
