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

def _authorize_ingress(authorization: str | None) -> None:
    """Require the shared ingress credential when configured."""
    expected_token = os.getenv("EDGE_INGRESS_TOKEN", "")
    if expected_token and authorization != f"Bearer {expected_token}":
        raise HTTPException(status_code=401, detail="Edge caller authentication failed")


def _client_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid client IP") from exc
    return value


@app.post("/v1/admission", response_model=AdmissionResponse)
async def admission(payload: AdmissionRequest, authorization: str | None = Header(default=None)) -> AdmissionResponse:
    _authorize_ingress(authorization)
    _client_ip(payload.client_ip)
    decision = policy.decide(method=payload.method, path=payload.path, client_key=payload.client_ip)
    return AdmissionResponse(**decision.__dict__)


@app.get("/v1/authz")
async def authz(
    x_original_method: str = Header(default="GET"),
    x_original_uri: str = Header(default="/"),
    x_client_ip: str = Header(default=""),
    authorization: str | None = Header(default=None),
):
    """Nginx auth_request adapter: return signed decision headers only."""
    _authorize_ingress(authorization)
    client_ip = _client_ip(x_client_ip)
    method = x_original_method.upper()
    if not method or len(method) > 16 or any(not char.isalnum() and char != "_" for char in method):
        raise HTTPException(status_code=400, detail="Invalid request method")
    if not x_original_uri.startswith("/") or len(x_original_uri) > 2048:
        raise HTTPException(status_code=400, detail="Invalid request URI")
    decision = policy.decide(method=method, path=x_original_uri, client_key=client_ip)
    if not decision.allow:
        raise HTTPException(status_code=403, detail="Edge admission denied")
    import base64
    import json
    from fastapi.responses import Response
    payload = decision.__dict__.copy()
    signature = payload.pop("signature")
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return Response(
        status_code=204,
        headers={
            "X-Aegis-Edge-Decision": encoded,
            "X-Aegis-Edge-Signature": signature,
            "X-Aegis-Edge-Client-IP": decision.client_ip,
        },
    )
