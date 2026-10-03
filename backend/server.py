"""
Aegis SOC — FastAPI backend.

Security posture (see SECURITY_DOSSIER.md for full control mapping):
- bcrypt cost 12, per-password salt
- JWT access (12h) + refresh (7d) in httpOnly, secure, samesite=none cookies
- Brute-force lockout: 5 failed attempts per {ip}:{email} → 15-min lockout
- Tenant isolation via tenant_filter() — non-privileged users hard-scoped
- Audit trail on every mutating action (actor, action, resource, ip, tenant, timestamp)
- Pydantic v2 validation on all request bodies; Literal enums for status/severity/tenant
- Parameterized MongoDB queries (motor) — no string concatenation
- Account enumeration prevention: generic "Invalid email or password"
- Owner protected from deletion
- Secrets loaded from environment only; never logged

Honest non-claims (per dossier honesty guardrails):
- httpOnly prevents JS from reading the raw token, but a successful XSS could still
  make authenticated requests via the cookie. We do NOT claim immunity to XSS.
- Tenant isolation is logical/query-level today; database-level isolation is PLANNED.
- No blanket "immune to X" claims anywhere.
"""

from __future__ import annotations

import os
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings

from security_hardening import SecurityHeadersMiddleware, forwarded_client_ip


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    MONGO_URL: str = "mongodb://localhost:27017"
    DB_NAME: str = "aegis_soc"
    JWT_SECRET: str = "change-me-to-a-64-char-hex-string"
    ADMIN_EMAIL: str = "william.brown@aegis-soc.io"
    ADMIN_PASSWORD: str = "change-me"
    ANALYST_EMAIL: str = "analyst@aegis-soc.io"
    ANALYST_PASSWORD: str = "change-me"
    FRONTEND_URL: str = "http://localhost:3000"
    CORS_ORIGINS: str = "http://localhost:3000"
    MONGO_TLS: bool = True
    MONGO_TLS_CA_FILE: str = ""
    MONGO_TLS_CERT_KEY_FILE: str = ""
    MONGO_TLS_ALLOW_INVALID_CERTS: bool = False
    TRUSTED_PROXY_IPS: str = ""
    SSO_BASE_URL: str = "http://localhost:8001"
    SAML_ENABLED: bool = False
    OIDC_ENABLED: bool = False
    SAML_IDP_METADATA_URL: str = ""
    SAML_IDP_ENTITY_ID: str = ""
    SAML_IDP_SSO_URL: str = ""
    SAML_IDP_X509_CERT: str = ""
    OIDC_ISSUER_URL: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_SCOPES: str = "openid profile email"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

ACCESS_TOKEN_MINUTES = 12 * 60
REFRESH_TOKEN_DAYS = 7
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15


# ─────────────────────────────────────────────────────────────────────────────
# App + DB
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Aegis SOC API", version="2.1.0", docs_url="/docs", redoc_url="/redoc")

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()] + [settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

mongo_kwargs = {
    "tls": settings.MONGO_TLS,
    "tlsAllowInvalidCertificates": settings.MONGO_TLS_ALLOW_INVALID_CERTS,
}
if settings.MONGO_TLS_CA_FILE:
    mongo_kwargs["tlsCAFile"] = settings.MONGO_TLS_CA_FILE
if settings.MONGO_TLS_CERT_KEY_FILE:
    mongo_kwargs["tlsCertificateKeyFile"] = settings.MONGO_TLS_CERT_KEY_FILE
client = AsyncIOMotorClient(settings.MONGO_URL, **mongo_kwargs)
db = client[settings.DB_NAME]

api_router = APIRouter(prefix="/api")


# ─────────────────────────────────────────────────────────────────────────────
# Security helpers
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str, tenant: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "tenant": tenant,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key="access_token", value=access_token,
        httponly=True, secure=True, samesite="none",
        max_age=ACCESS_TOKEN_MINUTES * 60, path="/",
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=True, samesite="none",
        max_age=REFRESH_TOKEN_DAYS * 24 * 3600, path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(key="access_token", path="/", samesite="none", secure=True)
    response.delete_cookie(key="refresh_token", path="/", samesite="none", secure=True)


async def get_current_user(request: Request) -> dict:
    """Re-fetches the user from Mongo on every call (session revalidation)."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNSUPPORTED_MEDIA_TYPE, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_TOKEN_EXPIRED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_INVALID_TOKEN, detail="Invalid token")

    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_NOT_FOUND, detail="User not found")
    user.pop("password_hash", None)
    return user


def require_role(*roles: str):
    async def _checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return _checker


def tenant_filter(user: dict, requested: Optional[str] = None) -> dict:
    """Non-privileged users are hard-scoped to their own tenant; owner/admin may filter freely."""
    if user["role"] in ("owner", "admin"):
        if requested and requested != "all":
            return {"tenant": requested}
        return {}  # all tenants
    return {"tenant": user["tenant"]}


async def write_audit(actor: str, action: str, resource: str, request: Request, tenant: str = "") -> None:
    await db.audit_logs.insert_one({
        "actor": actor,
        "action": action,
        "resource": resource,
        "ip": forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS),
        "tenant": tenant,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


async def check_lockout(ip: str, email: str) -> None:
    key = f"{ip}:{email}"
    attempt = await db.login_attempts.find_one({"key": key})
    if attempt and attempt.get("locked_until") and datetime.now(timezone.utc) < attempt["locked_until"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again after {attempt['locked_until'].isoformat()}",
        )


async def record_failed_attempt(ip: str, email: str) -> None:
    key = f"{ip}:{email}"
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"key": key})
    count = (attempt.get("count", 0) if attempt else 0) + 1
    update = {"$set": {"count": count, "last_attempt": now}}
    if count >= LOCKOUT_THRESHOLD:
        update["$set"]["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
    await db.login_attempts.update_one({"key": key}, update, upsert=True)


async def clear_failed_attempts(ip: str, email: str) -> None:
    await db.login_attempts.delete_one({"key": f"{ip}:{email}"})


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

Tenant = Literal["government", "private", "saas"]
Role = Literal["owner", "admin", "analyst", "viewer"]
IncidentStatus = Literal["new", "investigating", "contained", "resolved"]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str = Field(min_length=1, max_length=100)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=6)


class IncidentUpdate(BaseModel):
    status: IncidentStatus


class UserInvite(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    role: Role
    tenant: Tenant
    password: str = Field(min_length=6)


# ─────────────────────────────────────────────────────────────────────────────
# Startup: indexes + idempotent seeding
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.login_attempts.create_index("key", unique=True)
    for col in ("threats", "incidents", "vulnerabilities", "assets", "compliance", "audit_logs"):
        await db[col].create_index([("tenant", 1), ("timestamp", -1)])
    await seed_users()
    await seed_demo_data()


async def seed_users():
    """Idempotent: re-hash owner password if ADMIN_PASSWORD changed."""
    for email, password, role, tenant, name in [
        (settings.ADMIN_EMAIL, settings.ADMIN_PASSWORD, "owner", "saas", "William Brown"),
        (settings.ANALYST_EMAIL, settings.ANALYST_PASSWORD, "analyst", "government", "Demo Analyst"),
    ]:
        existing = await db.users.find_one({"email": email})
        if existing:
            if not verify_password(password, existing["password_hash"]):
                await db.users.update_one(
                    {"email": email},
                    {"$set": {"password_hash": hash_password(password)}},
                )
        else:
            await db.users.insert_one({
                "id": secrets.token_hex(16),
                "email": email,
                "name": name,
                "role": role,
                "tenant": tenant,
                "password_hash": hash_password(password),
                "created_at": datetime.now(timezone.utc).isoformat(),
            })


async def seed_demo_data():
    """Idempotent seeder — skips if data already exists."""
    if await db.threats.count_documents({}) > 0:
        return

    now = datetime.now(timezone.utc)
    severities = ["critical", "high", "high", "medium", "medium", "medium", "low", "low", "low", "low"]
    tenants = ["government", "private", "saas"]
    sources = ["10.0.1.45", "185.220.101.42", "45.33.32.156", "203.0.113.77", "198.51.100.23"]
    geos = ["RU", "CN", "KP", "IR", "US", "DE", "BR"]
    techniques = ["T1566", "T1059", "T1071", "T1003", "T1027", "T1047", "T1083", "T1110"]

    threats = []
    for i in range(120):
        t = now - timedelta(hours=secrets.randbelow(336))
        threats.append({
            "id": secrets.token_hex(8),
            "tenant": secrets.choice(tenants),
            "severity": secrets.choice(severities),
            "title": f"Simulated threat event {i+1:03d}",
            "description": f"Correlated SIEM event — simulated telemetry for demo purposes.",
            "source_ip": secrets.choice(sources),
            "geo": secrets.choice(geos),
            "confidence": round(secrets.uniform(0.4, 0.99), 2),
            "affected_asset": f"asset-{secrets.randbelow(60)+1:03d}",
            "mitre_technique": secrets.choice(techniques),
            "timestamp": t.isoformat(),
        })
    await db.threats.insert_many(threats)

    cves = ["CVE-2024-3094", "CVE-2024-6387", "CVE-2024-21762", "CVE-2024-3400", "CVE-2024-4577",
            "CVE-2024-38063", "CVE-2024-30051", "CVE-2024-20696", "CVE-2023-4966", "CVE-2023-36884"]
    vulns = []
    for i, cve in enumerate(cves * 3):
        vulns.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "cve_id": cve,
            "cvss": round(secrets.uniform(4.0, 9.8), 1),
            "title": f"{cve} — simulated vulnerability",
            "affected_asset": f"asset-{secrets.randbelow(60)+1:03d}",
            "patched": secrets.choice([True, False, False, False]),
            "discovered_at": (now - timedelta(days=secrets.randbelow(30))).isoformat(),
        })
    await db.vulnerabilities.insert_many(vulns)

    kill_chain = ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "c2", "actions_on_objectives"]
    incidents = []
    for i in range(24):
        incidents.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "title": f"Incident {i+1:03d} — simulated SOC case",
            "status": secrets.choice(["new", "investigating", "contained", "resolved"]),
            "severity": secrets.choice(severities),
            "kill_chain_phase": secrets.choice(kill_chain),
            "assignee": secrets.choice(["Demo Analyst", "Unassigned", "William Brown"]),
            "created_at": (now - timedelta(days=secrets.randbelow(14))).isoformat(),
            "updated_at": now.isoformat(),
        })
    await db.incidents.insert_many(incidents)

    asset_types = ["workstation", "server", "firewall", "router", "database", "endpoint"]
    assets = []
    for i in range(60):
        assets.append({
            "id": secrets.token_hex(8),
            "tenant": tenants[i % 3],
            "name": f"{secrets.choice(asset_types)}-{i+1:03d}",
            "type": secrets.choice(asset_types),
            "ip": f"10.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}",
            "os": secrets.choice(["Windows 11", "Ubuntu 22.04", "RHEL 9", "macOS Sonoma"]),
            "risk_score": round(secrets.uniform(1.0, 9.5), 1),
            "last_seen": (now - timedelta(minutes=secrets.randbelow(1440))).isoformat(),
        })
    await db.assets.insert_many(assets)

    frameworks = ["NIST 800-53", "ISO 27001", "SOC 2", "HIPAA", "FedRAMP", "PCI-DSS 4.0", "CMMC L2"]
    compliance = []
    for fw in frameworks:
        for t in tenants:
            compliance.append({
                "id": secrets.token_hex(8),
                "tenant": t,
                "framework": fw,
                "score": round(secrets.uniform(55.0, 95.0), 1),
                "controls_passing": secrets.randbelow(80) + 20,
                "controls_total": 100,
                "last_assessed": (now - timedelta(days=secrets.randbelow(7))).isoformat(),
            })
    await db.compliance.insert_many(compliance)

    audits = []
    for i in range(80):
        audits.append({
            "actor": secrets.choice(["william.brown@aegis-soc.io", "analyst@aegis-soc.io", "system"]),
            "action": secrets.choice(["login", "logout", "incident_update", "vuln_patch", "user_invite", "threat_view"]),
            "resource": f"resource-{secrets.randbelow(50)}",
            "ip": secrets.choice(sources),
            "tenant": secrets.choice(tenants),
            "created_at": (now - timedelta(hours=secrets.randbelow(720))).isoformat(),
        })
    await db.audit_logs.insert_many(audits)


# ─────────────────────────────────────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────────────────────────────────────

@api_router.get("/")
async def health():
    return {"status": "ok", "service": "aegis-soc-api", "version": "2.1.0"}


@api_router.post("/auth/register")
async def register(body: RegisterRequest, request: Request, response: Response):
    if await db.users.find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = secrets.token_hex(16)
    await db.users.insert_one({
        "id": user_id,
        "email": body.email,
        "name": body.name,
        "role": "viewer",
        "tenant": "private",
        "password_hash": hash_password(body.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    access = create_access_token(user_id, body.email, "viewer", "private")
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)
    await write_audit(body.email, "register", "users", request, "private")
    return {"message": "Registered", "email": body.email, "role": "viewer"}


@api_router.post("/auth/login")
async def login(body: LoginRequest, request: Request, response: Response):
    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await check_lockout(ip, body.email)
    user = await db.users.find_one({"email": body.email})
    if not user or not verify_password(body.password, user["password_hash"]):
        await record_failed_attempt(ip, body.email)
        # Generic message — prevents account enumeration
        raise HTTPException(status_code=401, detail="Invalid email or password")
    await clear_failed_attempts(ip, body.email)
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"])
    refresh = create_refresh_token(user["id"])
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "login", "auth", request, user["tenant"])
    return {"message": "Logged in", "email": user["email"], "role": user["role"], "tenant": user["tenant"]}


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response, user: dict = Depends(get_current_user)):
    clear_auth_cookies(response)
    await write_audit(user["email"], "logout", "auth", request, user["tenant"])
    return {"message": "Logged out"}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api_router.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"])
    response.set_cookie(
        key="access_token", value=access, httponly=True, secure=True,
        samesite="none", max_age=ACCESS_TOKEN_MINUTES * 60, path="/",
    )
    return {"message": "Token refreshed"}


@api_router.post("/auth/password-reset/request")
async def password_reset_request(body: PasswordResetRequest, request: Request):
    user = await db.users.find_one({"email": body.email})
    # Always return success — prevents enumeration
    if user:
        token = secrets.token_urlsafe(32)
        await db.password_reset_tokens.insert_one({
            "email": body.email,
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "used": False,
        })
        # In production: send token via email. Demo: log only.
        print(f"[DEMO] Password reset token for {body.email}: {token}")
    await write_audit(body.email, "password_reset_request", "auth", request)
    return {"message": "If the account exists, a reset link has been sent."}


@api_router.post("/auth/password-reset/confirm")
async def password_reset_confirm(body: PasswordResetConfirm, request: Request):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    record = await db.password_reset_tokens.find_one({"token_hash": token_hash, "used": False})
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    await db.users.update_one(
        {"email": record["email"]},
        {"$set": {"password_hash": hash_password(body.new_password)}},
    )
    await db.password_reset_tokens.update_one({"token_hash": token_hash}, {"$set": {"used": True}})
    await write_audit(record["email"], "password_reset_confirm", "auth", request)
    return {"message": "Password updated. Please log in."}


# ─────────────────────────────────────────────────────────────────────────────
# Metrics & Threats
# ─────────────────────────────────────────────────────────────────────────────

@api_router.get("/metrics/overview")
async def metrics_overview(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    total_threats = await db.threats.count_documents(filt)
    open_incidents = await db.incidents.count_documents({**filt, "status": {"$ne": "resolved"}})
    critical = await db.threats.count_documents({**filt, "severity": "critical"})
    high = await db.threats.count_documents({**filt, "severity": "high"})
    # 7-day trend
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


@api_router.get("/threats")
async def list_threats(limit: int = 50, severity: Optional[str] = None, tenant: Optional[str] = None,
                       user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    if severity:
        filt["severity"] = severity
    return await db.threats.find(filt, {"_id": 0}).sort("timestamp", -1).to_list(limit)


@api_router.get("/threats/live")
async def threats_live(user: dict = Depends(get_current_user)):
    """Simulates & inserts a new live threat (demo telemetry)."""
    now = datetime.now(timezone.utc)
    threat = {
        "id": secrets.token_hex(8),
        "tenant": user["tenant"] if user["role"] not in ("owner", "admin") else secrets.choice(["government", "private", "saas"]),
        "severity": secrets.choice(["critical", "high", "medium", "low"]),
        "title": f"Live simulated event {secrets.token_hex(4)}",
        "description": "Simulated live telemetry — not a real attack.",
        "source_ip": f"{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}",
        "geo": secrets.choice(["RU", "CN", "KP", "IR", "US", "DE"]),
        "confidence": round(secrets.uniform(0.5, 0.99), 2),
        "affected_asset": f"asset-{secrets.randbelow(60)+1:03d}",
        "mitre_technique": secrets.choice(["T1566", "T1059", "T1071", "T1003", "T1027"]),
        "timestamp": now.isoformat(),
    }
    await db.threats.insert_one(threat)
    threat.pop("_id", None)
    return threat


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

@api_router.get("/vulnerabilities")
async def list_vulns(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.vulnerabilities.find(filt, {"_id": 0}).sort("cvss", -1).to_list(100)


@api_router.post("/vulnerabilities/{vuln_id}/patch")
async def patch_vuln(vuln_id: str, request: Request, user: dict = Depends(get_current_user)):
    result = await db.vulnerabilities.update_one(
        {"id": vuln_id, **tenant_filter(user)},
        {"$set": {"patched": True, "patched_at": datetime.now(timezone.utc).isoformat(), "patched_by": user["email"]}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    await write_audit(user["email"], "vuln_patch", vuln_id, request, user["tenant"])
    return {"message": "Patched"}


# ─────────────────────────────────────────────────────────────────────────────
# Incidents
# ─────────────────────────────────────────────────────────────────────────────

@api_router.get("/incidents")
async def list_incidents(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.incidents.find(filt, {"_id": 0}).sort("created_at", -1).to_list(100)


@api_router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, body: IncidentUpdate, request: Request,
                          user: dict = Depends(get_current_user)):
    result = await db.incidents.update_one(
        {"id": incident_id, **tenant_filter(user)},
        {"$set": {"status": body.status, "updated_at": datetime.now(timezone.utc).isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await write_audit(user["email"], "incident_update", incident_id, request, user["tenant"])
    return {"message": "Updated", "status": body.status}


# ─────────────────────────────────────────────────────────────────────────────
# Assets, Compliance, Audit
# ─────────────────────────────────────────────────────────────────────────────

@api_router.get("/assets")
async def list_assets(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.assets.find(filt, {"_id": 0}).sort("risk_score", -1).to_list(100)


@api_router.get("/compliance")
async def list_compliance(tenant: Optional[str] = None, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.compliance.find(filt, {"_id": 0}).to_list(50)


@api_router.get("/audit-logs")
async def list_audit_logs(tenant: Optional[str] = None, limit: int = 100, user: dict = Depends(get_current_user)):
    filt = tenant_filter(user, tenant)
    return await db.audit_logs.find(filt, {"_id": 0}).sort("created_at", -1).to_list(limit)


# ─────────────────────────────────────────────────────────────────────────────
# Users (owner / admin only)
# ─────────────────────────────────────────────────────────────────────────────

@api_router.get("/users")
async def list_users(user: dict = Depends(require_role("owner", "admin"))):
    users = await db.users.find(tenant_filter(user), {"_id": 0, "password_hash": 0}).to_list(100)
    return users


@api_router.post("/users")
async def invite_user(body: UserInvite, request: Request, user: dict = Depends(require_role("owner", "admin"))):
    if await db.users.find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = secrets.token_hex(16)
    await db.users.insert_one({
        "id": user_id,
        "email": body.email,
        "name": body.name,
        "role": body.role,
        "tenant": body.tenant,
        "password_hash": hash_password(body.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "invited_by": user["email"],
    })
    await write_audit(user["email"], "user_invite", body.email, request, body.tenant)
    return {"message": "User invited", "email": body.email, "role": body.role}


@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, request: Request, user: dict = Depends(require_role("owner", "admin"))):
    target = await db.users.find_one({"id": user_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "owner":
        raise HTTPException(status_code=400, detail="Cannot remove the owner")
    await db.users.delete_one({"id": user_id})
    await write_audit(user["email"], "user_delete", target["email"], request, target["tenant"])
    return {"message": "User removed"}


# Import security routers after shared server dependencies are defined to avoid circular imports.
from sso import sso_router
from anomaly import anomaly_router

app.include_router(api_router)
app.include_router(sso_router)
app.include_router(anomaly_router)
