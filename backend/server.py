"""
Aegis SOC — FastAPI application entrypoint.

Security posture (see SECURITY_DOSSIER.md for full control mapping):
- bcrypt cost 12, per-password salt
- JWT access (15m) + rotating refresh (7d) in httpOnly, secure, SameSite cookies
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

from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings, validate_security_settings, allowed_csrf_origins
from security_hardening import SecurityHeadersMiddleware
from seed import run_startup

# Re-export symbols that sso.py / anomaly.py currently import from server
from database import db  # noqa: F401
from deps import (  # noqa: F401
    get_current_user,
    require_role,
    tenant_filter,
    write_audit,
)

validate_security_settings()

app = FastAPI(
    title="Aegis SOC API",
    version="2.1.0",
    docs_url="/docs" if settings.AEGIS_ENV.lower() != "production" else None,
    redoc_url="/redoc" if settings.AEGIS_ENV.lower() != "production" else None,
)


@app.middleware("http")
async def csrf_origin_guard(request: Request, call_next):
    """Reject cross-origin state-changing browser requests that carry Aegis auth cookies."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and (
        request.cookies.get("access_token") or request.cookies.get("refresh_token")
    ):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        if origin:
            source = origin.rstrip("/")
        elif referer:
            parsed = urlparse(referer)
            source = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        else:
            source = None
        if source is None or source not in allowed_csrf_origins():
            return JSONResponse(status_code=403, content={"detail": "Cross-origin request blocked"})
    return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(dict.fromkeys(
        [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()] + [settings.FRONTEND_URL]
    )),
    allow_credentials=True,
    allow_methods=[m.strip().upper() for m in settings.CORS_ALLOW_METHODS.split(",") if m.strip()],
    allow_headers=[h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",") if h.strip()],
)


@app.on_event("startup")
async def on_startup():
    await run_startup()


# ── Routers ─────────────────────────────────────────────────────────────────
from routers.auth import router as auth_router
from routers.metrics import router as metrics_router
from routers.threats import router as threats_router
from routers.vulnerabilities import router as vulns_router
from routers.incidents import router as incidents_router
from routers.resources import router as resources_router
from routers.users import router as users_router

# Existing modules (keep import path stable)
from sso import sso_router
from anomaly import anomaly_router

app.include_router(auth_router, prefix="/api")
app.include_router(metrics_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(vulns_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(resources_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(sso_router)
app.include_router(anomaly_router)
