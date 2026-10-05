"""
Aegis SOC — FastAPI application entrypoint.

Security posture:
- bcrypt cost 12, per-password salt
- JWT access (15m) + rotating refresh (7d) in httpOnly, secure, SameSite cookies
- Brute-force lockout: 5 failed attempts per {ip}:{email} → 15-min lockout
- Zero Trust: protected API routes fail closed without authentication
- Zero Trust: server-side session revalidation and device-context binding
- Tenant isolation via tenant_filter() with explicit cross-tenant scope
- Audit trail with request correlation IDs
- Pydantic v2 validation and parameterized MongoDB queries
- Secrets loaded from environment only
- Production OIDC and SAML federation with cryptographic validation

Honest non-claims:
- httpOnly does not make the application XSS-immune.
- Tenant isolation remains logical/query-level, not database-level.
- FedRAMP/CMMC/ISO/SOC 2/etc. certification is not claimed by this code alone.
"""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings, validate_security_settings, allowed_csrf_origins
from security_hardening import SecurityHeadersMiddleware
from zero_trust import ZeroTrustMiddleware
from seed import run_startup

from database import client, db  # noqa: F401
from deps import get_current_user, require_role, tenant_filter, write_audit  # noqa: F401

validate_security_settings()

app = FastAPI(
    title="Aegis SOC API",
    version="2.2.0",
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


app.add_middleware(ZeroTrustMiddleware)
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


@app.on_event("shutdown")
async def on_shutdown():
    await client.close()


from routers.auth import router as auth_router
from routers.metrics import router as metrics_router
from routers.threats import router as threats_router
from routers.vulnerabilities import router as vulns_router
from routers.incidents import router as incidents_router
from routers.resources import router as resources_router
from routers.users import router as users_router

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
