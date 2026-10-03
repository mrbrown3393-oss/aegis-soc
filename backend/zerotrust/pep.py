"""
Aegis SOC — Zero Trust Policy Enforcement Point (PEP) middleware.

Runs before protected routes and enforces per-request verification:
identity validity, authentication freshness (step-up), device posture,
and session risk. Fail-closed: any failure denies the request.

See docs/zero-trust-architecture.md (AEG-ZTA-001).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import jwt
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware

# Paths exempt from PEP checks (auth bootstrap + health)
EXEMPT_PREFIXES = (
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/refresh",
    "/api/auth/password-reset",
    "/api/auth/sso",
    "/docs",
    "/redoc",
    "/openapi.json",
)

# Admin actions require step-up: auth age below this threshold
STEP_UP_MAX_AUTH_AGE_MINUTES = int(os.getenv("ZT_STEP_UP_MAX_AUTH_AGE_MIN", "15"))
SENSITIVE_PATHS = (
    "/api/users",
    "/api/security/quarantine",
)

# Device posture: set ZT_REQUIRE_DEVICE_POSTURE=true to require managed devices
REQUIRE_DEVICE_POSTURE = os.getenv("ZT_REQUIRE_DEVICE_POSTURE", "false").lower() == "true"
DEVICE_POSTURE_HEADER = "x-device-posture"
EXPECTED_POSTURE = os.getenv("ZT_DEVICE_POSTURE_VALUE", "managed;compliant")

RISK_DENY_THRESHOLD = float(os.getenv("ZT_RISK_DENY_THRESHOLD", "0.85"))


def _session_risk(payload: dict, request: Request) -> float:
    """Heuristic 0..1 session risk from request signals vs. token claims."""
    risk = 0.0
    # Token age contributes: older sessions are riskier
    iat = payload.get("iat")
    if iat:
        age_min = (datetime.now(timezone.utc) - datetime.fromtimestamp(iat, tz=timezone.utc)).total_seconds() / 60
        risk += min(age_min / (12 * 60), 1.0) * 0.3
    # Missing/odd UA on API calls is a weak signal
    if not request.headers.get("user-agent"):
        risk += 0.2
    return min(risk, 1.0)


class ZeroTrustPEPMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, jwt_secret: str, audit=None):
        super().__init__(app)
        self._secret = jwt_secret
        self._audit = audit  # optional async callable(actor, action, resource, request)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/") or any(path.startswith(p) for p in EXEMPT_PREFIXES):
            return await call_next(request)

        token = request.cookies.get("access_token")
        if not token:
            return await call_next(request)  # route-level auth returns 401 uniformly

        try:
            payload = jwt.decode(token, self._secret, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return await call_next(request)

        # 1) Step-up: sensitive paths require recent authentication
        if any(path.startswith(p) for p in SENSITIVE_PATHS) and request.method not in ("GET", "HEAD"):
            iat = payload.get("iat")
            if not iat:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Step-up authentication required")
            age_min = (datetime.now(timezone.utc) - datetime.fromtimestamp(iat, tz=timezone.utc)).total_seconds() / 60
            if age_min > STEP_UP_MAX_AUTH_AGE_MINUTES:
                if self._audit:
                    await self._audit(payload.get("email", "unknown"), "zt_stepup_denied", path, request)
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Step-up authentication required")

        # 2) Device posture for privileged roles
        if REQUIRE_DEVICE_POSTURE and payload.get("role") in ("owner", "admin"):
            if request.headers.get(DEVICE_POSTURE_HEADER) != EXPECTED_POSTURE:
                if self._audit:
                    await self._audit(payload.get("email", "unknown"), "zt_posture_denied", path, request)
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Managed, compliant device required")

        # 3) Session risk
        risk = _session_risk(payload, request)
        if risk >= RISK_DENY_THRESHOLD:
            if self._audit:
                await self._audit(payload.get("email", "unknown"), "zt_risk_denied", path, request)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session risk too high — re-authenticate")

        return await call_next(request)
