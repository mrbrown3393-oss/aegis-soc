"""Zero Trust request/session policy for Aegis SOC."""
from __future__ import annotations

import hashlib
import secrets

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config import settings

PUBLIC_PATHS = {
    "/",
    "/api/",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/password-reset/request",
    "/api/auth/password-reset/confirm",
    "/api/auth/mfa/setup",
    "/api/auth/mfa/verify",
}


def request_id(request: Request) -> str:
    """Return a bounded correlation ID while tolerating lightweight request stubs in tests."""
    state = getattr(request, "state", None)
    current = getattr(state, "aegis_request_id", None)
    if current:
        return current
    headers = getattr(request, "headers", {})
    existing = headers.get("x-request-id", "").strip()
    value = existing if existing and len(existing) <= 128 else secrets.token_urlsafe(16)
    if state is not None:
        state.aegis_request_id = value
    return value


def device_fingerprint(request: Request) -> str:
    """Stable-enough browser/device binding without storing raw user-agent data."""
    material = "|".join(
        [
            request.headers.get("user-agent", ""),
            request.headers.get("accept-language", ""),
            request.headers.get("sec-ch-ua", ""),
            request.headers.get("sec-ch-ua-platform", ""),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def enforce_protected_path(request: Request) -> None:
    """Fail closed for unexpected API routes that bypass authentication dependencies."""
    path = request.url.path
    if path.startswith("/api/auth/sso/"):
        return
    if path.startswith("/api/") and path not in PUBLIC_PATHS and not request.cookies.get("access_token"):
        raise HTTPException(status_code=401, detail="Authentication required")


def require_mfa_strength(auth_strength: str | None) -> None:
    if settings.MFA_REQUIRED and auth_strength != "mfa":
        raise HTTPException(status_code=403, detail="MFA-authenticated session required")


class ZeroTrustMiddleware(BaseHTTPMiddleware):
    """Global fail-closed guard for API endpoints."""

    async def dispatch(self, request: Request, call_next):
        request_id(request)
        try:
            enforce_protected_path(request)
        except HTTPException as exc:
            response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
            response.headers["X-Request-ID"] = request.state.aegis_request_id
            return response
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.aegis_request_id
        return response
