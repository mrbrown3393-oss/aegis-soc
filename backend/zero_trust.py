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
    existing = request.headers.get("x-request-id", "").strip()
    if existing and len(existing) <= 128:
        return existing
    return secrets.token_urlsafe(16)


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )


def require_mfa_strength(auth_strength: str | None) -> None:
    """Production protected actions must originate from an MFA-authenticated session."""
    if settings.MFA_REQUIRED and auth_strength != "mfa":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA-authenticated session required",
        )


class ZeroTrustMiddleware(BaseHTTPMiddleware):
    """Global fail-closed guard for API endpoints."""

    async def dispatch(self, request: Request, call_next):
        try:
            enforce_protected_path(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id(request)
        return response
