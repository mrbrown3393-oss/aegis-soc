"""Zero Trust request/session policy for Aegis SOC.

Principles:
- authenticate every protected request;
- continuously validate the server-side session;
- bind sessions to a device/browser fingerprint;
- require MFA-strength sessions in production;
- fail closed on missing trust context;
- emit a request correlation ID for audit/incident response.
"""
from __future__ import annotations

import hashlib
import secrets

from fastapi import HTTPException, Request, status

from config import settings


PUBLIC_PATHS = {
    "/",
    "/api/",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/password-reset/request",
    "/api/auth/password-reset/confirm",
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
    if request.url.path.startswith("/api/") and request.url.path not in PUBLIC_PATHS:
        if not request.cookies.get("access_token"):
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
