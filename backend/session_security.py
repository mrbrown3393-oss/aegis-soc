"""Shared request-bound authentication session policy.

Keeps request-derived security context out of low-level session persistence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import secrets

from fastapi import HTTPException, Request

from auth_helpers import create_auth_session
from database import db
from zero_trust import device_fingerprint


async def create_bound_auth_session(user_id: str, request: Request) -> tuple[str, str]:
    """Create an auth session bound to the device context of this request."""
    return await create_auth_session(user_id, device_fingerprint(request))


async def rotate_refresh_session(
    session: dict,
    user_id: str,
    session_id: str,
    refresh_jti: str,
    request: Request,
) -> str:
    """Atomically rotate a refresh token and revoke the session on replay."""
    current_fingerprint = device_fingerprint(request)
    stored_fingerprint = session.get("device_fingerprint")
    if not stored_fingerprint or not secrets.compare_digest(stored_fingerprint, current_fingerprint):
        await db.auth_sessions.update_one(
            {"session_id": session_id, "user_id": user_id, "revoked_at": None},
            {"$set": {
                "revoked_at": datetime.now(timezone.utc),
                "revoke_reason": "device_context_changed_on_refresh",
            }},
        )
        raise HTTPException(status_code=401, detail="Session device context changed")

    new_jti = secrets.token_urlsafe(24)
    rotated = await db.auth_sessions.update_one(
        {
            "session_id": session_id,
            "user_id": user_id,
            "refresh_jti": refresh_jti,
            "revoked_at": None,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        },
        {"$set": {"refresh_jti": new_jti}},
    )
    if getattr(rotated, "modified_count", 0) != 1:
        await db.auth_sessions.update_one(
            {"session_id": session_id, "user_id": user_id, "revoked_at": None},
            {"$set": {
                "revoked_at": datetime.now(timezone.utc),
                "revoke_reason": "refresh_token_replay",
            }},
        )
        raise HTTPException(status_code=401, detail="Refresh token replay detected; session revoked")
    return new_jti
