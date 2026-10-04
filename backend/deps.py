"""FastAPI dependencies: current user, roles, tenant scoping, audit."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import secrets

import jwt
from fastapi import Depends, HTTPException, Request, status

from auth_helpers import active_session, enforce_authenticated_rate_limit, decode_jwt
from config import settings
from database import db
from security_hardening import forwarded_client_ip
from zero_trust import device_fingerprint, request_id


async def get_current_user(request: Request) -> dict:
    """Re-fetch the user and trust context from Mongo on every protected request."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_jwt(token)
        if payload.get("type") != "access" or not payload.get("sid"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if not await active_session(payload["sid"], payload["sub"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or expired")

    session = await db.auth_sessions.find_one({
        "session_id": payload["sid"],
        "user_id": payload["sub"],
        "revoked_at": None,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or expired")

    # Bind the session to the browser/device context. Existing sessions are
    # enrolled on first use; subsequent context changes fail closed.
    fingerprint = device_fingerprint(request)
    stored_fingerprint = session.get("device_fingerprint")
    if stored_fingerprint:
        if not secrets.compare_digest(stored_fingerprint, fingerprint):
            await db.auth_sessions.update_one(
                {"session_id": payload["sid"], "user_id": payload["sub"], "revoked_at": None},
                {"$set": {"revoked_at": datetime.now(timezone.utc), "revoke_reason": "device_context_changed"}},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session device context changed")
    else:
        await db.auth_sessions.update_one(
            {"session_id": payload["sid"], "user_id": payload["sub"], "revoked_at": None},
            {"$set": {"device_fingerprint": fingerprint}},
        )

    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await enforce_authenticated_rate_limit(ip, payload["sub"])
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    user.pop("password_hash", None)
    return user


def require_role(*roles: str):
    async def _checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return _checker


def tenant_filter(user: dict, requested: Optional[str] = None) -> dict:
    """Default-deny tenant scope; cross-tenant access must be explicitly requested."""
    if user["role"] == "owner":
        if requested == "all":
            return {}
        # Owners operate within their current tenant unless they explicitly
        # select another tenant. This prevents accidental portfolio-wide reads.
        return {"tenant": requested or user["tenant"]}
    return {"tenant": user["tenant"]}


async def write_audit(
    actor: str,
    action: str,
    resource: str,
    request: Request,
    tenant: str = "",
) -> None:
    await db.audit_logs.insert_one({
        "id": secrets.token_hex(8),
        "actor": actor,
        "action": action,
        "resource": resource,
        "ip": forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS),
        "tenant": tenant,
        "request_id": request_id(request),
        "tenant_scope": tenant or "unspecified",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
