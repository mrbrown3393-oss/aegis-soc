"""FastAPI dependencies: current user, roles, tenant scoping, audit."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status

from auth_helpers import active_session
from config import settings
from database import db
from security_hardening import forwarded_client_ip


async def get_current_user(request: Request) -> dict:
    """Re-fetches the user from Mongo on every call (session revalidation)."""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access" or not payload.get("sid"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if not await active_session(payload["sid"], payload["sub"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or expired")
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
    """Only the owner may cross tenant boundaries; all other roles stay on their own tenant."""
    if user["role"] == "owner":
        if requested and requested != "all":
            return {"tenant": requested}
        return {}  # all tenants
    return {"tenant": user["tenant"]}


async def write_audit(
    actor: str,
    action: str,
    resource: str,
    request: Request,
    tenant: str = "",
) -> None:
    await db.audit_logs.insert_one({
        "actor": actor,
        "action": action,
        "resource": resource,
        "ip": forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS),
        "tenant": tenant,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
