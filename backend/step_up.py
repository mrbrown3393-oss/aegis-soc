"""Step-up authentication for high-impact actions."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import Depends, HTTPException, Request, status

from auth_helpers import decode_jwt, encode_jwt
from deps import get_current_user
from zero_trust import device_fingerprint
import jwt


STEP_UP_MINUTES = 10
HIGH_IMPACT_ROLES = frozenset({"owner", "admin", "analyst"})


def create_step_up_token(session_id: str, fingerprint: str) -> str:
    now = datetime.now(timezone.utc)
    return encode_jwt({
        "sid": session_id,
        "fp": fingerprint,
        "type": "step_up",
        "exp": now + timedelta(minutes=STEP_UP_MINUTES),
        "iat": now,
    })


def validate_step_up_claims(payload: dict, access_payload: dict, fingerprint: str) -> None:
    """Validate step-up type, session binding, and device binding."""
    if payload.get("type") != "step_up" or payload.get("sid") != access_payload.get("sid"):
        raise HTTPException(status_code=401, detail="Invalid step-up session")
    if payload.get("fp") != fingerprint:
        raise HTTPException(status_code=401, detail="Step-up device context changed")


def enforce_step_up_role(user: dict, roles: set[str] | frozenset[str] | tuple[str, ...]) -> None:
    if user.get("role") not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def _require_step_up_token(request: Request) -> None:
    token = request.cookies.get("step_up")
    access = request.cookies.get("access_token")
    if not token or not access:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up authentication required")
    try:
        payload = decode_jwt(token)
        access_payload = decode_jwt(access)
        validate_step_up_claims(payload, access_payload, device_fingerprint(request))
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid step-up token")


async def require_step_up(
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict:
    await _require_step_up_token(request)
    return user


def require_step_up_role(*roles: str):
    """Require a valid step-up token plus one of the supplied application roles."""
    allowed = frozenset(roles)

    async def _checker(
        request: Request,
        user: dict = Depends(get_current_user),
    ) -> dict:
        await _require_step_up_token(request)
        enforce_step_up_role(user, allowed)
        return user

    return _checker
