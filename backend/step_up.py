"""Step-up authentication for high-impact actions."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import Depends, HTTPException, Request, status

from auth_helpers import decode_jwt, encode_jwt, verify_totp, decrypt_mfa_secret
from database import db
from deps import get_current_user
from zero_trust import device_fingerprint
import jwt


STEP_UP_MINUTES = 10


def create_step_up_token(session_id: str, fingerprint: str) -> str:
    now = datetime.now(timezone.utc)
    return encode_jwt({
        "sid": session_id,
        "fp": fingerprint,
        "type": "step_up",
        "exp": now + timedelta(minutes=STEP_UP_MINUTES),
        "iat": now,
    })


async def require_step_up(
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict:
    token = request.cookies.get("step_up")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up authentication required")
    try:
        payload = decode_jwt(token)
        if payload.get("type") != "step_up" or payload.get("sid") != request.cookies.get("_aegis_session_id"):
            # Session ID is intentionally not trusted from a client cookie; derive it from
            # the validated access token below.
            access = request.cookies.get("access_token")
            access_payload = decode_jwt(access) if access else {}
            if payload.get("type") != "step_up" or payload.get("sid") != access_payload.get("sid"):
                raise HTTPException(status_code=401, detail="Invalid step-up session")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid step-up token")
    if payload.get("fp") != device_fingerprint(request):
        raise HTTPException(status_code=401, detail="Step-up device context changed")
    return user
