"""Verification of short-lived, signed remote-edge admission decisions."""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import hmac
import json
import time

from fastapi import HTTPException, Request

from config import settings

_seen: dict[str, int] = {}


def _decode(value: str) -> dict:
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (binascii.Error, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=403, detail="Invalid edge decision") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=403, detail="Invalid edge decision")
    return payload


def _cleanup(now: int) -> None:
    expired = [key for key, expires in _seen.items() if expires < now]
    for key in expired:
        _seen.pop(key, None)


def verify_edge_decision(request: Request) -> None:
    if not settings.EDGE_ENFORCE_DECISION:
        return

    encoded = request.headers.get("x-aegis-edge-decision", "")
    signature = request.headers.get("x-aegis-edge-signature", "")
    if not encoded or not signature:
        raise HTTPException(status_code=403, detail="Missing edge admission decision")

    payload = _decode(encoded)
    required = {
        "allow", "risk_score", "reason", "decision_id", "issued_at",
        "expires_at", "method", "path", "client_ip", "audience", "nonce",
    }
    if set(payload) != required:
        raise HTTPException(status_code=403, detail="Invalid edge decision fields")

    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(settings.EDGE_VERIFY_SECRET.encode("utf-8"), canonical, sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=403, detail="Invalid edge decision signature")

        now = int(time.time())
        issued_at = int(payload["issued_at"])
        expires_at = int(payload["expires_at"])
        risk_score = int(payload["risk_score"])
        method = str(payload["method"]).upper()
        path = str(payload["path"])
        audience = str(payload["audience"])
        decision_id = str(payload["decision_id"])
        nonce = str(payload["nonce"])
        client_ip = str(payload["client_ip"])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=403, detail="Invalid edge decision values") from exc

    skew = settings.EDGE_MAX_CLOCK_SKEW_SECONDS
    if audience != settings.EDGE_AUDIENCE:
        raise HTTPException(status_code=403, detail="Invalid edge decision audience")
    if method != request.method.upper() or path != request.url.path:
        raise HTTPException(status_code=403, detail="Edge decision request mismatch")
    if expires_at <= now - skew or issued_at > now + skew or expires_at <= issued_at:
        raise HTTPException(status_code=403, detail="Expired or not-yet-valid edge decision")
    if expires_at - issued_at > 15 + skew:
        raise HTTPException(status_code=403, detail="Edge decision lifetime exceeds policy")
    if not 0 <= risk_score <= 100 or not decision_id or not nonce or not client_ip:
        raise HTTPException(status_code=403, detail="Invalid edge decision claims")

    trusted_ip = request.headers.get(settings.EDGE_TRUSTED_CLIENT_IP_HEADER.lower(), "")
    if not trusted_ip or not hmac.compare_digest(trusted_ip, client_ip):
        raise HTTPException(status_code=403, detail="Edge client identity mismatch")

    _cleanup(now)
    replay_key = f"{decision_id}:{nonce}"
    if replay_key in _seen:
        raise HTTPException(status_code=403, detail="Edge decision replay detected")
    _seen[replay_key] = expires_at

    if payload["allow"] is not True:
        raise HTTPException(status_code=403, detail="Edge admission denied")
