"""Password hashing, JWT, MFA/TOTP, sessions, and lockout helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from pymongo import ReturnDocument
from fastapi import HTTPException, Request, Response, status

from config import (
    settings,
    ACCESS_TOKEN_MINUTES,
    REFRESH_TOKEN_DAYS,
    LOCKOUT_THRESHOLD,
    LOCKOUT_MINUTES,
    AUTH_RATE_LIMIT_PER_MINUTE,
    IDLE_TIMEOUT_MINUTES,
)
from database import db
from security_hardening import forwarded_client_ip


# ── Password ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


# ── MFA / TOTP ──────────────────────────────────────────────────────────────

def mfa_secret(user_id: str) -> str:
    if len(settings.MFA_MASTER_SECRET) < 32:
        if settings.AEGIS_ENV.lower() == "production":
            raise RuntimeError("MFA master secret is not configured")
        master = "development-only-mfa-master"
    else:
        master = settings.MFA_MASTER_SECRET
    digest = hmac.new(master.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=")


def totp(secret_b32: str, timestamp: Optional[float] = None) -> str:
    now = datetime.now(timezone.utc).timestamp() if timestamp is None else timestamp
    counter = int(now // 30)
    key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(secret_b32: str, code: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    return any(
        hmac.compare_digest(totp(secret_b32, now + drift * 30), code)
        for drift in (-1, 0, 1)
    )


def create_mfa_pending_token(user_id: str) -> str:
    return jwt.encode(
        {
            "sub": user_id,
            "type": "mfa_pending",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "iat": datetime.now(timezone.utc),
        },
        settings.JWT_SECRET,
        algorithm="HS256",
    )


def set_mfa_pending_cookie(response: Response, token: str) -> None:
    secure = settings.AEGIS_ENV.lower() == "production"
    samesite = "strict" if secure else "lax"
    response.set_cookie(
        key="mfa_pending",
        value=token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=300,
        path="/",
    )


def clear_mfa_pending_cookie(response: Response) -> None:
    secure = settings.AEGIS_ENV.lower() == "production"
    samesite = "strict" if secure else "lax"
    response.delete_cookie(key="mfa_pending", path="/", samesite=samesite, secure=secure)


def pending_user(request: Request) -> dict:
    token = request.cookies.get("mfa_pending")
    if not token:
        raise HTTPException(status_code=401, detail="MFA verification required")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "mfa_pending":
            raise HTTPException(status_code=401, detail="Invalid MFA session")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid MFA session")
    return payload


# ── JWT + Sessions ──────────────────────────────────────────────────────────

def create_access_token(user_id: str, email: str, role: str, tenant: str, session_id: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "tenant": tenant,
        "sid": session_id,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def create_refresh_token(user_id: str, session_id: str, jti: str) -> str:
    payload = {
        "sub": user_id,
        "sid": session_id,
        "jti": jti,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


async def create_auth_session(user_id: str) -> tuple[str, str]:
    """Create a server-side session so logout/reset can revoke JWTs immediately."""
    session_id = secrets.token_urlsafe(24)
    refresh_jti = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    await db.auth_sessions.insert_one({
        "session_id": session_id,
        "user_id": user_id,
        "refresh_jti": refresh_jti,
        "created_at": now,
        "expires_at": now + timedelta(days=REFRESH_TOKEN_DAYS),
        "revoked_at": None,
        "last_activity_at": now,
    })
    return session_id, refresh_jti


async def revoke_session(session_id: str) -> None:
    await db.auth_sessions.update_one(
        {"session_id": session_id, "revoked_at": None},
        {"$set": {"revoked_at": datetime.now(timezone.utc)}},
    )


async def revoke_user_sessions(user_id: str) -> None:
    await db.auth_sessions.update_many(
        {"user_id": user_id, "revoked_at": None},
        {"$set": {"revoked_at": datetime.now(timezone.utc)}},
    )


async def active_session(session_id: str, user_id: str) -> bool:
    """Validate the server session and enforce a rolling idle timeout."""
    now = datetime.now(timezone.utc)
    session = await db.auth_sessions.find_one({
        "session_id": session_id,
        "user_id": user_id,
        "revoked_at": None,
        "expires_at": {"$gt": now},
    })
    if not session:
        return False
    last_activity = session.get("last_activity_at") or session.get("created_at") or now
    if isinstance(last_activity, str):
        try:
            last_activity = datetime.fromisoformat(last_activity)
        except ValueError:
            last_activity = now
    if last_activity.tzinfo is None:
        last_activity = last_activity.replace(tzinfo=timezone.utc)
    if now - last_activity > timedelta(minutes=IDLE_TIMEOUT_MINUTES):
        await revoke_session(session_id)
        return False
    await db.auth_sessions.update_one(
        {"session_id": session_id, "user_id": user_id, "revoked_at": None},
        {"$set": {"last_activity_at": now}},
    )
    return True


async def enforce_authenticated_rate_limit(ip: str, user_id: str) -> None:
    """Bound authenticated request volume with a Mongo-backed fixed window."""
    now = datetime.now(timezone.utc)
    window = now.replace(second=0, microsecond=0)
    key = f"auth:{user_id}:{ip}:{window.isoformat()}"
    record = await db.auth_rate_limits.find_one_and_update(
        {"key": key},
        {"$inc": {"count": 1}, "$setOnInsert": {"window": window}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    count = int(record.get("count", 0)) if record else 0
    if count > AUTH_RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    secure = settings.AEGIS_ENV.lower() == "production"
    samesite = "strict" if secure else "lax"
    response.set_cookie(
        key="access_token", value=access_token,
        httponly=True, secure=secure, samesite=samesite,
        max_age=ACCESS_TOKEN_MINUTES * 60, path="/",
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=secure, samesite=samesite,
        max_age=REFRESH_TOKEN_DAYS * 24 * 3600, path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    secure = settings.AEGIS_ENV.lower() == "production"
    samesite = "strict" if secure else "lax"
    response.delete_cookie(key="access_token", path="/", samesite=samesite, secure=secure)
    response.delete_cookie(key="refresh_token", path="/", samesite=samesite, secure=secure)


# ── Lockouts / rate limits ──────────────────────────────────────────────────

async def check_lockout(ip: str, email: str) -> None:
    key = f"{ip}:{email}"
    attempt = await db.login_attempts.find_one({"key": key})
    if attempt and attempt.get("locked_until") and datetime.now(timezone.utc) < attempt["locked_until"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again after {attempt['locked_until'].isoformat()}",
        )


async def record_failed_attempt(ip: str, email: str) -> None:
    key = f"{ip}:{email}"
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"key": key})
    count = (attempt.get("count", 0) if attempt else 0) + 1
    update = {"$set": {"count": count, "last_attempt": now}}
    if count >= LOCKOUT_THRESHOLD:
        update["$set"]["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
    await db.login_attempts.update_one({"key": key}, update, upsert=True)


async def clear_failed_attempts(ip: str, email: str) -> None:
    await db.login_attempts.delete_one({"key": f"{ip}:{email}"})


async def check_password_reset_rate_limit(ip: str, email: str) -> None:
    key = f"reset:{ip}:{email}"
    attempt = await db.login_attempts.find_one({"key": key})
    now = datetime.now(timezone.utc)
    if attempt and attempt.get("locked_until") and now < attempt["locked_until"]:
        raise HTTPException(status_code=429, detail="Too many password reset requests")


async def record_password_reset_attempt(ip: str, email: str) -> None:
    key = f"reset:{ip}:{email}"
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"key": key})
    count = (attempt.get("count", 0) if attempt else 0) + 1
    update = {"$set": {"count": count, "last_attempt": now}}
    if count >= LOCKOUT_THRESHOLD:
        update["$set"]["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
    await db.login_attempts.update_one({"key": key}, update, upsert=True)


async def check_mfa_lockout(ip: str, user_id: str) -> None:
    key = f"mfa:{ip}:{user_id}"
    attempt = await db.login_attempts.find_one({"key": key})
    if attempt and attempt.get("locked_until") and datetime.now(timezone.utc) < attempt["locked_until"]:
        raise HTTPException(status_code=429, detail="MFA temporarily locked. Try again later")


async def record_mfa_failure(ip: str, user_id: str) -> None:
    key = f"mfa:{ip}:{user_id}"
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"key": key})
    count = (attempt.get("count", 0) if attempt else 0) + 1
    update = {"$set": {"count": count, "last_attempt": now}}
    if count >= LOCKOUT_THRESHOLD:
        update["$set"]["locked_until"] = now + timedelta(minutes=LOCKOUT_MINUTES)
    await db.login_attempts.update_one({"key": key}, update, upsert=True)


async def clear_mfa_failures(ip: str, user_id: str) -> None:
    await db.login_attempts.delete_one({"key": f"mfa:{ip}:{user_id}"})
