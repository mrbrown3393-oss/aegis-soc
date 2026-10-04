"""Authentication routes: register, login, MFA, logout, refresh, password reset."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from auth_helpers import (
    hash_password,
    verify_password,
    mfa_secret,
    verify_totp,
    create_mfa_pending_token,
    set_mfa_pending_cookie,
    clear_mfa_pending_cookie,
    pending_user,
    create_access_token,
    create_refresh_token,
    create_auth_session,
    revoke_session,
    revoke_user_sessions,
    set_auth_cookies,
    clear_auth_cookies,
    check_lockout,
    record_failed_attempt,
    clear_failed_attempts,
    check_password_reset_rate_limit,
    record_password_reset_attempt,
    check_mfa_lockout,
    record_mfa_failure,
    clear_mfa_failures,
)
from config import settings
from database import db
from deps import get_current_user, write_audit
from models import (
    RegisterRequest,
    LoginRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
)
from security_hardening import forwarded_client_ip
import jwt

router = APIRouter(tags=["auth"])


@router.get("/")
async def health():
    return {"status": "ok", "service": "aegis-soc-api", "version": "2.1.0"}


@router.post("/auth/register")
async def register(body: RegisterRequest, request: Request, response: Response):
    if settings.AEGIS_ENV.lower() == "production":
        raise HTTPException(status_code=403, detail="Self-registration is disabled in production")
    if await db.users.find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = secrets.token_hex(16)
    await db.users.insert_one({
        "id": user_id,
        "email": body.email,
        "name": body.name,
        "role": "viewer",
        "tenant": "private",
        "password_hash": hash_password(body.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await write_audit(body.email, "register", "users", request, "private")
    return {"message": "Registered. Please sign in.", "email": body.email, "role": "viewer"}


@router.post("/auth/login")
async def login(body: LoginRequest, request: Request, response: Response):
    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await check_lockout(ip, body.email)
    user = await db.users.find_one({"email": body.email})
    if not user or not verify_password(body.password, user["password_hash"]):
        await record_failed_attempt(ip, body.email)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    await clear_failed_attempts(ip, body.email)
    if settings.MFA_REQUIRED:
        set_mfa_pending_cookie(response, create_mfa_pending_token(user["id"]))
        return {
            "message": "MFA verification required",
            "mfaRequired": True,
            "mfaEnrolled": bool(user.get("mfaEnrolledAt")),
            "email": user["email"],
            "role": user["role"],
            "tenant": user["tenant"],
        }
    session_id, refresh_jti = await create_auth_session(user["id"])
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], session_id)
    refresh = create_refresh_token(user["id"], session_id, refresh_jti)
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "login", "auth", request, user["tenant"])
    return {"message": "Logged in", "email": user["email"], "role": user["role"], "tenant": user["tenant"]}


@router.get("/auth/mfa/setup")
async def mfa_setup(request: Request):
    payload = pending_user(request)
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    secret = mfa_secret(user["id"])
    otpauth = f"otpauth://totp/AegisSOC:{user['email']}?secret={secret}&issuer=AegisSOC"
    return {"secret": secret, "otpauth": otpauth}


@router.post("/auth/mfa/verify")
async def mfa_verify(body: dict, request: Request, response: Response):
    payload = pending_user(request)
    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await check_mfa_lockout(ip, payload["sub"])
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    code = str(body.get("code", "")).strip()
    secret = mfa_secret(user["id"])
    if not verify_totp(secret, code):
        await record_mfa_failure(ip, user["id"])
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    await clear_mfa_failures(ip, user["id"])
    if not user.get("mfaEnrolledAt"):
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"mfaEnrolledAt": datetime.now(timezone.utc).isoformat()}},
        )
    clear_mfa_pending_cookie(response)
    session_id, refresh_jti = await create_auth_session(user["id"])
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], session_id)
    refresh = create_refresh_token(user["id"], session_id, refresh_jti)
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "mfa_verify", "auth", request, user["tenant"])
    return {
        "message": "MFA verified",
        "email": user["email"],
        "role": user["role"],
        "tenant": user["tenant"],
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response, user: dict = Depends(get_current_user)):
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
            if payload.get("sid"):
                await revoke_session(payload["sid"])
        except jwt.InvalidTokenError:
            pass
    clear_auth_cookies(response)
    await write_audit(user["email"], "logout", "auth", request, user.get("tenant", ""))
    return {"message": "Logged out"}


@router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@router.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    session = await db.auth_sessions.find_one({
        "session_id": payload["sid"],
        "user_id": payload["sub"],
        "refresh_jti": payload["jti"],
        "revoked_at": None,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if not session:
        raise HTTPException(status_code=401, detail="Session revoked or expired")

    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Rotate refresh token
    new_jti = secrets.token_urlsafe(24)
    await db.auth_sessions.update_one(
        {"session_id": payload["sid"]},
        {"$set": {"refresh_jti": new_jti}},
    )
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], payload["sid"])
    new_refresh = create_refresh_token(user["id"], payload["sid"], new_jti)
    set_auth_cookies(response, access, new_refresh)
    return {"message": "Token refreshed"}


@router.post("/auth/password-reset/request")
async def password_reset_request(body: PasswordResetRequest, request: Request):
    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await check_password_reset_rate_limit(ip, body.email)
    await record_password_reset_attempt(ip, body.email)
    user = await db.users.find_one({"email": body.email})
    if user:
        token = secrets.token_urlsafe(32)
        await db.password_reset_tokens.insert_one({
            "email": body.email,
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "used": False,
        })
        # Deliver the token through a dedicated email provider in deployment.
        # Never log reset tokens or include them in API responses.
    await write_audit(body.email, "password_reset_request", "auth", request)
    return {"message": "If the account exists, a reset link has been sent."}


@router.post("/auth/password-reset/confirm")
async def password_reset_confirm(body: PasswordResetConfirm, request: Request):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    record = await db.password_reset_tokens.find_one({"token_hash": token_hash, "used": False})
    if not record or record.get("expires_at", now) <= now:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    consumed = await db.password_reset_tokens.update_one(
        {
            "token_hash": token_hash,
            "used": False,
            "expires_at": {"$gt": now},
        },
        {"$set": {"used": True, "used_at": now}},
    )
    if consumed.modified_count != 1:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user = await db.users.find_one({"email": record["email"]})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    await db.users.update_one(
        {"email": record["email"]},
        {"$set": {"password_hash": hash_password(body.new_password)}},
    )
    await revoke_user_sessions(user["id"])
    await write_audit(record["email"], "password_reset_confirm", "auth", request)
    return {"message": "Password updated. Please log in."}
