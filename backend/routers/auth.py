"""Authentication routes: register, login, MFA, logout, refresh, password reset."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from session_security import create_bound_auth_session

from auth_helpers import (
    hash_password,
    verify_password,
    generate_mfa_secret,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    legacy_mfa_secret,
    verify_totp,
    create_mfa_pending_token,
    create_mfa_challenge,
    consume_mfa_challenge,
    invalidate_mfa_challenges,
    set_mfa_pending_cookie,
    clear_mfa_pending_cookie,
    pending_user,
    create_access_token,
    create_refresh_token,
    decode_jwt,
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
from step_up import create_step_up_token
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
        await invalidate_mfa_challenges(user["id"])
        challenge_id = await create_mfa_challenge(user["id"])
        set_mfa_pending_cookie(response, create_mfa_pending_token(user["id"], challenge_id))
        return {
            "message": "MFA verification required",
            "mfaRequired": True,
            "mfaEnrolled": bool(user.get("mfaEnrolledAt")),
            "email": user["email"],
            "role": user["role"],
            "tenant": user["tenant"],
        }
    session_id, refresh_jti = await create_bound_auth_session(user["id"], request)
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], session_id)
    refresh = create_refresh_token(user["id"], session_id, refresh_jti)
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "login", "auth", request, user["tenant"])
    return {"message": "Logged in", "email": user["email"], "role": user["role"], "tenant": user["tenant"]}


@router.get("/auth/mfa/setup")
async def mfa_setup(request: Request):
    payload = await pending_user(request)
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("mfaEnrolledAt"):
        raise HTTPException(status_code=409, detail="MFA is already enrolled")

    if not user.get("mfa_secret_enc"):
        secret = generate_mfa_secret()
        await db.users.update_one(
            {"id": user["id"], "mfa_secret_enc": {"$exists": False}},
            {"$set": {"mfa_secret_enc": encrypt_mfa_secret(user["id"], secret)}},
        )
        user = await db.users.find_one({"id": user["id"]})
    encrypted = user.get("mfa_secret_enc")
    if not encrypted:
        raise HTTPException(status_code=500, detail="MFA setup unavailable")
    secret = decrypt_mfa_secret(user["id"], encrypted)
    otpauth = f"otpauth://totp/AegisSOC:{user['email']}?secret={secret}&issuer=AegisSOC"
    return {"secret": secret, "otpauth": otpauth}


@router.post("/auth/mfa/verify")
async def mfa_verify(body: dict, request: Request, response: Response):
    payload = await pending_user(request)
    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await check_mfa_lockout(ip, payload["sub"])
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    code = str(body.get("code", "")).strip()

    encrypted = user.get("mfa_secret_enc")
    if encrypted:
        secret = decrypt_mfa_secret(user["id"], encrypted)
        if not verify_totp(secret, code):
            await record_mfa_failure(ip, user["id"])
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    elif user.get("mfaEnrolledAt"):
        # One-time migration path for accounts enrolled before randomized
        # per-user secrets were introduced. A valid legacy code proves control
        # of the old factor, but does not grant a session; it forces re-enrollment.
        if not verify_totp(legacy_mfa_secret(user["id"]), code):
            await record_mfa_failure(ip, user["id"])
            raise HTTPException(status_code=401, detail="Invalid MFA code")
        new_secret = generate_mfa_secret()
        await db.users.update_one(
            {"id": user["id"], "mfaEnrolledAt": {"$exists": True}, "mfa_secret_enc": {"$exists": False}},
            {
                "$set": {"mfa_secret_enc": encrypt_mfa_secret(user["id"], new_secret)},
                "$unset": {"mfaEnrolledAt": ""},
            },
        )
        await clear_mfa_failures(ip, user["id"])
        raise HTTPException(status_code=409, detail="MFA re-enrollment required")
    else:
        raise HTTPException(status_code=409, detail="MFA setup required")

    await clear_mfa_failures(ip, user["id"])
    if not await consume_mfa_challenge(payload["cid"], user["id"]):
        clear_mfa_pending_cookie(response)
        raise HTTPException(status_code=401, detail="MFA challenge already used or expired")
    if not user.get("mfaEnrolledAt"):
        await db.users.update_one(
            {"id": user["id"], "mfa_secret_enc": {"$exists": True}},
            {"$set": {"mfaEnrolledAt": datetime.now(timezone.utc).isoformat()}},
        )
    clear_mfa_pending_cookie(response)
    session_id, refresh_jti = await create_bound_auth_session(user["id"], request)
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


@router.post("/auth/step-up")
async def step_up(body: dict, request: Request, response: Response, user: dict = Depends(get_current_user)):
    """Re-authenticate with the enrolled TOTP factor for high-impact actions."""
    code = str(body.get("code", "")).strip()
    encrypted = user.get("mfa_secret_enc")
    if not encrypted or not user.get("mfaEnrolledAt"):
        raise HTTPException(status_code=409, detail="MFA enrollment required")
    ip = forwarded_client_ip(request, settings.TRUSTED_PROXY_IPS)
    await check_mfa_lockout(ip, user["id"])
    secret = decrypt_mfa_secret(user["id"], encrypted)
    if not verify_totp(secret, code):
        await record_mfa_failure(ip, user["id"])
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    await clear_mfa_failures(ip, user["id"])
    access_payload = decode_jwt(request.cookies["access_token"])
    token = create_step_up_token(access_payload["sid"], device_fingerprint(request))
    secure = settings.AEGIS_ENV.lower() == "production"
    response.set_cookie("step_up", token, httponly=True, secure=secure, samesite="strict" if secure else "lax", max_age=600, path="/")
    await write_audit(user["email"], "step_up_verify", "auth", request, user.get("tenant", ""))
    return {"message": "Step-up authentication verified", "expiresIn": 600}


@router.post("/auth/logout")
async def logout(request: Request, response: Response, user: dict = Depends(get_current_user)):
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = decode_jwt(token, verify_exp=False)
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
        payload = decode_jwt(token)
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

    # Refresh is an authenticated session operation too: do not let a stolen
    # refresh cookie move a bound session to a different device context.
    current_fingerprint = device_fingerprint(request)
    stored_fingerprint = session.get("device_fingerprint")
    if stored_fingerprint and not secrets.compare_digest(stored_fingerprint, current_fingerprint):
        await db.auth_sessions.update_one(
            {
                "session_id": payload["sid"],
                "user_id": payload["sub"],
                "refresh_jti": payload["jti"],
                "revoked_at": None,
            },
            {"$set": {
                "revoked_at": datetime.now(timezone.utc),
                "revoke_reason": "device_context_changed_on_refresh",
            }},
        )
        raise HTTPException(status_code=401, detail="Session device context changed")

    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    new_jti = secrets.token_urlsafe(24)
    rotated = await db.auth_sessions.update_one(
        {
            "session_id": payload["sid"],
            "user_id": payload["sub"],
            "refresh_jti": payload["jti"],
            "revoked_at": None,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        },
        {"$set": {"refresh_jti": new_jti}},
    )
    if getattr(rotated, "modified_count", 0) != 1:
        raise HTTPException(status_code=401, detail="Refresh token already used or session changed")

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
