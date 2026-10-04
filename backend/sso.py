"""Production OIDC authorization-code flow with state, nonce, PKCE and strict ID-token validation."""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from auth_helpers import create_access_token, create_auth_session, create_refresh_token, set_auth_cookies
from config import settings
from database import db
from deps import write_audit

sso_router = APIRouter(prefix="/api/auth/sso", tags=["federated-sso"])

_STATE_TTL = timedelta(minutes=10)
_HTTP_TIMEOUT = httpx.Timeout(5.0, connect=5.0)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _configured() -> bool:
    return bool(
        settings.OIDC_ENABLED
        and settings.OIDC_ISSUER_URL
        and settings.OIDC_CLIENT_ID
        and settings.OIDC_CLIENT_SECRET
        and settings.OIDC_REDIRECT_URI
    )


def _issuer() -> str:
    return settings.OIDC_ISSUER_URL.rstrip("/")


def _trusted_provider_endpoint(value: str) -> str:
    parsed = urlparse(value)
    issuer = urlparse(_issuer())
    if parsed.scheme != "https" or parsed.hostname != issuer.hostname:
        raise HTTPException(503, "OIDC provider endpoint is not trusted")
    return value


async def _discovery() -> dict:
    if not _configured():
        raise HTTPException(503, "OIDC is not completely configured")
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(f"{_issuer()}/.well-known/openid-configuration")
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "OIDC provider metadata is unavailable")
    if data.get("issuer", "").rstrip("/") != _issuer():
        raise HTTPException(503, "OIDC issuer metadata mismatch")
    required = {"authorization_endpoint", "token_endpoint", "jwks_uri"}
    if not required.issubset(data):
        raise HTTPException(503, "OIDC provider metadata is incomplete")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        data[field] = _trusted_provider_endpoint(str(data[field]))
    return data


async def _jwks(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "OIDC signing keys are unavailable")
    if not isinstance(data.get("keys"), list):
        raise HTTPException(503, "OIDC signing keys are invalid")
    return data


def _verify_id_token(token: str, jwks: dict, nonce: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid OIDC ID token")

    allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
    if alg not in allowed or not kid:
        raise HTTPException(401, "Unsupported OIDC signing algorithm")

    jwk = next((key for key in jwks["keys"] if key.get("kid") == kid), None)
    if not jwk:
        raise HTTPException(401, "OIDC signing key not found")

    try:
        key = jwt.algorithms.get_default_algorithms()[alg].from_jwk(jwk)
        claims = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            audience=settings.OIDC_CLIENT_ID,
            issuer=_issuer(),
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            leeway=30,
        )
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "OIDC ID token validation failed")

    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise HTTPException(401, "OIDC nonce validation failed")
    if settings.OIDC_REQUIRE_MFA_CLAIM:
        amr = claims.get("amr", [])
        if not isinstance(amr, list) or not any(
            secrets.compare_digest(str(value), required)
            for value in amr
            for required in settings.OIDC_MFA_AMR_VALUES.split(",")
            if required.strip()
        ):
            raise HTTPException(403, "OIDC authentication does not satisfy MFA policy")
    return claims


def _tenant_and_role(claims: dict) -> tuple[str, str]:
    tenant = str(claims.get(settings.OIDC_TENANT_CLAIM, "")).strip().lower()
    allowed = {item.strip().lower() for item in settings.OIDC_ALLOWED_TENANTS.split(",") if item.strip()}
    if not tenant or tenant not in allowed:
        raise HTTPException(403, "OIDC identity is not mapped to an allowed tenant")
    role = str(claims.get(settings.OIDC_ROLE_CLAIM, "viewer")).strip().lower()
    if role not in {"viewer", "analyst", "admin"}:
        role = "viewer"
    return tenant, role


@sso_router.get("/config")
async def sso_config():
    return {
        "saml": {
            "enabled": settings.SAML_ENABLED,
            "configured": bool(settings.SAML_IDP_SSO_URL and settings.SAML_IDP_ENTITY_ID and settings.SAML_IDP_X509_CERT),
        },
        "oidc": {"enabled": settings.OIDC_ENABLED, "configured": _configured()},
    }


@sso_router.get("/oidc/login")
async def oidc_login():
    metadata = await _discovery()
    state = _b64(secrets.token_bytes(32))
    nonce = _b64(secrets.token_bytes(32))
    verifier = _b64(secrets.token_bytes(48))
    challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())
    expires = datetime.now(timezone.utc) + _STATE_TTL

    await db.sso_oidc_states.insert_one({
        "state_hash": _sha256(state),
        "nonce": nonce,
        "code_verifier": verifier,
        "expires_at": expires,
        "used": False,
    })
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "scope": settings.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{metadata['authorization_endpoint']}?{urlencode(params)}", status_code=302)


@sso_router.get("/oidc/callback")
async def oidc_callback(request: Request):
    error = request.query_params.get("error")
    if error:
        raise HTTPException(401, "OIDC authentication was not completed")
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    if not state or not code or len(state) > 256 or len(code) > 4096:
        raise HTTPException(400, "Invalid OIDC callback")

    now = datetime.now(timezone.utc)
    record = await db.sso_oidc_states.find_one_and_update(
        {"state_hash": _sha256(state), "used": False, "expires_at": {"$gt": now}},
        {"$set": {"used": True, "used_at": now}},
    )
    if not record:
        raise HTTPException(401, "Invalid or expired OIDC state")
    nonce = record["nonce"]
    verifier = record["code_verifier"]

    metadata = await _discovery()
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
            response = await client.post(
                metadata["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.OIDC_REDIRECT_URI,
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "code_verifier": verifier,
                },
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            tokens = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(401, "OIDC token exchange failed")

    id_token = tokens.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise HTTPException(401, "OIDC provider did not return an ID token")
    claims = _verify_id_token(id_token, await _jwks(metadata["jwks_uri"]), nonce)

    subject = str(claims.get("sub", "")).strip()
    email = str(claims.get("email", "")).strip().lower()
    if not subject or not email:
        raise HTTPException(403, "OIDC identity is missing required subject or email")
    tenant, role = _tenant_and_role(claims)

    user = await db.users.find_one({"oidc_issuer": _issuer(), "oidc_sub": subject})
    if not user:
        user = await db.users.find_one({"email": email})
        if user and not settings.OIDC_ALLOW_EMAIL_LINKING:
            raise HTTPException(403, "Existing account requires explicit OIDC provider linking")
    if user:
        if user.get("oidc_issuer") and user.get("oidc_issuer") != _issuer():
            raise HTTPException(403, "Account is bound to a different identity provider")
        if user.get("tenant") != tenant:
            raise HTTPException(403, "OIDC tenant mapping does not match the account")
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"oidc_issuer": _issuer(), "oidc_sub": subject, "oidc_last_login_at": now}},
        )
    else:
        user_id = secrets.token_hex(16)
        await db.users.insert_one({
            "id": user_id,
            "email": email,
            "name": str(claims.get("name") or claims.get("preferred_username") or email)[:200],
            "role": role,
            "tenant": tenant,
            "oidc_issuer": _issuer(),
            "oidc_sub": subject,
            "oidc_last_login_at": now,
            "created_at": now.isoformat(),
        })
        user = await db.users.find_one({"id": user_id})

    session_id, refresh_jti = await create_auth_session(user["id"])
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], session_id)
    refresh = create_refresh_token(user["id"], session_id, refresh_jti)
    response = RedirectResponse(settings.OIDC_SUCCESS_REDIRECT_URL, status_code=303)
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "oidc_login", "auth", request, user["tenant"])
    return response


@sso_router.get("/saml/login")
async def saml_login():
    raise HTTPException(503, "SAML integration remains disabled until signed requests and IdP validation are configured")


@sso_router.post("/saml/acs")
async def saml_acs():
    raise HTTPException(503, "SAML integration remains disabled until assertion signature, audience, issuer, recipient, and replay validation are configured")
