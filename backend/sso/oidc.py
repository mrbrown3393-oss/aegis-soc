"""
Aegis SOC — OIDC federated SSO (FastAPI + Authlib).

Routes (mounted under /api/auth/sso/oidc):
  GET  /login     — redirect to IdP authorization endpoint
  GET  /callback  — handle authorization response, provision user, set cookies

Environment:
  OIDC_ENABLED=true
  OIDC_CLIENT_ID=...
  OIDC_CLIENT_SECRET=...
  OIDC_ISSUER=https://idp.example.com            (discovery via /.well-known/openid-configuration)
  OIDC_REDIRECT_URI=https://aegis.example.com/api/auth/sso/oidc/callback
  OIDC_DEFAULT_ROLE=viewer                       (role for just-in-time provisioned users)
  OIDC_DEFAULT_TENANT=private
  OIDC_ADMIN_GROUP=aegis-admins                  (optional group claim → admin role mapping)
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response


def _enabled() -> bool:
    return os.getenv("OIDC_ENABLED", "false").lower() == "true"


def build_oidc_router(db, create_access_token, create_refresh_token, set_auth_cookies, write_audit) -> APIRouter:
    """Factory keeps this module decoupled from server.py internals."""
    router = APIRouter(prefix="/api/auth/sso/oidc", tags=["sso-oidc"])

    if not _enabled():
        @router.get("/login")
        async def disabled():
            raise HTTPException(status_code=404, detail="OIDC SSO is not enabled")
        return router

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()
    oauth.register(
        name="aegis",
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        server_metadata_url=os.environ["OIDC_ISSUER"].rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email groups"},
    )

    @router.get("/login")
    async def login(request: Request):
        redirect_uri = os.getenv("OIDC_REDIRECT_URI") or str(request.url_for("oidc_callback"))
        return await oauth.aegis.authorize_redirect(request, redirect_uri)

    @router.get("/callback", name="oidc_callback")
    async def callback(request: Request, response: Response):
        token = await oauth.aegis.authorize_access_token(request)
        claims = token.get("userinfo") or {}
        email = (claims.get("email") or "").lower()
        if not email:
            raise HTTPException(status_code=400, detail="IdP did not return an email claim")

        groups = claims.get("groups") or []
        admin_group = os.getenv("OIDC_ADMIN_GROUP", "aegis-admins")
        role = "admin" if admin_group in groups else os.getenv("OIDC_DEFAULT_ROLE", "viewer")
        tenant = os.getenv("OIDC_DEFAULT_TENANT", "private")

        user = await db.users.find_one({"email": email})
        if not user:
            # Just-in-time provisioning — least privilege by default (AEG-AC-001).
            user = {
                "id": secrets.token_hex(16),
                "email": email,
                "name": claims.get("name") or email,
                "role": role,
                "tenant": tenant,
                "sso": {"provider": "oidc", "sub": claims.get("sub")},
                "password_hash": None,  # federated users have no local credential
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await db.users.insert_one(user)
        elif user.get("disabled"):
            raise HTTPException(status_code=403, detail="Account disabled")

        access = create_access_token(user["id"], email, user["role"], user["tenant"])
        refresh = create_refresh_token(user["id"])
        set_auth_cookies(response, access, refresh)
        await write_audit(email, "sso_login_oidc", "auth", request, user["tenant"])
        return {"message": "Logged in via OIDC", "email": email, "role": user["role"], "tenant": user["tenant"]}

    return router
