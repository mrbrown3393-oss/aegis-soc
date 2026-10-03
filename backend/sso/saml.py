"""
Aegis SOC — SAML 2.0 Service Provider (FastAPI + python3-saml).

Routes (mounted under /api/auth/sso/saml):
  GET  /login     — SP-initiated SSO redirect to IdP
  POST /acs       — Assertion Consumer Service (IdP POSTs the SAMLResponse)
  GET  /metadata  — SP metadata XML for IdP registration

Environment:
  SAML_ENABLED=true
  SAML_SP_ENTITY_ID=https://aegis.example.com/api/auth/sso/saml/metadata
  SAML_SP_ACS_URL=https://aegis.example.com/api/auth/sso/saml/acs
  SAML_IDP_ENTITY_ID=...
  SAML_IDP_SSO_URL=https://idp.example.com/sso
  SAML_IDP_X509_CERT=-----BEGIN CERTIFICATE-----... (single line, \n escaped)
  SAML_DEFAULT_ROLE=viewer
  SAML_DEFAULT_TENANT=private
  SAML_ADMIN_GROUP=aegis-admins

Hardening notes:
- strict=True, signatures required, assertions must be signed
- wantAssertionsSigned + wantMessagesSigned enforce signed responses
- NameID is treated as the immutable identity; email is required
- Local password login for federated users is disabled (password_hash=None)
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, PlainTextResponse


def _enabled() -> bool:
    return os.getenv("SAML_ENABLED", "false").lower() == "true"


def _saml_settings() -> dict:
    cert = os.environ["SAML_IDP_X509_CERT"].replace("\\n", "\n")
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": os.environ["SAML_SP_ENTITY_ID"],
            "assertionConsumerService": {
                "url": os.environ["SAML_SP_ACS_URL"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": os.environ["SAML_IDP_ENTITY_ID"],
            "singleSignOnService": {
                "url": os.environ["SAML_IDP_SSO_URL"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": True,
            "wantAssertionsEncrypted": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            "rejectDeprecatedAlgorithm": True,
        },
    }


async def _prepare_saml_request(request: Request, post_data: dict | None = None) -> dict:
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


def build_saml_router(db, create_access_token, create_refresh_token, set_auth_cookies, write_audit) -> APIRouter:
    router = APIRouter(prefix="/api/auth/sso/saml", tags=["sso-saml"])

    if not _enabled():
        @router.get("/login")
        async def disabled():
            raise HTTPException(status_code=404, detail="SAML SSO is not enabled")
        return router

    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    @router.get("/login")
    async def login(request: Request):
        req = await _prepare_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings())
        return RedirectResponse(auth.login())

    @router.post("/acs")
    async def acs(request: Request, response: Response):
        form = await request.form()
        post_data = {k: str(v) for k, v in form.items()}
        req = await _prepare_saml_request(request, post_data)
        auth = OneLogin_Saml2_Auth(req, _saml_settings())
        auth.process_response()

        errors = auth.get_errors()
        if errors or not auth.is_authenticated():
            await write_audit("unknown", "sso_login_saml_failed", "auth", request)
            raise HTTPException(status_code=401, detail="SAML authentication failed")

        attrs = auth.get_attributes()
        email = (auth.get_nameid() or "").lower()
        if not email and attrs.get("email"):
            email = attrs["email"][0].lower()
        if not email:
            raise HTTPException(status_code=400, detail="Assertion missing email/NameID")

        groups = attrs.get("groups", [])
        admin_group = os.getenv("SAML_ADMIN_GROUP", "aegis-admins")
        role = "admin" if admin_group in groups else os.getenv("SAML_DEFAULT_ROLE", "viewer")
        tenant = os.getenv("SAML_DEFAULT_TENANT", "private")

        user = await db.users.find_one({"email": email})
        if not user:
            user = {
                "id": secrets.token_hex(16),
                "email": email,
                "name": (attrs.get("displayName") or [email])[0],
                "role": role,
                "tenant": tenant,
                "sso": {"provider": "saml", "nameid": auth.get_nameid()},
                "password_hash": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await db.users.insert_one(user)
        elif user.get("disabled"):
            raise HTTPException(status_code=403, detail="Account disabled")

        access = create_access_token(user["id"], email, user["role"], user["tenant"])
        refresh = create_refresh_token(user["id"])
        set_auth_cookies(response, access, refresh)
        await write_audit(email, "sso_login_saml", "auth", request, user["tenant"])
        return {"message": "Logged in via SAML", "email": email, "role": user["role"], "tenant": user["tenant"]}

    @router.get("/metadata")
    async def metadata(request: Request):
        req = await _prepare_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings())
        xml = auth.get_settings().get_sp_metadata()
        errors = auth.get_settings().validate_metadata(xml)
        if errors:
            raise HTTPException(status_code=500, detail="SP metadata invalid")
        return PlainTextResponse(xml, media_type="application/samlmetadata+xml")

    return router
