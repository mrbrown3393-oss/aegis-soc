from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic_settings import BaseSettings


class SSOSettings(BaseSettings):
    SSO_BASE_URL:str="http://localhost:8001"; SAML_ENABLED:bool=False; OIDC_ENABLED:bool=False
    SAML_IDP_ENTITY_ID:str=""; SAML_IDP_SSO_URL:str=""
    OIDC_ISSUER_URL:str=""; OIDC_CLIENT_ID:str=""; OIDC_CLIENT_SECRET:str=""
    OIDC_SCOPES:str="openid profile email"
    class Config: env_file=".env"; extra="ignore"

settings=SSOSettings()
sso_router=APIRouter(prefix="/api/auth/sso",tags=["federated-sso"])

@sso_router.get("/config")
async def sso_config():
    return {"saml":{"enabled":settings.SAML_ENABLED,"configured":bool(settings.SAML_IDP_SSO_URL and settings.SAML_IDP_ENTITY_ID)},
            "oidc":{"enabled":settings.OIDC_ENABLED,"configured":bool(settings.OIDC_ISSUER_URL and settings.OIDC_CLIENT_ID)}}

@sso_router.get("/oidc/login")
async def oidc_login():
    # Fail closed until a complete provider integration is configured with
    # server-side state/nonce handling, PKCE, token exchange, issuer/audience
    # validation, JWKS signature validation, and tenant mapping.
    raise HTTPException(503, "OIDC integration is disabled until secure provider validation is configured")


@sso_router.get("/oidc/callback")
async def oidc_callback():
    raise HTTPException(503, "OIDC integration is disabled until secure provider validation is configured")


@sso_router.get("/saml/login")
async def saml_login():
    # Never emit an unsigned SAML AuthnRequest. A production SAML integration
    # must use a vetted SAML library and validate the IdP metadata/certificate.
    raise HTTPException(503, "SAML integration is disabled until signed requests and IdP validation are configured")


@sso_router.post("/saml/acs")
async def saml_acs():
    raise HTTPException(503, "SAML integration is disabled until assertion signature, audience, issuer, recipient, and replay validation are configured")
