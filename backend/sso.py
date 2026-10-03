from __future__ import annotations
import base64, secrets
from datetime import datetime, timezone
from urllib.parse import urlencode
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
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
    if not settings.OIDC_ENABLED or not settings.OIDC_ISSUER_URL or not settings.OIDC_CLIENT_ID: raise HTTPException(503,"OIDC is not configured")
    state=secrets.token_urlsafe(32); nonce=secrets.token_urlsafe(32)
    callback=f"{settings.SSO_BASE_URL.rstrip('/')}/api/auth/sso/oidc/callback"
    params={"client_id":settings.OIDC_CLIENT_ID,"response_type":"code","scope":settings.OIDC_SCOPES,"redirect_uri":callback,"state":state,"nonce":nonce}
    return RedirectResponse(f"{settings.OIDC_ISSUER_URL.rstrip('/')}/authorize?{urlencode(params)}")

@sso_router.get("/oidc/callback")
async def oidc_callback(request:Request,code:str,state:str):
    if not settings.OIDC_ENABLED: raise HTTPException(503,"OIDC is not configured")
    raise HTTPException(501,"OIDC callback requires provider token-exchange and server-side state configuration")

@sso_router.get("/saml/login")
async def saml_login():
    if not settings.SAML_ENABLED or not settings.SAML_IDP_SSO_URL or not settings.SAML_IDP_ENTITY_ID: raise HTTPException(503,"SAML is not configured")
    request_id="_"+secrets.token_hex(16); issue=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    acs=f"{settings.SSO_BASE_URL.rstrip('/')}/api/auth/sso/saml/acs"
    xml=f'<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0" IssueInstant="{issue}" AssertionConsumerServiceURL="{acs}"><saml:Issuer>{settings.SAML_IDP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>'
    return RedirectResponse(f"{settings.SAML_IDP_SSO_URL}?{urlencode({'SAMLRequest':base64.b64encode(xml.encode()).decode()})}")

@sso_router.post("/saml/acs")
async def saml_acs(request:Request):
    if not settings.SAML_ENABLED: raise HTTPException(503,"SAML is not configured")
    raise HTTPException(501,"SAML ACS requires assertion signature and audience validation configuration")
