"""
Aegis SOC — one-call security wiring for the FastAPI app.

Usage in backend/server.py (after `app = FastAPI(...)` and db setup):

    from security_setup import install_security
    install_security(app, db=db, settings=settings,
                     create_access_token=create_access_token,
                     create_refresh_token=create_refresh_token,
                     set_auth_cookies=set_auth_cookies,
                     write_audit=write_audit,
                     get_current_user=get_current_user,
                     require_role=require_role,
                     tenant_filter=tenant_filter)

Installs, in order:
  1. Starlette SessionMiddleware (required for OIDC OAuth state) when SSO enabled
  2. Strict security headers middleware
  3. Zero Trust PEP middleware (continuous per-request verification)
  4. SAML / OIDC SSO routers (when *_ENABLED=true)
  5. Security operations API (threat tracing + quarantine)
"""

from __future__ import annotations

import os


def install_security(app, *, db, settings, create_access_token, create_refresh_token,
                     set_auth_cookies, write_audit, get_current_user, require_role, tenant_filter):
    # 1) Session middleware for OAuth state/nonce (OIDC) — cookie-based, secret from env
    if os.getenv("OIDC_ENABLED", "false").lower() == "true":
        from starlette.middleware.sessions import SessionMiddleware
        app.add_middleware(SessionMiddleware, secret_key=settings.JWT_SECRET,
                           same_site="lax", https_only=True)

    # 2) Strict security headers
    from middleware.security_headers import SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)

    # 3) Zero Trust PEP — continuous verification, fail-closed
    if os.getenv("ZT_PEP_ENABLED", "true").lower() == "true":
        from zerotrust.pep import ZeroTrustPEPMiddleware

        async def _audit(actor, action, resource, request):
            await write_audit(actor, action, resource, request)

        app.add_middleware(ZeroTrustPEPMiddleware, jwt_secret=settings.JWT_SECRET, audit=_audit)

    # 4) Federated SSO routers
    from sso.oidc import build_oidc_router
    from sso.saml import build_saml_router

    app.include_router(build_oidc_router(db, create_access_token, create_refresh_token,
                                         set_auth_cookies, write_audit))
    app.include_router(build_saml_router(db, create_access_token, create_refresh_token,
                                         set_auth_cookies, write_audit))

    # 5) Security operations API (tracing + quarantine)
    from security.routes import build_security_router
    app.include_router(build_security_router(db, get_current_user, require_role,
                                             tenant_filter, write_audit))

    return app
