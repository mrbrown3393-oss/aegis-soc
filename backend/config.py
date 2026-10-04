"""Aegis SOC configuration and production safety validation."""
from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MONGO_URL: str = "mongodb://localhost:27017"
    DB_NAME: str = "aegis_soc"
    JWT_SECRET: str = "change-me-to-a-64-char-hex-string"
    JWT_PREVIOUS_SECRET: str = ""
    ADMIN_EMAIL: str = "william.brown@aegis-soc.io"
    ADMIN_PASSWORD: str = "change-me"
    ANALYST_EMAIL: str = "analyst@aegis-soc.io"
    ANALYST_PASSWORD: str = "change-me"
    FRONTEND_URL: str = "http://localhost:3000"
    CORS_ORIGINS: str = "http://localhost:3000"
    MONGO_TLS: bool = True
    MONGO_TLS_CA_FILE: str = ""
    MONGO_TLS_CERT_KEY_FILE: str = ""
    MONGO_TLS_ALLOW_INVALID_CERTS: bool = False
    TRUSTED_PROXY_IPS: str = ""
    SSO_BASE_URL: str = "http://localhost:8001"
    SAML_ENABLED: bool = False
    OIDC_ENABLED: bool = False
    SAML_IDP_METADATA_URL: str = ""
    SAML_IDP_ENTITY_ID: str = ""
    SAML_IDP_SSO_URL: str = ""
    SAML_IDP_X509_CERT: str = ""
    OIDC_ISSUER_URL: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_SCOPES: str = "openid profile email"
    OIDC_REDIRECT_URI: str = ""
    OIDC_SUCCESS_REDIRECT_URL: str = "http://localhost:3000"
    OIDC_TENANT_CLAIM: str = "tenant"
    OIDC_ALLOWED_TENANTS: str = "private"
    OIDC_ROLE_CLAIM: str = "role"
    OIDC_REQUIRE_MFA_CLAIM: bool = True
    OIDC_MFA_AMR_VALUES: str = "mfa"
    MFA_REQUIRED: bool = True
    MFA_MASTER_SECRET: str = ""
    AEGIS_ENV: str = "development"
    CORS_ALLOW_METHODS: str = "GET,POST,PATCH,DELETE,OPTIONS"
    CORS_ALLOW_HEADERS: str = "Content-Type,Authorization,X-Requested-With"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

# Token / lockout constants
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_DAYS = 7
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15
AUTH_RATE_LIMIT_PER_MINUTE = 120
IDLE_TIMEOUT_MINUTES = 15


def validate_security_settings() -> None:
    """Fail closed on unsafe production defaults before the API starts."""
    if settings.AEGIS_ENV.lower() != "production":
        return
    if settings.JWT_SECRET == "change-me-to-a-64-char-hex-string" or len(settings.JWT_SECRET) < 32:
        raise RuntimeError("Production requires a strong JWT_SECRET of at least 32 characters.")
    if settings.JWT_PREVIOUS_SECRET and len(settings.JWT_PREVIOUS_SECRET) < 32:
        raise RuntimeError("Production JWT_PREVIOUS_SECRET must be empty or at least 32 characters.")
    if settings.ADMIN_PASSWORD == "change-me" or settings.ANALYST_PASSWORD == "change-me":
        raise RuntimeError("Production requires non-default operator passwords.")
    if not settings.MFA_REQUIRED:
        raise RuntimeError("Production requires MFA_REQUIRED=true.")
    if len(settings.MFA_MASTER_SECRET) < 32:
        raise RuntimeError("Production requires a strong MFA_MASTER_SECRET of at least 32 characters.")
    if not settings.MONGO_TLS:
        raise RuntimeError("Production requires MongoDB TLS.")
    if settings.MONGO_TLS_ALLOW_INVALID_CERTS:
        raise RuntimeError("Production cannot allow invalid MongoDB TLS certificates.")
    origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
    if "*" in origins:
        raise RuntimeError("Production CORS cannot use wildcard origins.")
    if not origins or not settings.FRONTEND_URL.strip():
        raise RuntimeError("Production requires an explicit frontend/CORS origin.")
    if not settings.FRONTEND_URL.lower().startswith("https://"):
        raise RuntimeError("Production FRONTEND_URL must use HTTPS.")
    if settings.OIDC_ENABLED:
        oidc_required = {
            "OIDC_ISSUER_URL": settings.OIDC_ISSUER_URL,
            "OIDC_CLIENT_ID": settings.OIDC_CLIENT_ID,
            "OIDC_CLIENT_SECRET": settings.OIDC_CLIENT_SECRET,
            "OIDC_REDIRECT_URI": settings.OIDC_REDIRECT_URI,
        }
        if any(not value.strip() for value in oidc_required.values()):
            raise RuntimeError("Production OIDC requires issuer, client, secret, and redirect URI.")
        if not settings.OIDC_REDIRECT_URI.lower().startswith("https://"):
            raise RuntimeError("Production OIDC_REDIRECT_URI must use HTTPS.")
        if not settings.OIDC_SUCCESS_REDIRECT_URL.lower().startswith("https://"):
            raise RuntimeError("Production OIDC_SUCCESS_REDIRECT_URL must use HTTPS.")
        if not settings.OIDC_ALLOWED_TENANTS.strip():
            raise RuntimeError("Production OIDC requires an explicit tenant allowlist.")
        if settings.OIDC_REQUIRE_MFA_CLAIM and not settings.OIDC_MFA_AMR_VALUES.strip():
            raise RuntimeError("Production OIDC MFA enforcement requires at least one allowed AMR value.")


def allowed_csrf_origins() -> set[str]:
    return {
        origin.strip().rstrip("/")
        for origin in settings.CORS_ORIGINS.split(",")
        if origin.strip()
    } | {settings.FRONTEND_URL.strip().rstrip("/")}
