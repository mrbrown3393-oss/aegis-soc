import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

os.environ.update({
    "MONGO_URL": "mongodb://localhost:27017",
    "DB_NAME": "aegis_test",
    "JWT_SECRET": "test-secret-not-for-production",
    "ADMIN_EMAIL": "admin@test.io",
    "ADMIN_PASSWORD": "TestPass123!",
    "ANALYST_EMAIL": "analyst@test.io",
    "ANALYST_PASSWORD": "TestPass123!",
    "FRONTEND_URL": "http://localhost:3000",
    "CORS_ORIGINS": "http://localhost:3000",
    "MONGO_TLS": "false",
    "AEGIS_ENV": "test",
})


def test_backend_imports_and_security_routes():
    from server import app

    paths = {route.path for route in app.routes}
    assert "/api/" in paths
    assert "/api/security/telemetry/fuse" in paths
    assert "/api/security/quarantine" in paths
    assert "/api/auth/sso/oidc/login" in paths
    assert "/api/auth/sso/saml/login" in paths


def test_security_headers_middleware_is_registered():
    from server import app

    middleware_names = {m.cls.__name__ for m in app.user_middleware}
    assert "SecurityHeadersMiddleware" in middleware_names


def test_proxy_ip_ignores_untrusted_forwarded_header():
    from security_hardening import forwarded_client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"203.0.113.10")],
        "client": ("198.51.100.20", 1234),
        "scheme": "http",
        "server": ("localhost", 80),
        "query_string": b"",
    }
    request = Request(scope)
    assert forwarded_client_ip(request, "10.0.0.0/8") == "198.51.100.20"
    assert forwarded_client_ip(request, "198.51.100.0/24") == "203.0.113.10"


def test_production_rejects_unsafe_defaults(monkeypatch):
    from server import settings, validate_security_settings

    monkeypatch.setattr(settings, "AEGIS_ENV", "production")
    monkeypatch.setattr(settings, "JWT_SECRET", "change-me-to-a-64-char-hex-string")
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "change-me")
    monkeypatch.setattr(settings, "ANALYST_PASSWORD", "change-me")
    monkeypatch.setattr(settings, "MONGO_TLS", True)
    monkeypatch.setattr(settings, "MONGO_TLS_ALLOW_INVALID_CERTS", False)
    monkeypatch.setattr(settings, "CORS_ORIGINS", "https://console.example.com")
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://console.example.com")

    import pytest
    with pytest.raises(RuntimeError, match="strong JWT_SECRET"):
        validate_security_settings()


def test_production_rejects_wildcard_cors(monkeypatch):
    from server import settings, validate_security_settings

    monkeypatch.setattr(settings, "AEGIS_ENV", "production")
    monkeypatch.setattr(settings, "JWT_SECRET", "x" * 64)
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "real-production-password")
    monkeypatch.setattr(settings, "ANALYST_PASSWORD", "real-production-password")
    monkeypatch.setattr(settings, "MONGO_TLS", True)
    monkeypatch.setattr(settings, "MONGO_TLS_ALLOW_INVALID_CERTS", False)
    monkeypatch.setattr(settings, "CORS_ORIGINS", "*")
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://console.example.com")

    import pytest
    with pytest.raises(RuntimeError, match="wildcard origins"):
        validate_security_settings()


def test_csrf_guard_blocks_cross_origin_authenticated_mutation():
    from fastapi.testclient import TestClient
    from server import app

    client = TestClient(app)
    client.cookies.set("access_token", "test-cookie")
    response = client.post("/api/auth/refresh", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-origin request blocked"


def test_csrf_guard_allows_configured_origin():
    from fastapi.testclient import TestClient
    from server import app

    client = TestClient(app)
    client.cookies.set("access_token", "test-cookie")
    response = client.post("/api/auth/refresh", headers={"Origin": "http://localhost:3000"})
    # The CSRF guard must allow the configured origin; downstream auth may reject
    # the intentionally fake token, but it must not reject it as cross-origin.
    assert response.status_code != 403


def test_totp_accepts_current_and_adjacent_time_step(monkeypatch):
    from server import _mfa_secret, _totp, _verify_totp, settings

    monkeypatch.setattr(settings, "MFA_MASTER_SECRET", "m" * 64)
    monkeypatch.setattr(settings, "AEGIS_ENV", "test")
    secret = _mfa_secret("test-user")
    code = _totp(secret, 1_000_000)
    assert _verify_totp(secret, code)
    assert _verify_totp(secret, _totp(secret, 1_000_030))
    assert not _verify_totp(secret, "000000")



def test_tenant_filter_hard_scopes_admin_and_nonprivileged_users():
    from server import tenant_filter

    admin = {"role": "admin", "tenant": "government"}
    analyst = {"role": "analyst", "tenant": "private"}
    owner = {"role": "owner", "tenant": "saas"}

    assert tenant_filter(admin, "private") == {"tenant": "government"}
    assert tenant_filter(analyst, "government") == {"tenant": "private"}
    assert tenant_filter(owner, "government") == {"tenant": "government"}


def test_password_policy_enforces_minimum_and_bcrypt_byte_limit():
    from server import RegisterRequest, PasswordResetConfirm, UserInvite
    import pytest

    with pytest.raises(ValueError):
        RegisterRequest(email="a@example.com", password="short", name="A")

    long_utf8 = "é" * 40
    with pytest.raises(ValueError):
        RegisterRequest(email="a@example.com", password=long_utf8, name="A")

    with pytest.raises(ValueError):
        PasswordResetConfirm(token="x", new_password="short")

    with pytest.raises(ValueError):
        UserInvite(email="b@example.com", name="B", role="viewer", tenant="private", password="short")


def test_production_requires_mfa_master_secret(monkeypatch):
    from server import settings, validate_security_settings

    monkeypatch.setattr(settings, "AEGIS_ENV", "production")
    monkeypatch.setattr(settings, "JWT_SECRET", "x" * 64)
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "real-production-password")
    monkeypatch.setattr(settings, "ANALYST_PASSWORD", "real-production-password")
    monkeypatch.setattr(settings, "MFA_REQUIRED", True)
    monkeypatch.setattr(settings, "MFA_MASTER_SECRET", "")
    monkeypatch.setattr(settings, "MONGO_TLS", True)
    monkeypatch.setattr(settings, "MONGO_TLS_ALLOW_INVALID_CERTS", False)
    monkeypatch.setattr(settings, "CORS_ORIGINS", "https://console.example.com")
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://console.example.com")

    import pytest
    with pytest.raises(RuntimeError, match="MFA_MASTER_SECRET"):
        validate_security_settings()
