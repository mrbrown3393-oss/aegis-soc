import os

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
    from backend.security_hardening import forwarded_client_ip
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
