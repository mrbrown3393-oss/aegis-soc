import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

_AEGIS_APP = None


def _aegis_app():
    """Load and cache Aegis' backend app from the repository, avoiding module collisions."""
    global _AEGIS_APP
    if _AEGIS_APP is not None:
        return _AEGIS_APP

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
    sys.path.insert(0, backend_dir)

    # The backend intentionally uses top-level imports (config, routers, anomaly,
    # etc.). Remove any preloaded modules with those names so server.py and all of
    # its routers resolve against this checkout rather than an unrelated module.
    aegis_modules = {
        "server", "config", "database", "deps", "models", "seed",
        "auth_helpers", "security_hardening", "sso", "anomaly",
    }
    for name in list(sys.modules):
        if name in aegis_modules or name == "routers" or name.startswith("routers."):
            sys.modules.pop(name, None)

    server_path = os.path.join(backend_dir, "server.py")
    spec = importlib.util.spec_from_file_location("server", server_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["server"] = module
    spec.loader.exec_module(module)
    _AEGIS_APP = module.app
    return _AEGIS_APP
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
    "MFA_MASTER_SECRET": "test-mfa-master-secret-0123456789abcdef",
})


def test_backend_imports_and_security_routes():
    app = _aegis_app()

    paths = {route.path for route in app.routes if hasattr(route, "path")}
    assert any(path.startswith("/api/") for path in paths)
    assert "/api/security/telemetry/fuse" in paths
    assert "/api/security/quarantine" in paths
    assert "/api/auth/sso/oidc/login" in paths
    assert "/api/auth/sso/saml/login" in paths


def test_security_headers_middleware_is_registered():
    app = _aegis_app()

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
    monkeypatch.setattr(settings, "MFA_MASTER_SECRET", "m" * 64)
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
    app = _aegis_app()

    client = TestClient(app)
    client.cookies.set("access_token", "test-cookie")
    response = client.post("/api/auth/refresh", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-origin request blocked"


def test_csrf_guard_blocks_authenticated_mutation_without_origin_or_referer():
    from fastapi.testclient import TestClient
    app = _aegis_app()

    client = TestClient(app)
    client.cookies.set("access_token", "test-cookie")
    response = client.post("/api/auth/refresh")
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-origin request blocked"


def test_csrf_guard_allows_configured_origin():
    from fastapi.testclient import TestClient
    app = _aegis_app()

    client = TestClient(app)
    client.cookies.set("access_token", "test-cookie")
    response = client.post("/api/auth/refresh", headers={"Origin": "http://localhost:3000"})
    # The CSRF guard must allow the configured origin; downstream auth may reject
    # the intentionally fake token, but it must not reject it as cross-origin.
    assert response.status_code != 403


def test_totp_accepts_current_and_adjacent_time_step(monkeypatch):
    from auth_helpers import mfa_secret, totp, verify_totp
    from config import settings

    monkeypatch.setattr(settings, "MFA_MASTER_SECRET", "m" * 64)
    monkeypatch.setattr(settings, "AEGIS_ENV", "test")
    secret = mfa_secret("test-user")
    timestamp = 1_000_000
    code = totp(secret, timestamp)
    assert verify_totp(secret, code, timestamp=timestamp)
    assert verify_totp(secret, totp(secret, timestamp + 30), timestamp=timestamp)
    assert not verify_totp(secret, "000000", timestamp=timestamp)



def test_tenant_filter_hard_scopes_admin_and_nonprivileged_users():
    from server import tenant_filter

    admin = {"role": "admin", "tenant": "government"}
    analyst = {"role": "analyst", "tenant": "private"}
    owner = {"role": "owner", "tenant": "saas"}

    assert tenant_filter(admin, "private") == {"tenant": "government"}
    assert tenant_filter(analyst, "government") == {"tenant": "private"}
    assert tenant_filter(owner, "government") == {"tenant": "government"}


def test_password_policy_enforces_minimum_and_bcrypt_byte_limit():
    from models import RegisterRequest, PasswordResetConfirm, UserInvite
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


def test_admin_cannot_grant_owner_role():
    import pytest
    from models import UserInvite
    from routers.users import validate_invite_authorization

    body = UserInvite(
        email="new@example.com",
        name="New User",
        role="owner",
        tenant="government",
        password="StrongPassword123!",
    )
    with pytest.raises(Exception, match="Only the owner can grant"):
        validate_invite_authorization({"role": "admin", "tenant": "government"}, body)


def test_proxy_ip_uses_first_untrusted_hop_from_right():
    from security_hardening import forwarded_client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"203.0.113.10, 10.0.0.9, 10.0.0.8")],
        "client": ("10.0.0.7", 1234),
        "scheme": "http",
        "server": ("localhost", 80),
        "query_string": b"",
    }
    request = Request(scope)
    assert forwarded_client_ip(request, "10.0.0.0/8") == "203.0.113.10"


def test_proxy_ip_does_not_trust_all_forwarded_hops():
    from security_hardening import forwarded_client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"10.0.0.9, 10.0.0.8")],
        "client": ("10.0.0.7", 1234),
        "scheme": "http",
        "server": ("localhost", 80),
        "query_string": b"",
    }
    request = Request(scope)
    assert forwarded_client_ip(request, "10.0.0.0/8") == "10.0.0.7"


def test_telemetry_fusion_requires_operator_role():
    app = _aegis_app()
    from anomaly import fuse_telemetry

    dependency = next(
        dep for dep in app.routes
        if getattr(dep, "path", None) == "/api/security/telemetry/fuse"
    )

    def dependency_calls(dependant):
        for item in dependant.dependencies:
            yield item.call
            yield from dependency_calls(item)

    checkers = [call for call in dependency_calls(dependency.dependant) if getattr(call, "__name__", "") == "_checker"]
    assert checkers
    checker = checkers[0]
    assert checker.__closure__ is not None
    assert any(
        cell.cell_contents == ("owner", "admin", "operator")
        for cell in checker.__closure__
    )

def test_authenticated_rate_limit_is_atomic(monkeypatch):
    import asyncio
    import pytest
    from auth_helpers import enforce_authenticated_rate_limit
    from config import AUTH_RATE_LIMIT_PER_MINUTE

    class FakeCollection:
        def __init__(self):
            self.count = 0

        async def find_one_and_update(self, query, update, upsert, return_document):
            self.count += update["$inc"]["count"]
            return {"count": self.count, "window": update["$setOnInsert"]["window"]}

    class FakeDB:
        def __init__(self):
            self.auth_rate_limits = FakeCollection()

    monkeypatch.setattr("auth_helpers.db", FakeDB())

    async def run():
        for _ in range(AUTH_RATE_LIMIT_PER_MINUTE):
            await enforce_authenticated_rate_limit("203.0.113.10", "user-1")
        with pytest.raises(Exception, match="Rate limit exceeded"):
            await enforce_authenticated_rate_limit("203.0.113.10", "user-1")

    asyncio.run(run())


def test_idle_session_revokes_after_timeout(monkeypatch):
    import asyncio
    from auth_helpers import active_session

    class FakeSessions:
        async def find_one(self, query):
            from datetime import datetime, timezone, timedelta
            old = datetime.now(timezone.utc) - timedelta(minutes=16)
            return {
                "session_id": query["session_id"],
                "user_id": query["user_id"],
                "created_at": old,
                "last_activity_at": old,
                "revoked_at": None,
            }

        async def update_one(self, query, update):
            return None

    class FakeDB:
        def __init__(self):
            self.auth_sessions = FakeSessions()

    monkeypatch.setattr("auth_helpers.db", FakeDB())

    async def run():
        assert await active_session("session-1", "user-1") is False

    asyncio.run(run())



def test_jwt_rotation_accepts_previous_key(monkeypatch):
    from auth_helpers import create_access_token, decode_jwt
    from config import settings
    monkeypatch.setattr(settings, "JWT_SECRET", "n" * 64)
    monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET", "o" * 64)
    token = create_access_token("user-1", "user@example.com", "analyst", "private", "session-1")
    assert decode_jwt(token)["sub"] == "user-1"


def test_jwt_rotation_verifies_legacy_previous_key(monkeypatch):
    import jwt
    from datetime import datetime, timezone, timedelta
    from auth_helpers import decode_jwt
    from config import settings
    old = "o" * 64
    monkeypatch.setattr(settings, "JWT_SECRET", "n" * 64)
    monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET", old)
    token = jwt.encode({"sub": "user-2", "type": "access", "sid": "session-2", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, old, algorithm="HS256", headers={"kid": "previous"})
    assert decode_jwt(token)["sub"] == "user-2"


def test_jwt_rotation_rejects_retired_key(monkeypatch):
    import jwt
    import pytest
    from datetime import datetime, timezone, timedelta
    from auth_helpers import decode_jwt
    from config import settings
    monkeypatch.setattr(settings, "JWT_SECRET", "n" * 64)
    monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET", "o" * 64)
    token = jwt.encode({"sub": "user-3", "type": "access", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, "p" * 64, algorithm="HS256", headers={"kid": "retired"})
    with pytest.raises(jwt.InvalidTokenError):
        decode_jwt(token)


def test_tenant_boundary_filters_apply_to_all_data_listing_routers(monkeypatch):
    import asyncio
    from routers import incidents, metrics, resources, threats, vulnerabilities

    class Cursor:
        def __init__(self, rows=None):
            self.rows = rows or []

        def sort(self, *args, **kwargs):
            return self

        async def to_list(self, limit):
            return self.rows[:limit]

    class Collection:
        def __init__(self):
            self.filters = []

        def find(self, filt, *args):
            self.filters.append(filt.copy())
            return Cursor()

        async def count_documents(self, filt):
            self.filters.append(filt.copy())
            return 0

        def aggregate(self, pipeline):
            self.filters.append(pipeline[0]["$match"].copy())
            return Cursor()

    class FakeDB:
        def __init__(self):
            self.incidents = Collection()
            self.threats = Collection()
            self.assets = Collection()
            self.compliance = Collection()
            self.audit_logs = Collection()
            self.vulnerabilities = Collection()

    fake = FakeDB()
    monkeypatch.setattr(incidents, "db", fake)
    monkeypatch.setattr(metrics, "db", fake)
    monkeypatch.setattr(resources, "db", fake)
    monkeypatch.setattr(threats, "db", fake)
    monkeypatch.setattr(vulnerabilities, "db", fake)

    user = {"role": "admin", "tenant": "government"}

    async def run():
        await incidents.list_incidents("private", user)
        await metrics.metrics_overview("private", user)
        await resources.list_assets("private", user)
        await resources.list_compliance("private", user)
        await resources.list_audit_logs("private", 10, user)
        await threats.list_threats(10, "high", "private", user)
        await vulnerabilities.list_vulns("private", user)

    asyncio.run(run())

    assert fake.incidents.filters[0] == {"tenant": "government"}
    assert all(f.get("tenant") == "government" for f in fake.assets.filters)
    assert all(f.get("tenant") == "government" for f in fake.compliance.filters)
    assert all(f.get("tenant") == "government" for f in fake.audit_logs.filters)
    assert fake.threats.filters[0]["tenant"] == "government"
    assert any(f.get("severity") == "high" for f in fake.threats.filters)
    assert fake.vulnerabilities.filters[0] == {"tenant": "government"}


def test_tenant_boundary_filters_apply_to_mutating_endpoints(monkeypatch):
    import asyncio
    from routers import incidents, users, vulnerabilities
    from models import IncidentUpdate, UserInvite

    class Result:
        matched_count = 0

    class Collection:
        def __init__(self):
            self.filters = []

        async def update_one(self, filt, update):
            self.filters.append(filt.copy())
            return Result()

        async def find_one(self, filt):
            self.filters.append(filt.copy())
            return None

    class FakeDB:
        def __init__(self):
            self.incidents = Collection()
            self.vulnerabilities = Collection()
            self.users = Collection()

    fake = FakeDB()
    monkeypatch.setattr(incidents, "db", fake)
    monkeypatch.setattr(vulnerabilities, "db", fake)
    monkeypatch.setattr(users, "db", fake)

    user = {"role": "analyst", "tenant": "government", "email": "analyst@example.com"}

    class Request:
        pass

    async def run():
        try:
            await incidents.update_incident(
                "incident-private",
                IncidentUpdate(status="resolved"),
                Request(),
                user,
            )
        except Exception:
            pass

        try:
            await vulnerabilities.patch_vuln(
                "vuln-private",
                Request(),
                user,
            )
        except Exception:
            pass

    asyncio.run(run())

    assert fake.incidents.filters[0] == {"id": "incident-private", "tenant": "government"}
    assert fake.vulnerabilities.filters[0] == {"id": "vuln-private", "tenant": "government"}

    body = UserInvite(
        email="new@example.com",
        name="New User",
        role="viewer",
        tenant="private",
        password="StrongPassword123!",
    )
    import pytest
    with pytest.raises(Exception, match="Cannot invite users into another tenant"):
        users.validate_invite_authorization(user, body)



def test_native_pymongo_async_driver_is_used():
    from database import client
    from pymongo import AsyncMongoClient

    assert isinstance(client, AsyncMongoClient)
