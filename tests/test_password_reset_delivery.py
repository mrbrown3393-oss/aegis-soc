"""Regression tests for password-reset delivery fail-closed behavior."""
import os
import sys

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

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


def test_password_reset_request_does_not_mint_undeliverable_tokens(monkeypatch):
    import asyncio
    from models import PasswordResetRequest
    from routers import auth as auth_module

    class ForbiddenTokenWrites:
        async def insert_one(self, document):
            raise AssertionError("A reset token must not be stored without delivery.")

    class FakeDB:
        password_reset_tokens = ForbiddenTokenWrites()

    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr(auth_module, "db", FakeDB())
    monkeypatch.setattr(auth_module, "check_password_reset_rate_limit", noop)
    monkeypatch.setattr(auth_module, "record_password_reset_attempt", noop)
    monkeypatch.setattr(auth_module, "write_audit", noop)
    monkeypatch.setattr(auth_module, "forwarded_client_ip", lambda *args: "127.0.0.1")

    body = PasswordResetRequest(email="account@example.com")
    result = asyncio.run(auth_module.password_reset_request(body, object()))

    message = result["message"].lower()
    assert "unavailable" in message
    assert "delivery" in message
    assert "sent" not in message
