import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

os.environ.update({
    "MONGO_URL": "mongodb://localhost:27017",
    "DB_NAME": "aegis_test",
    "JWT_SECRET": "test-secret-not-for-production",
    "AEGIS_ENV": "test",
    "MFA_MASTER_SECRET": "test-mfa-master-secret-0123456789abcdef",
})


def _fake_db():
    class Sessions:
        def __init__(self, modified_count):
            self.modified_count = modified_count
            self.update_filters = []

        async def find_one(self, query):
            return {
                "session_id": "session-1",
                "user_id": "user-1",
                "refresh_jti": "old-jti",
                "device_fingerprint": "trusted-device",
                "revoked_at": None,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            }

        async def update_one(self, query, update):
            self.update_filters.append((query, update))
            class Result:
                pass
            result = Result()
            result.modified_count = self.modified_count
            return result

    class Users:
        async def find_one(self, query):
            return {
                "id": "user-1",
                "email": "user@example.com",
                "role": "analyst",
                "tenant": "private",
            }

    class FakeDB:
        def __init__(self, modified_count):
            self.auth_sessions = Sessions(modified_count)
            self.users = Users()

    return FakeDB


def _patch_refresh(monkeypatch, fake, session_security):
    from routers import auth
    monkeypatch.setattr(auth, "db", fake)
    monkeypatch.setattr(session_security, "db", fake)
    monkeypatch.setattr(session_security, "device_fingerprint", lambda request: "trusted-device")
    monkeypatch.setattr(auth, "decode_jwt", lambda token: {
        "type": "refresh", "sid": "session-1", "sub": "user-1", "jti": "old-jti",
    })
    monkeypatch.setattr(auth, "create_access_token", lambda *args: "access")
    monkeypatch.setattr(auth, "create_refresh_token", lambda *args: "refresh")
    monkeypatch.setattr(auth, "set_auth_cookies", lambda *args: None)

    class Request:
        cookies = {"refresh_token": "refresh-token"}
        headers = {}

    class Response:
        pass

    return auth, Request, Response


def test_refresh_rotation_rejects_stale_jti_atomically(monkeypatch):
    import asyncio
    import session_security

    fake = _fake_db()(modified_count=0)
    auth, Request, Response = _patch_refresh(monkeypatch, fake, session_security)

    async def run():
        try:
            await auth.refresh(Request(), Response())
        except Exception as exc:
            assert getattr(exc, "status_code", None) == 401
            assert getattr(exc, "detail", None) == "Refresh token replay detected; session revoked"
        else:
            raise AssertionError("stale refresh token was accepted")

    asyncio.run(run())
    assert len(fake.auth_sessions.update_filters) == 2
    rotate_query, _ = fake.auth_sessions.update_filters[0]
    revoke_query, revoke_update = fake.auth_sessions.update_filters[1]
    assert rotate_query["session_id"] == "session-1"
    assert rotate_query["user_id"] == "user-1"
    assert rotate_query["refresh_jti"] == "old-jti"
    assert rotate_query["revoked_at"] is None
    assert "$gt" in rotate_query["expires_at"]
    assert revoke_query["session_id"] == "session-1"
    assert revoke_query["revoked_at"] is None
    assert revoke_update["$set"]["revoke_reason"] == "refresh_token_replay"


def test_refresh_rotation_updates_only_current_jti(monkeypatch):
    import asyncio
    import session_security

    fake = _fake_db()(modified_count=1)
    auth, Request, Response = _patch_refresh(monkeypatch, fake, session_security)
    asyncio.run(auth.refresh(Request(), Response()))

    assert len(fake.auth_sessions.update_filters) == 1
    query, update = fake.auth_sessions.update_filters[0]
    assert query["refresh_jti"] == "old-jti"
    assert update["$set"]["refresh_jti"]
    assert update["$set"]["refresh_jti"] != "old-jti"


def test_refresh_rejects_device_context_change_and_revokes_session(monkeypatch):
    import asyncio
    import session_security
    from routers import auth

    fake = _fake_db()(modified_count=1)
    monkeypatch.setattr(auth, "db", fake)
    monkeypatch.setattr(session_security, "db", fake)
    monkeypatch.setattr(session_security, "device_fingerprint", lambda request: "untrusted-device")
    monkeypatch.setattr(auth, "decode_jwt", lambda token: {
        "type": "refresh", "sid": "session-1", "sub": "user-1", "jti": "old-jti",
    })

    class Request:
        cookies = {"refresh_token": "refresh-token"}
        headers = {}

    class Response:
        pass

    async def run():
        try:
            await auth.refresh(Request(), Response())
        except Exception as exc:
            assert getattr(exc, "status_code", None) == 401
            assert getattr(exc, "detail", None) == "Session device context changed"
        else:
            raise AssertionError("refresh token crossed a device boundary")

    asyncio.run(run())
    assert len(fake.auth_sessions.update_filters) == 1
    query, update = fake.auth_sessions.update_filters[0]
    assert query["session_id"] == "session-1"
    assert query["user_id"] == "user-1"
    assert query["revoked_at"] is None
    assert update["$set"]["revoke_reason"] == "device_context_changed_on_refresh"
