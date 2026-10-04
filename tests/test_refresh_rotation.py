import asyncio
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


def test_refresh_rotation_rejects_stale_jti_atomically(monkeypatch):
    from routers import auth

    class Result:
        modified_count = 0

    class Sessions:
        def __init__(self):
            self.update_filters = []

        async def find_one(self, query):
            return {
                "session_id": "session-1",
                "user_id": "user-1",
                "refresh_jti": "old-jti",
                "revoked_at": None,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            }

        async def update_one(self, query, update):
            self.update_filters.append((query, update))
            return Result()

    class Users:
        async def find_one(self, query):
            return {
                "id": "user-1",
                "email": "user@example.com",
                "role": "analyst",
                "tenant": "private",
            }

    class FakeDB:
        def __init__(self):
            self.auth_sessions = Sessions()
            self.users = Users()

    fake = FakeDB()
    monkeypatch.setattr(auth, "db", fake)
    monkeypatch.setattr(
        auth,
        "decode_jwt",
        lambda token: {
            "type": "refresh",
            "sid": "session-1",
            "sub": "user-1",
            "jti": "old-jti",
        },
    )

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
        else:
            raise AssertionError("stale refresh token was accepted")

    asyncio.run(run())

    query, _ = fake.auth_sessions.update_filters[0]
    assert query["session_id"] == "session-1"
    assert query["user_id"] == "user-1"
    assert query["refresh_jti"] == "old-jti"
    assert query["revoked_at"] is None
    assert "$gt" in query["expires_at"]


def test_refresh_rotation_updates_only_current_jti(monkeypatch):
    from routers import auth

    class Result:
        modified_count = 1

    class Sessions:
        def __init__(self):
            self.update_filters = []

        async def find_one(self, query):
            return {
                "session_id": "session-1",
                "user_id": "user-1",
                "refresh_jti": "old-jti",
                "revoked_at": None,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            }

        async def update_one(self, query, update):
            self.update_filters.append((query, update))
            return Result()

    class Users:
        async def find_one(self, query):
            return {
                "id": "user-1",
                "email": "user@example.com",
                "role": "analyst",
                "tenant": "private",
            }

    class FakeDB:
        def __init__(self):
            self.auth_sessions = Sessions()
            self.users = Users()

    fake = FakeDB()
    monkeypatch.setattr(auth, "db", fake)
    monkeypatch.setattr(
        auth,
        "decode_jwt",
        lambda token: {
            "type": "refresh",
            "sid": "session-1",
            "sub": "user-1",
            "jti": "old-jti",
        },
    )
    monkeypatch.setattr(auth, "create_access_token", lambda *args: "access")
    monkeypatch.setattr(auth, "create_refresh_token", lambda *args: "refresh")
    monkeypatch.setattr(auth, "set_auth_cookies", lambda *args: None)

    class Request:
        cookies = {"refresh_token": "refresh-token"}
        headers = {}

    class Response:
        pass

    async def run():
        result = await auth.refresh(Request(), Response())
        assert result == {"message": "Token refreshed"}

    asyncio.run(run())

    query, update = fake.auth_sessions.update_filters[0]
    assert query["refresh_jti"] == "old-jti"
    assert update["$set"]["refresh_jti"]
    assert update["$set"]["refresh_jti"] != "old-jti"


def test_refresh_rejects_device_context_change_and_revokes_session(monkeypatch):
    from routers import auth

    class Result:
        modified_count = 1

    class Sessions:
        def __init__(self):
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
            return Result()

    class Users:
        async def find_one(self, query):
            return {"id": "user-1", "email": "user@example.com", "role": "analyst", "tenant": "private"}

    class FakeDB:
        def __init__(self):
            self.auth_sessions = Sessions()
            self.users = Users()

    fake = FakeDB()
    monkeypatch.setattr(auth, "db", fake)
    monkeypatch.setattr(auth, "decode_jwt", lambda token: {
        "type": "refresh", "sid": "session-1", "sub": "user-1", "jti": "old-jti",
    })
    monkeypatch.setattr(auth, "device_fingerprint", lambda request: "untrusted-device")

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
    query, update = fake.auth_sessions.update_filters[0]
    assert query["refresh_jti"] == "old-jti"
    assert query["revoked_at"] is None
    assert update["$set"]["revoke_reason"] == "device_context_changed_on_refresh"
