import asyncio
from datetime import datetime, timezone

import pytest


def test_lockout_recording_uses_atomic_mongo_update(monkeypatch):
    from auth_helpers import record_failed_attempt
    from config import LOCKOUT_THRESHOLD

    class FakeCollection:
        def __init__(self):
            self.calls = []

        async def find_one_and_update(self, query, update, upsert, return_document):
            self.calls.append((query, update, upsert, return_document))
            return {"count": LOCKOUT_THRESHOLD}

    class FakeDB:
        def __init__(self):
            self.login_attempts = FakeCollection()

    fake = FakeDB()
    monkeypatch.setattr("auth_helpers.db", fake)

    asyncio.run(record_failed_attempt("203.0.113.10", "user@example.com"))

    assert len(fake.login_attempts.calls) == 1
    query, update, upsert, _ = fake.login_attempts.calls[0]
    assert query == {"key": "203.0.113.10:user@example.com"}
    assert upsert is True
    assert isinstance(update, list)
    stage = update[0]["$set"]
    assert stage["count"]["$add"][1] == 1
    assert stage["locked_until"]["$cond"][0]["$gte"][1] == LOCKOUT_THRESHOLD


def test_password_reset_and_mfa_lockouts_share_atomic_counter(monkeypatch):
    from auth_helpers import record_password_reset_attempt, record_mfa_failure

    class FakeCollection:
        def __init__(self):
            self.keys = []

        async def find_one_and_update(self, query, update, upsert, return_document):
            self.keys.append(query["key"])
            return {"count": 1}

    class FakeDB:
        def __init__(self):
            self.login_attempts = FakeCollection()

    fake = FakeDB()
    monkeypatch.setattr("auth_helpers.db", fake)

    async def run():
        await record_password_reset_attempt("203.0.113.10", "user@example.com")
        await record_mfa_failure("203.0.113.10", "user-1")

    asyncio.run(run())

    assert fake.login_attempts.keys == [
        "reset:203.0.113.10:user@example.com",
        "mfa:203.0.113.10:user-1",
    ]
