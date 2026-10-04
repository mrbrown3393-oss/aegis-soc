import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

os.environ.update({
    "MFA_MASTER_SECRET": "test-mfa-master-secret-that-is-at-least-32-bytes",
    "AEGIS_ENV": "test",
    "JWT_SECRET": "test-secret-not-for-production",
    "MONGO_URL": "mongodb://localhost:27017",
    "DB_NAME": "aegis_test",
})

from auth_helpers import (  # noqa: E402
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    generate_mfa_secret,
    legacy_mfa_secret,
    totp,
)


def test_mfa_secrets_are_random_per_generation():
    first = generate_mfa_secret()
    second = generate_mfa_secret()

    assert first != second
    assert len(first) >= 32
    assert len(second) >= 32
    assert totp(first).isdigit()
    assert len(totp(first)) == 6


def test_mfa_secret_encryption_round_trips_and_uses_unique_nonces():
    user_id = "user-123"
    secret = generate_mfa_secret()

    encrypted_one = encrypt_mfa_secret(user_id, secret)
    encrypted_two = encrypt_mfa_secret(user_id, secret)

    assert encrypted_one != encrypted_two
    assert decrypt_mfa_secret(user_id, encrypted_one) == secret
    assert decrypt_mfa_secret(user_id, encrypted_two) == secret


def test_mfa_secret_ciphertext_is_bound_to_user():
    user_id = "user-123"
    secret = generate_mfa_secret()
    encrypted = encrypt_mfa_secret(user_id, secret)

    try:
        decrypt_mfa_secret("different-user", encrypted)
    except RuntimeError:
        pass
    else:
        raise AssertionError("MFA secret ciphertext was not bound to the user identity")


def test_mfa_secret_tampering_is_rejected():
    user_id = "user-123"
    secret = generate_mfa_secret()
    encrypted = encrypt_mfa_secret(user_id, secret)
    tampered = encrypted[:-2] + ("AA" if encrypted[-2:] != "AA" else "BB")

    try:
        decrypt_mfa_secret(user_id, tampered)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Tampered MFA secret ciphertext was accepted")


def test_legacy_mfa_secret_is_separate_from_randomized_secret():
    user_id = "user-123"
    legacy = legacy_mfa_secret(user_id)
    randomized = generate_mfa_secret()

    assert legacy == legacy_mfa_secret(user_id)
    assert randomized != legacy


class _FakeResult:
    def __init__(self, modified_count=0):
        self.modified_count = modified_count


class _FakeCollection:
    def __init__(self):
        self.rows = {}

    async def insert_one(self, document):
        self.rows[document["challenge_id"]] = dict(document)

    async def find_one(self, query):
        row = self.rows.get(query["challenge_id"])
        if not row or row["user_id"] != query["user_id"] or row["consumed_at"] is not None:
            return None
        expires = query["expires_at"]["$gt"]
        if row["expires_at"] <= expires:
            return None
        return row

    async def update_one(self, query, update):
        row = self.rows.get(query["challenge_id"])
        if not row or row["user_id"] != query["user_id"] or row["consumed_at"] is not None:
            return _FakeResult()
        if row["expires_at"] <= query["expires_at"]["$gt"]:
            return _FakeResult()
        row["consumed_at"] = update["$set"]["consumed_at"]
        return _FakeResult(1)

    async def update_many(self, query, update):
        for row in self.rows.values():
            if row["user_id"] == query["user_id"] and row["consumed_at"] is None:
                row["consumed_at"] = update["$set"]["consumed_at"]


class _FakeDb:
    def __init__(self):
        self.mfa_challenges = _FakeCollection()


async def test_mfa_challenge_is_single_use(monkeypatch):
    import auth_helpers

    fake_db = _FakeDb()
    monkeypatch.setattr(auth_helpers, "db", fake_db)

    challenge_id = await auth_helpers.create_mfa_challenge("user-123")
    assert await auth_helpers.validate_mfa_challenge(challenge_id, "user-123")
    assert await auth_helpers.consume_mfa_challenge(challenge_id, "user-123")
    assert not await auth_helpers.validate_mfa_challenge(challenge_id, "user-123")
    assert not await auth_helpers.consume_mfa_challenge(challenge_id, "user-123")


async def test_mfa_challenge_is_bound_to_user(monkeypatch):
    import auth_helpers

    fake_db = _FakeDb()
    monkeypatch.setattr(auth_helpers, "db", fake_db)

    challenge_id = await auth_helpers.create_mfa_challenge("user-123")
    assert not await auth_helpers.validate_mfa_challenge(challenge_id, "different-user")
    assert not await auth_helpers.consume_mfa_challenge(challenge_id, "different-user")


async def test_mfa_challenges_can_be_invalidated(monkeypatch):
    import auth_helpers

    fake_db = _FakeDb()
    monkeypatch.setattr(auth_helpers, "db", fake_db)

    first = await auth_helpers.create_mfa_challenge("user-123")
    second = await auth_helpers.create_mfa_challenge("user-123")
    await auth_helpers.invalidate_mfa_challenges("user-123")

    assert not await auth_helpers.validate_mfa_challenge(first, "user-123")
    assert not await auth_helpers.validate_mfa_challenge(second, "user-123")
