import asyncio
from datetime import datetime, timezone, timedelta

from deps import tenant_filter\nfrom step_up import STEP_UP_MINUTES, create_step_up_token, enforce_step_up_role, validate_step_up_claims
from zero_trust import device_fingerprint, enforce_protected_path


class Request:
    def __init__(self, path="/api/metrics/overview", cookies=None, headers=None):
        self.url = type("URL", (), {"path": path})()
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.state = type("State", (), {})()


def test_protected_api_requires_access_cookie():
    request = Request()
    try:
        enforce_protected_path(request)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401
    else:
        raise AssertionError("protected API route must fail closed without authentication")


def test_auth_paths_remain_public_for_login_flow():
    for path in ("/api/auth/login", "/api/auth/refresh", "/api/auth/mfa/setup", "/api/auth/mfa/verify"):
        enforce_protected_path(Request(path=path))


def test_sso_endpoints_are_explicitly_handled_by_sso_router():
    enforce_protected_path(Request(path="/api/auth/sso/config"))


def test_device_fingerprint_changes_with_security_context():
    first = Request(headers={"user-agent": "AegisTest/1", "accept-language": "en-US"})
    same = Request(headers={"user-agent": "AegisTest/1", "accept-language": "en-US"})
    changed = Request(headers={"user-agent": "AegisTest/2", "accept-language": "en-US"})
    assert device_fingerprint(first) == device_fingerprint(same)
    assert device_fingerprint(first) != device_fingerprint(changed)


def test_non_owner_tenant_scope_cannot_be_overridden():
    user = {"role": "analyst", "tenant": "private"}
    assert tenant_filter(user, "government") == {"tenant": "private"}


def test_owner_cross_tenant_scope_is_explicit():
    user = {"role": "owner", "tenant": "government"}
    assert tenant_filter(user, "private") == {"tenant": "private"}
    assert tenant_filter(user, "all") == {}
\n\ndef test_step_up_claims_reject_session_mismatch():
    from fastapi import HTTPException
    payload = {"type": "step_up", "sid": "session-a", "fp": "fp-a"}
    access = {"type": "access", "sid": "session-b"}
    try:
        validate_step_up_claims(payload, access, "fp-a")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("step-up token must be bound to the access session")


def test_step_up_claims_reject_device_change():
    from fastapi import HTTPException
    payload = {"type": "step_up", "sid": "session-a", "fp": "fp-a"}
    access = {"type": "access", "sid": "session-a"}
    try:
        validate_step_up_claims(payload, access, "fp-b")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("step-up token must be bound to the validated device context")


def test_step_up_role_enforcement():
    from fastapi import HTTPException
    enforce_step_up_role({"role": "admin"}, {"owner", "admin"})
    try:
        enforce_step_up_role({"role": "viewer"}, {"owner", "admin"})
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("high-impact actions must retain role authorization")
