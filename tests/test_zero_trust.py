import asyncio
from datetime import datetime, timezone, timedelta

from deps import tenant_filter
from step_up import STEP_UP_MINUTES, create_step_up_token, enforce_step_up_role, validate_step_up_claims
from zero_trust import device_fingerprint, enforce_protected_path


class Request:
    def __init__(self, path="/api/metrics/overview", cookies=None, headers=None, method="GET"):
        self.url = type("URL", (), {"path": path})()
        self.method = method
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


def test_step_up_claims_reject_session_mismatch():
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


def test_edge_decision_is_required_when_enforcement_is_enabled():
    from fastapi import HTTPException
    import edge_security
    from edge_security import verify_edge_decision

    previous = edge_security.settings.EDGE_ENFORCE_DECISION
    edge_security.settings.EDGE_ENFORCE_DECISION = True
    try:
        try:
            verify_edge_decision(Request())
        except HTTPException as exc:
            assert exc.status_code == 403
        else:
            raise AssertionError("edge enforcement must fail closed without a signed decision")
    finally:
        edge_security.settings.EDGE_ENFORCE_DECISION = previous


def test_signed_edge_decision_is_bound_to_request_and_replay_protected():
    import base64
    import json
    import os
    import secrets
    from dataclasses import asdict
    import edge_security
    from edge.policy import EdgePolicy
    from edge_security import verify_edge_decision

    previous_env_secret = os.environ.get("EDGE_SIGNING_SECRET")
    os.environ["EDGE_SIGNING_SECRET"] = "unit-test-" + secrets.token_hex(32)
    policy = EdgePolicy()
    decision = policy.decide(method="GET", path="/api/metrics/overview", client_key="192.0.2.20")
    payload = asdict(decision)
    signature = payload.pop("signature")
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")

    request = Request(
        path="/api/metrics/overview",
        headers={
            "x-aegis-edge-decision": encoded,
            "x-aegis-edge-signature": signature,
            "x-aegis-edge-client-ip": "192.0.2.20",
        },
    )
    previous = (
        edge_security.settings.EDGE_ENFORCE_DECISION,
        edge_security.settings.EDGE_VERIFY_SECRET,
        edge_security.settings.EDGE_AUDIENCE,
    )
    edge_security.settings.EDGE_ENFORCE_DECISION = True
    edge_security.settings.EDGE_VERIFY_SECRET = os.environ["EDGE_SIGNING_SECRET"]
    edge_security.settings.EDGE_AUDIENCE = "aegis-api"
    try:
        verify_edge_decision(request)
        try:
            verify_edge_decision(request)
        except Exception as exc:
            assert getattr(exc, "status_code", None) == 403
        else:
            raise AssertionError("a signed edge decision must not be reusable")
    finally:
        edge_security.settings.EDGE_ENFORCE_DECISION, edge_security.settings.EDGE_VERIFY_SECRET, edge_security.settings.EDGE_AUDIENCE = previous
        if previous_env_secret is None:
            os.environ.pop("EDGE_SIGNING_SECRET", None)
        else:
            os.environ["EDGE_SIGNING_SECRET"] = previous_env_secret
