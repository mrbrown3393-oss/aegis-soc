"""Regression tests for centralized session device binding."""

from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_auth_session_requires_creation_device_fingerprint():
    source = _source("backend/auth_helpers.py")
    assert 'device_fingerprint_value: str)' in source
    assert '"device_fingerprint": device_fingerprint_value' in source


def test_request_bound_session_algorithm_is_centralized():
    source = _source("backend/session_security.py")
    assert "def create_bound_auth_session" in source
    assert "device_fingerprint(request)" in source
    assert "create_auth_session(user_id, device_fingerprint(request))" in source


def test_password_login_and_mfa_use_bound_session_algorithm():
    source = _source("backend/routers/auth.py")
    tree = ast.parse(source)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_bound_auth_session"
    ]
    assert len(calls) == 2
    for call in calls:
        assert len(call.args) == 2
        assert ast.unparse(call.args[1]) == "request"


def test_oidc_uses_bound_session_algorithm():
    source = _source("backend/sso.py")
    tree = ast.parse(source)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "create_bound_auth_session"
    ]
    assert len(calls) == 1
    assert len(calls[0].args) == 2
    assert ast.unparse(calls[0].args[1]) == "request"
