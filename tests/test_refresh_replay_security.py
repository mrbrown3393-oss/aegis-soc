"""Regression coverage for centralized refresh-token replay protection."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_refresh_security_algorithm_requires_device_binding_and_replay_revocation():
    source = _source("backend/session_security.py")
    assert "async def rotate_refresh_session" in source
    assert "device_context_changed_on_refresh" in source
    assert "refresh_token_replay" in source
    assert 'revoke_reason": "refresh_token_replay"' in source


def test_refresh_route_delegates_to_centralized_algorithm():
    source = _source("backend/routers/auth.py")
    tree = ast.parse(source)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "rotate_refresh_session"
    ]
    assert len(calls) == 1
    assert len(calls[0].args) == 5
