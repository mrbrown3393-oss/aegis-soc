"""Shared request-bound authentication session policy.

Keeps request-derived security context out of low-level session persistence.
"""
from __future__ import annotations

from fastapi import Request

from auth_helpers import create_auth_session
from zero_trust import device_fingerprint


async def create_bound_auth_session(user_id: str, request: Request) -> tuple[str, str]:
    """Create an auth session bound to the device context of this request."""
    return await create_auth_session(user_id, device_fingerprint(request))
