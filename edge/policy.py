"""Remote security-edge decision engine for Aegis SOC.

The edge is intentionally stateless with respect to Aegis user sessions. It makes
short-lived, signed admission decisions from request metadata and bounded local
rate state. Aegis remains the authority for identity, tenant, RBAC and session
validation.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
import secrets
import time


@dataclass(frozen=True)
class Decision:
    allow: bool
    risk_score: int
    reason: str
    decision_id: str
    issued_at: int
    expires_at: int
    signature: str


class EdgePolicy:
    def __init__(self) -> None:
        secret = os.getenv("EDGE_SIGNING_SECRET", "")
        if len(secret) < 32:
            raise RuntimeError("EDGE_SIGNING_SECRET must be at least 32 characters")
        self._secret = secret.encode("utf-8")
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._window_seconds = int(os.getenv("EDGE_RATE_WINDOW_SECONDS", "60"))
        self._max_requests = int(os.getenv("EDGE_RATE_LIMIT", "120"))

    def _rate_count(self, client_key: str, now: float) -> int:
        events = self._events[client_key]
        cutoff = now - self._window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        events.append(now)
        return len(events)

    @staticmethod
    def _risk(method: str, path: str, rate_count: int, max_requests: int) -> tuple[int, str]:
        score = 0
        reason = "normal"

        if method.upper() in {"DELETE", "PATCH"}:
            score += 15
            reason = "high-impact-method"
        if path.startswith("/api/auth/"):
            score += 10
            reason = "authentication-path"
        if any(token in path.lower() for token in ("/admin", "/users", "/settings")):
            score += 15
            reason = "sensitive-path"
        if rate_count > max_requests:
            score += 70
            reason = "edge-rate-limit"
        elif rate_count > int(max_requests * 0.75):
            score += 25
            reason = "elevated-request-rate"

        return min(score, 100), reason

    def decide(self, *, method: str, path: str, client_key: str) -> Decision:
        now = int(time.time())
        count = self._rate_count(client_key, float(now))
        score, reason = self._risk(method, path, count, self._max_requests)
        allow = score < 70
        issued_at = now
        expires_at = now + 15
        decision_id = secrets.token_urlsafe(18)

        payload = {
            "allow": allow,
            "risk_score": score,
            "reason": reason,
            "decision_id": decision_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        signature = hmac.new(
            self._secret,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            sha256,
        ).hexdigest()

        return Decision(**payload, signature=signature)
