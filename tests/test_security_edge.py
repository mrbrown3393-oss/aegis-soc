import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Synthetic test-only value; never use this value outside tests.
os.environ.setdefault("EDGE_SIGNING_SECRET", "test-only-edge-signing-secret-" + "x" * 40)

from fastapi.testclient import TestClient

from edge.app import app, policy


client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_admission_returns_signed_short_lived_decision():
    response = client.post(
        "/v1/admission",
        json={"method": "GET", "path": "/api/threats", "client_ip": "192.0.2.10"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is True
    assert 0 <= body["risk_score"] <= 100
    assert body["expires_at"] - body["issued_at"] == 15
    assert len(body["signature"]) == 64
    assert body["method"] == "GET"
    assert body["path"] == "/api/threats"
    assert body["client_ip"] == "192.0.2.10"
    assert body["audience"] == "aegis-api"
    assert body["nonce"]


def test_invalid_ip_is_rejected():
    response = client.post(
        "/v1/admission",
        json={"method": "GET", "path": "/api/threats", "client_ip": "not-an-ip"},
    )
    assert response.status_code == 400


def test_high_rate_is_blocked():
    original_limit = policy._max_requests
    try:
        policy._max_requests = 1
        first = client.post(
            "/v1/admission",
            json={"method": "GET", "path": "/api/threats", "client_ip": "192.0.2.11"},
        )
        second = client.post(
            "/v1/admission",
            json={"method": "GET", "path": "/api/threats", "client_ip": "192.0.2.11"},
        )
        assert first.json()["allow"] is True
        assert second.json()["allow"] is False
        assert second.json()["reason"] == "edge-rate-limit"
    finally:
        policy._max_requests = original_limit

def test_authz_returns_signed_headers_for_trusted_ingress():
    response = client.get(
        "/v1/authz",
        headers={
            "X-Original-Method": "GET",
            "X-Original-URI": "/api/threats",
            "X-Client-IP": "192.0.2.30",
        },
    )
    assert response.status_code == 204
    assert response.headers["x-aegis-edge-decision"]
    assert len(response.headers["x-aegis-edge-signature"]) == 64
    assert response.headers["x-aegis-edge-client-ip"] == "192.0.2.30"


def test_authz_rejects_malformed_original_uri():
    response = client.get(
        "/v1/authz",
        headers={
            "X-Original-Method": "GET",
            "X-Original-URI": "https://attacker.example/api/threats",
            "X-Client-IP": "192.0.2.31",
        },
    )
    assert response.status_code == 400
