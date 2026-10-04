from __future__ import annotations

import json
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from config import settings
from sso import _sha256, _tenant_and_role, _verify_id_token, _trusted_provider_endpoint


def test_oidc_state_hash_is_one_way_and_stable():
    value = "random-state-value"
    assert _sha256(value) == _sha256(value)
    assert _sha256(value) != value


def test_oidc_tenant_mapping_requires_allowlisted_tenant(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_TENANT_CLAIM", "tenant")
    monkeypatch.setattr(settings, "OIDC_ALLOWED_TENANTS", "private,government")
    monkeypatch.setattr(settings, "OIDC_ROLE_CLAIM", "role")
    assert _tenant_and_role({"tenant": "government", "role": "analyst"}) == ("government", "analyst")
    with pytest.raises(Exception) as exc:
        _tenant_and_role({"tenant": "unknown", "role": "admin"})
    assert getattr(exc.value, "status_code", None) == 403


def test_oidc_tenant_mapping_defaults_unknown_role_to_viewer(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_TENANT_CLAIM", "tenant")
    monkeypatch.setattr(settings, "OIDC_ALLOWED_TENANTS", "private")
    monkeypatch.setattr(settings, "OIDC_ROLE_CLAIM", "role")
    assert _tenant_and_role({"tenant": "private", "role": "owner"}) == ("private", "viewer")


def test_oidc_id_token_rejects_wrong_nonce(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.PKCS8,
        encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
    )
    issuer = "https://issuer.example"
    client_id = "client"
    token = jwt.encode(
        {"iss": issuer, "sub": "user-1", "aud": client_id, "iat": 1, "exp": 4102444800, "nonce": "correct"},
        private_pem,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", issuer)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", client_id)
    with pytest.raises(Exception) as exc:
        _verify_id_token(token, {"keys": [{"kid": "test-key", **public_jwk}]}, "wrong")
    assert getattr(exc.value, "status_code", None) == 401


def test_oidc_provider_endpoint_must_use_trusted_https_host(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", "https://issuer.example")
    assert _trusted_provider_endpoint("https://issuer.example/oauth2/token") == "https://issuer.example/oauth2/token"
    with pytest.raises(Exception) as exc:
        _trusted_provider_endpoint("https://attacker.example/keys")
    assert getattr(exc.value, "status_code", None) == 503


def test_oidc_mfa_claim_is_required_when_enabled(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.PKCS8,
        encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
    )
    issuer = "https://issuer.example"
    client_id = "client"
    token = jwt.encode(
        {"iss": issuer, "sub": "user-1", "aud": client_id, "iat": 1700000000, "exp": 4102444800, "nonce": "correct"},
        private_pem, algorithm="RS256", headers={"kid": "test-key"},
    )
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", issuer)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", client_id)
    monkeypatch.setattr(settings, "OIDC_REQUIRE_MFA_CLAIM", True)
    monkeypatch.setattr(settings, "OIDC_MFA_AMR_VALUES", "mfa")
    with pytest.raises(Exception) as exc:
        _verify_id_token(token, {"keys": [{"kid": "test-key", **public_jwk}]}, "correct")
    assert getattr(exc.value, "status_code", None) == 403
