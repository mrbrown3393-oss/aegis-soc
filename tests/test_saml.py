from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner

from config import settings
from sso import _saml_configured, _saml_tenant_and_role, validate_saml_response


def _make_cert_and_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _build_response(
    *,
    cert_pem: str,
    key_pem: bytes,
    request_id: str,
    audience: str,
    destination: str,
    recipient: str,
    issuer: str,
    assertion_id: str = "_assert1",
    not_on_or_after: datetime | None = None,
    email: str = "analyst@example.com",
    tenant: str = "private",
    role: str = "analyst",
    sign: bool = True,
) -> str:
    now = datetime.now(timezone.utc)
    nbf = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    noa = (not_on_or_after or (now + timedelta(minutes=5))).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Placeholder Signature node between Issuer and Subject (SAML schema location)
    xml = f"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_resp1" Version="2.0" IssueInstant="{nbf}"
                Destination="{destination}" InResponseTo="{request_id}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{nbf}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <ds:Signature Id="placeholder"></ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{noa}" Recipient="{recipient}" InResponseTo="{request_id}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{nbf}" NotOnOrAfter="{noa}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="tenant"><saml:AttributeValue>{tenant}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="role"><saml:AttributeValue>{role}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>Demo User</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    root = etree.fromstring(xml.encode("utf-8"))
    if sign:
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        signed_assertion = XMLSigner().sign(assertion, key=key_pem, cert=cert_pem)
        parent = assertion.getparent()
        parent.replace(assertion, signed_assertion)
    else:
        # Remove placeholder so unsigned path is truly unsigned
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        placeholder = assertion.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
        if placeholder is not None:
            assertion.remove(placeholder)
    return base64.b64encode(etree.tostring(root)).decode("ascii")


def test_saml_tenant_mapping_requires_allowlist(monkeypatch):
    monkeypatch.setattr(settings, "SAML_TENANT_ATTRIBUTE", "tenant")
    monkeypatch.setattr(settings, "SAML_ALLOWED_TENANTS", "private,government")
    monkeypatch.setattr(settings, "SAML_ROLE_ATTRIBUTE", "role")
    assert _saml_tenant_and_role({"tenant": "private", "role": "analyst"}) == ("private", "analyst")
    with pytest.raises(Exception) as exc:
        _saml_tenant_and_role({"tenant": "evil", "role": "admin"})
    assert getattr(exc.value, "status_code", None) == 403


def test_saml_configured_requires_all_trust_material(monkeypatch):
    monkeypatch.setattr(settings, "SAML_ENABLED", True)
    monkeypatch.setattr(settings, "SAML_SP_ENTITY_ID", "")
    monkeypatch.setattr(settings, "SAML_ACS_URL", "https://sp.example/acs")
    monkeypatch.setattr(settings, "SAML_IDP_ENTITY_ID", "https://idp.example")
    monkeypatch.setattr(settings, "SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setattr(settings, "SAML_IDP_X509_CERT", "cert")
    assert _saml_configured() is False


def test_saml_rejects_wrong_audience(monkeypatch):
    cert_pem, key_pem = _make_cert_and_key()
    monkeypatch.setattr(settings, "SAML_ENABLED", True)
    monkeypatch.setattr(settings, "SAML_SP_ENTITY_ID", "https://sp.example")
    monkeypatch.setattr(settings, "SAML_ACS_URL", "https://sp.example/acs")
    monkeypatch.setattr(settings, "SAML_IDP_ENTITY_ID", "https://idp.example")
    monkeypatch.setattr(settings, "SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setattr(settings, "SAML_IDP_X509_CERT", cert_pem)
    monkeypatch.setattr(settings, "SAML_ALLOWED_TENANTS", "private")
    monkeypatch.setattr(settings, "SAML_CLOCK_SKEW_SECONDS", 120)

    b64 = _build_response(
        cert_pem=cert_pem,
        key_pem=key_pem,
        request_id="_req1",
        audience="https://wrong.example",
        destination="https://sp.example/acs",
        recipient="https://sp.example/acs",
        issuer="https://idp.example",
    )
    with pytest.raises(Exception) as exc:
        validate_saml_response(b64, expected_request_id="_req1")
    assert getattr(exc.value, "status_code", None) == 401


def test_saml_rejects_expired_assertion(monkeypatch):
    cert_pem, key_pem = _make_cert_and_key()
    monkeypatch.setattr(settings, "SAML_ENABLED", True)
    monkeypatch.setattr(settings, "SAML_SP_ENTITY_ID", "https://sp.example")
    monkeypatch.setattr(settings, "SAML_ACS_URL", "https://sp.example/acs")
    monkeypatch.setattr(settings, "SAML_IDP_ENTITY_ID", "https://idp.example")
    monkeypatch.setattr(settings, "SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setattr(settings, "SAML_IDP_X509_CERT", cert_pem)
    monkeypatch.setattr(settings, "SAML_ALLOWED_TENANTS", "private")
    monkeypatch.setattr(settings, "SAML_CLOCK_SKEW_SECONDS", 0)

    expired = datetime.now(timezone.utc) - timedelta(minutes=10)
    b64 = _build_response(
        cert_pem=cert_pem,
        key_pem=key_pem,
        request_id="_req2",
        audience="https://sp.example",
        destination="https://sp.example/acs",
        recipient="https://sp.example/acs",
        issuer="https://idp.example",
        not_on_or_after=expired,
    )
    with pytest.raises(Exception) as exc:
        validate_saml_response(b64, expected_request_id="_req2")
    assert getattr(exc.value, "status_code", None) == 401


def test_saml_rejects_forged_unsigned_response(monkeypatch):
    cert_pem, key_pem = _make_cert_and_key()
    monkeypatch.setattr(settings, "SAML_ENABLED", True)
    monkeypatch.setattr(settings, "SAML_SP_ENTITY_ID", "https://sp.example")
    monkeypatch.setattr(settings, "SAML_ACS_URL", "https://sp.example/acs")
    monkeypatch.setattr(settings, "SAML_IDP_ENTITY_ID", "https://idp.example")
    monkeypatch.setattr(settings, "SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setattr(settings, "SAML_IDP_X509_CERT", cert_pem)
    monkeypatch.setattr(settings, "SAML_ALLOWED_TENANTS", "private")

    b64 = _build_response(
        cert_pem=cert_pem,
        key_pem=key_pem,
        request_id="_req3",
        audience="https://sp.example",
        destination="https://sp.example/acs",
        recipient="https://sp.example/acs",
        issuer="https://idp.example",
        sign=False,
    )
    with pytest.raises(Exception) as exc:
        validate_saml_response(b64, expected_request_id="_req3")
    assert getattr(exc.value, "status_code", None) == 401


def test_saml_accepts_valid_signed_response(monkeypatch):
    cert_pem, key_pem = _make_cert_and_key()
    monkeypatch.setattr(settings, "SAML_ENABLED", True)
    monkeypatch.setattr(settings, "SAML_SP_ENTITY_ID", "https://sp.example")
    monkeypatch.setattr(settings, "SAML_ACS_URL", "https://sp.example/acs")
    monkeypatch.setattr(settings, "SAML_IDP_ENTITY_ID", "https://idp.example")
    monkeypatch.setattr(settings, "SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setattr(settings, "SAML_IDP_X509_CERT", cert_pem)
    monkeypatch.setattr(settings, "SAML_ALLOWED_TENANTS", "private")
    monkeypatch.setattr(settings, "SAML_CLOCK_SKEW_SECONDS", 120)

    b64 = _build_response(
        cert_pem=cert_pem,
        key_pem=key_pem,
        request_id="_req4",
        audience="https://sp.example",
        destination="https://sp.example/acs",
        recipient="https://sp.example/acs",
        issuer="https://idp.example",
        assertion_id="_assert-ok",
    )
    identity = validate_saml_response(b64, expected_request_id="_req4")
    assert identity["email"] == "analyst@example.com"
    assert identity["tenant"] == "private"
    assert identity["role"] == "analyst"
    assert identity["assertion_id"] == "_assert-ok"
