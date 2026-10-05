"""Production OIDC and SAML federation with cryptographic validation."""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse
from xml.etree import ElementTree as ET

import httpx
import jwt
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from lxml import etree
from signxml import XMLVerifier
from signxml.exceptions import InvalidSignature

from auth_helpers import create_access_token, create_refresh_token, set_auth_cookies
from session_security import create_bound_auth_session
from config import settings
from database import db
from deps import write_audit

sso_router = APIRouter(prefix="/api/auth/sso", tags=["federated-sso"])

_STATE_TTL = timedelta(minutes=10)
_HTTP_TIMEOUT = httpx.Timeout(5.0, connect=5.0)

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _oidc_configured() -> bool:
    return bool(
        settings.OIDC_ENABLED
        and settings.OIDC_ISSUER_URL
        and settings.OIDC_CLIENT_ID
        and settings.OIDC_CLIENT_SECRET
        and settings.OIDC_REDIRECT_URI
    )


def _saml_configured() -> bool:
    return bool(
        settings.SAML_ENABLED
        and settings.SAML_SP_ENTITY_ID.strip()
        and settings.SAML_ACS_URL.strip()
        and settings.SAML_IDP_ENTITY_ID.strip()
        and settings.SAML_IDP_SSO_URL.strip()
        and settings.SAML_IDP_X509_CERT.strip()
    )


def _issuer() -> str:
    return settings.OIDC_ISSUER_URL.rstrip("/")


def _trusted_provider_endpoint(value: str) -> str:
    parsed = urlparse(value)
    issuer = urlparse(_issuer())
    if parsed.scheme != "https" or parsed.hostname != issuer.hostname:
        raise HTTPException(503, "OIDC provider endpoint is not trusted")
    return value


async def _discovery() -> dict:
    if not _oidc_configured():
        raise HTTPException(503, "OIDC is not completely configured")
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(f"{_issuer()}/.well-known/openid-configuration")
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "OIDC provider metadata is unavailable")
    if data.get("issuer", "").rstrip("/") != _issuer():
        raise HTTPException(503, "OIDC issuer metadata mismatch")
    required = {"authorization_endpoint", "token_endpoint", "jwks_uri"}
    if not required.issubset(data):
        raise HTTPException(503, "OIDC provider metadata is incomplete")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        data[field] = _trusted_provider_endpoint(str(data[field]))
    return data


async def _jwks(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "OIDC signing keys are unavailable")
    if not isinstance(data.get("keys"), list):
        raise HTTPException(503, "OIDC signing keys are invalid")
    return data


def _verify_id_token(token: str, jwks: dict, nonce: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid OIDC ID token")

    allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
    if alg not in allowed or not kid:
        raise HTTPException(401, "Unsupported OIDC signing algorithm")

    jwk = next((key for key in jwks["keys"] if key.get("kid") == kid), None)
    if not jwk:
        raise HTTPException(401, "OIDC signing key not found")

    try:
        key = jwt.algorithms.get_default_algorithms()[alg].from_jwk(jwk)
        claims = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            audience=settings.OIDC_CLIENT_ID,
            issuer=_issuer(),
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            leeway=30,
        )
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "OIDC ID token validation failed")

    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise HTTPException(401, "OIDC nonce validation failed")
    if settings.OIDC_REQUIRE_MFA_CLAIM:
        amr = claims.get("amr", [])
        if not isinstance(amr, list) or not any(
            secrets.compare_digest(str(value), required)
            for value in amr
            for required in settings.OIDC_MFA_AMR_VALUES.split(",")
            if required.strip()
        ):
            raise HTTPException(403, "OIDC authentication does not satisfy MFA policy")
    return claims


def _tenant_and_role(claims: dict) -> tuple[str, str]:
    tenant = str(claims.get(settings.OIDC_TENANT_CLAIM, "")).strip().lower()
    allowed = {item.strip().lower() for item in settings.OIDC_ALLOWED_TENANTS.split(",") if item.strip()}
    if not tenant or tenant not in allowed:
        raise HTTPException(403, "OIDC identity is not mapped to an allowed tenant")
    role = str(claims.get(settings.OIDC_ROLE_CLAIM, "viewer")).strip().lower()
    if role not in {"viewer", "analyst", "admin"}:
        role = "viewer"
    return tenant, role


def _saml_tenant_and_role(attrs: dict[str, str]) -> tuple[str, str]:
    tenant = str(attrs.get(settings.SAML_TENANT_ATTRIBUTE, "")).strip().lower()
    allowed = {item.strip().lower() for item in settings.SAML_ALLOWED_TENANTS.split(",") if item.strip()}
    if not tenant or tenant not in allowed:
        raise HTTPException(403, "SAML identity is not mapped to an allowed tenant")
    role = str(attrs.get(settings.SAML_ROLE_ATTRIBUTE, "viewer")).strip().lower()
    if role not in {"viewer", "analyst", "admin"}:
        role = "viewer"
    return tenant, role


def _normalize_x509_cert(pem_or_b64: str) -> str:
    value = pem_or_b64.strip()
    if "BEGIN CERTIFICATE" in value:
        return value
    body = "".join(value.split())
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _parse_xml_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(401, "Invalid SAML time condition") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _text(node) -> str:
    return (node.text or "").strip() if node is not None else ""


def _find(node, path: str):
    return node.find(path, NS) if node is not None else None


def _findall(node, path: str):
    return node.findall(path, NS) if node is not None else []


def _verify_saml_signature(xml_bytes: bytes, cert_pem: str) -> etree._Element:
    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError as exc:
        raise HTTPException(401, "Invalid SAML XML") from exc
    try:
        verified = XMLVerifier().verify(root, x509_cert=cert_pem)
    except InvalidSignature as exc:
        raise HTTPException(401, "SAML signature validation failed") from exc
    except Exception as exc:
        raise HTTPException(401, "SAML signature validation failed") from exc
    signed = verified.signed_xml
    if signed is None:
        raise HTTPException(401, "SAML response is not signed")
    return signed


def _extract_assertion(root: etree._Element) -> etree._Element:
    assertion = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    if assertion is None:
        assertion = root if _local(root.tag) == "Assertion" else None
    if assertion is None:
        raise HTTPException(401, "SAML response is missing an Assertion")
    return assertion


def _collect_attributes(assertion: etree._Element) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for attr in assertion.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        name = attr.get("Name") or attr.get("FriendlyName") or ""
        values = [
            (v.text or "").strip()
            for v in attr.findall("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
            if (v.text or "").strip()
        ]
        if name and values:
            attrs[name] = values[0]
            # also index by short name after last /
            short = name.rsplit("/", 1)[-1]
            attrs.setdefault(short, values[0])
    name_id = assertion.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    if name_id is not None and (name_id.text or "").strip():
        attrs.setdefault("NameID", (name_id.text or "").strip())
        attrs.setdefault("email", (name_id.text or "").strip())
    return attrs


def validate_saml_response(saml_response_b64: str, expected_request_id: str | None) -> dict:
    """Validate a SAML Response and return identity attributes.

    Enforces signature, issuer, audience, destination, recipient, time conditions,
    InResponseTo correlation, and required subject attributes.
    """
    if not _saml_configured():
        raise HTTPException(503, "SAML is not completely configured")
    if not saml_response_b64 or len(saml_response_b64) > 512_000:
        raise HTTPException(400, "Invalid SAMLResponse")

    try:
        xml_bytes = base64.b64decode(saml_response_b64, validate=False)
    except Exception as exc:
        raise HTTPException(400, "SAMLResponse is not valid base64") from exc

    cert_pem = _normalize_x509_cert(settings.SAML_IDP_X509_CERT)
    signed_root = _verify_saml_signature(xml_bytes, cert_pem)

    # Prefer protocol Response root when present
    response = signed_root
    if _local(signed_root.tag) != "Response":
        # Assertion-only signed payload is acceptable if envelope checks still pass via parent parse
        try:
            full_root = etree.fromstring(xml_bytes)
        except etree.XMLSyntaxError as exc:
            raise HTTPException(401, "Invalid SAML XML") from exc
        response = full_root if _local(full_root.tag) == "Response" else signed_root

    status_code = response.find(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    if status_code is not None:
        value = status_code.get("Value", "")
        if value and not value.endswith("Success"):
            raise HTTPException(401, "SAML authentication was not successful")

    issuer = response.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer_text = _text(issuer)
    if not secrets.compare_digest(issuer_text, settings.SAML_IDP_ENTITY_ID.strip()):
        raise HTTPException(401, "SAML issuer mismatch")

    destination = response.get("Destination") or ""
    if destination and not secrets.compare_digest(destination.rstrip("/"), settings.SAML_ACS_URL.strip().rstrip("/")):
        raise HTTPException(401, "SAML destination mismatch")

    in_response_to = response.get("InResponseTo") or ""
    if expected_request_id:
        if not in_response_to or not secrets.compare_digest(in_response_to, expected_request_id):
            raise HTTPException(401, "SAML InResponseTo correlation failed")
    elif in_response_to:
        # Unsolicited responses are rejected when SP-initiated correlation is expected
        raise HTTPException(401, "Unsolicited SAML response rejected")

    assertion = _extract_assertion(signed_root if _local(signed_root.tag) == "Assertion" else response)
    assertion_id = assertion.get("ID") or ""
    if not assertion_id or len(assertion_id) > 256:
        raise HTTPException(401, "SAML assertion is missing a valid ID")

    assertion_issuer = assertion.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if assertion_issuer is not None:
        if not secrets.compare_digest(_text(assertion_issuer), settings.SAML_IDP_ENTITY_ID.strip()):
            raise HTTPException(401, "SAML assertion issuer mismatch")

    conditions = assertion.find("{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
    now = datetime.now(timezone.utc)
    skew = timedelta(seconds=max(0, settings.SAML_CLOCK_SKEW_SECONDS))
    if conditions is not None:
        not_before = _parse_xml_time(conditions.get("NotBefore"))
        not_on_or_after = _parse_xml_time(conditions.get("NotOnOrAfter"))
        if not_before and now + skew < not_before:
            raise HTTPException(401, "SAML assertion is not yet valid")
        if not_on_or_after and now - skew >= not_on_or_after:
            raise HTTPException(401, "SAML assertion has expired")

        audiences = [
            _text(a)
            for a in conditions.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
            if _text(a)
        ]
        if audiences and settings.SAML_SP_ENTITY_ID.strip() not in audiences:
            raise HTTPException(401, "SAML audience mismatch")

    subject_conf = assertion.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData")
    if subject_conf is not None:
        recipient = subject_conf.get("Recipient") or ""
        if recipient and not secrets.compare_digest(
            recipient.rstrip("/"), settings.SAML_ACS_URL.strip().rstrip("/")
        ):
            raise HTTPException(401, "SAML recipient mismatch")
        conf_not_on_or_after = _parse_xml_time(subject_conf.get("NotOnOrAfter"))
        if conf_not_on_or_after and now - skew >= conf_not_on_or_after:
            raise HTTPException(401, "SAML subject confirmation has expired")
        conf_in_response_to = subject_conf.get("InResponseTo") or ""
        if expected_request_id and conf_in_response_to:
            if not secrets.compare_digest(conf_in_response_to, expected_request_id):
                raise HTTPException(401, "SAML subject InResponseTo mismatch")

    attrs = _collect_attributes(assertion)
    email = str(attrs.get(settings.SAML_EMAIL_ATTRIBUTE) or attrs.get("email") or attrs.get("NameID") or "").strip().lower()
    subject = str(attrs.get("NameID") or email).strip()
    if not subject or not email or "@" not in email:
        raise HTTPException(403, "SAML identity is missing required subject or email")

    tenant, role = _saml_tenant_and_role(attrs)
    name = str(attrs.get(settings.SAML_NAME_ATTRIBUTE) or attrs.get("displayName") or email)[:200]

    return {
        "assertion_id": assertion_id,
        "subject": subject,
        "email": email,
        "name": name,
        "tenant": tenant,
        "role": role,
    }


def _build_authn_request(request_id: str) -> str:
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = ET.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
        {
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": settings.SAML_IDP_SSO_URL.strip(),
            "AssertionConsumerServiceURL": settings.SAML_ACS_URL.strip(),
            "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
    )
    issuer = ET.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer.text = settings.SAML_SP_ENTITY_ID.strip()
    name_id_policy = ET.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy",
        {
            "Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "AllowCreate": "true",
        },
    )
    _ = name_id_policy
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return base64.b64encode(xml).decode("ascii")


@sso_router.get("/config")
async def sso_config():
    return {
        "saml": {
            "enabled": settings.SAML_ENABLED,
            "configured": _saml_configured(),
        },
        "oidc": {"enabled": settings.OIDC_ENABLED, "configured": _oidc_configured()},
    }


@sso_router.get("/oidc/login")
async def oidc_login():
    metadata = await _discovery()
    state = _b64(secrets.token_bytes(32))
    nonce = _b64(secrets.token_bytes(32))
    verifier = _b64(secrets.token_bytes(48))
    challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())
    expires = datetime.now(timezone.utc) + _STATE_TTL

    await db.sso_oidc_states.insert_one({
        "state_hash": _sha256(state),
        "nonce": nonce,
        "code_verifier": verifier,
        "expires_at": expires,
        "used": False,
    })
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "scope": settings.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{metadata['authorization_endpoint']}?{urlencode(params)}", status_code=302)


@sso_router.get("/oidc/callback")
async def oidc_callback(request: Request):
    error = request.query_params.get("error")
    if error:
        raise HTTPException(401, "OIDC authentication was not completed")
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    if not state or not code or len(state) > 256 or len(code) > 4096:
        raise HTTPException(400, "Invalid OIDC callback")

    now = datetime.now(timezone.utc)
    record = await db.sso_oidc_states.find_one_and_update(
        {"state_hash": _sha256(state), "used": False, "expires_at": {"$gt": now}},
        {"$set": {"used": True, "used_at": now}},
    )
    if not record:
        raise HTTPException(401, "Invalid or expired OIDC state")
    nonce = record["nonce"]
    verifier = record["code_verifier"]

    metadata = await _discovery()
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
            response = await client.post(
                metadata["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.OIDC_REDIRECT_URI,
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "code_verifier": verifier,
                },
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            tokens = response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(401, "OIDC token exchange failed")

    id_token = tokens.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise HTTPException(401, "OIDC provider did not return an ID token")
    claims = _verify_id_token(id_token, await _jwks(metadata["jwks_uri"]), nonce)

    subject = str(claims.get("sub", "")).strip()
    email = str(claims.get("email", "")).strip().lower()
    if not subject or not email:
        raise HTTPException(403, "OIDC identity is missing required subject or email")
    tenant, role = _tenant_and_role(claims)

    user = await db.users.find_one({"oidc_issuer": _issuer(), "oidc_sub": subject})
    if not user:
        user = await db.users.find_one({"email": email})
        if user and not settings.OIDC_ALLOW_EMAIL_LINKING:
            raise HTTPException(403, "Existing account requires explicit OIDC provider linking")
    if user:
        if user.get("oidc_issuer") and user.get("oidc_issuer") != _issuer():
            raise HTTPException(403, "Account is bound to a different identity provider")
        if user.get("tenant") != tenant:
            raise HTTPException(403, "OIDC tenant mapping does not match the account")
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"oidc_issuer": _issuer(), "oidc_sub": subject, "oidc_last_login_at": now}},
        )
    else:
        user_id = secrets.token_hex(16)
        await db.users.insert_one({
            "id": user_id,
            "email": email,
            "name": str(claims.get("name") or claims.get("preferred_username") or email)[:200],
            "role": role,
            "tenant": tenant,
            "oidc_issuer": _issuer(),
            "oidc_sub": subject,
            "oidc_last_login_at": now,
            "created_at": now.isoformat(),
        })
        user = await db.users.find_one({"id": user_id})

    session_id, refresh_jti = await create_bound_auth_session(user["id"], request)
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], session_id)
    refresh = create_refresh_token(user["id"], session_id, refresh_jti)
    response = RedirectResponse(settings.OIDC_SUCCESS_REDIRECT_URL, status_code=303)
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "oidc_login", "auth", request, user["tenant"])
    return response


@sso_router.get("/saml/login")
async def saml_login():
    if not _saml_configured():
        raise HTTPException(
            503,
            "SAML integration remains disabled until SP/IdP entity IDs, ACS URL, SSO URL, and IdP certificate are configured",
        )
    request_id = "_" + secrets.token_hex(16)
    expires = datetime.now(timezone.utc) + _STATE_TTL
    await db.sso_saml_requests.insert_one({
        "request_id": request_id,
        "request_id_hash": _sha256(request_id),
        "expires_at": expires,
        "used": False,
    })
    saml_request = _build_authn_request(request_id)
    params = {"SAMLRequest": saml_request}
    # RelayState is optional; omit to avoid open-redirect risk
    return RedirectResponse(f"{settings.SAML_IDP_SSO_URL.strip()}?{urlencode(params)}", status_code=302)


@sso_router.post("/saml/acs")
async def saml_acs(request: Request, SAMLResponse: str = Form(...)):
    if not _saml_configured():
        raise HTTPException(
            503,
            "SAML integration remains disabled until assertion signature, audience, issuer, recipient, and replay validation are configured",
        )

    now = datetime.now(timezone.utc)
    # Consume any matching pending request if InResponseTo will be present;
    # validation below still enforces correlation when a request was issued.
    # We look up after parsing would require two-pass; instead consume by scanning
    # is avoided — validate_saml_response checks InResponseTo against a provided id.
    # Strategy: decode just enough is expensive; instead find unused recent requests
    # is not secure. We require InResponseTo and look it up atomically.

    # First pass: decode XML enough to read InResponseTo without trusting content
    try:
        xml_bytes = base64.b64decode(SAMLResponse, validate=False)
        rough = etree.fromstring(xml_bytes)
    except Exception as exc:
        raise HTTPException(400, "Invalid SAMLResponse") from exc

    in_response_to = rough.get("InResponseTo") or ""
    if not in_response_to:
        raise HTTPException(401, "Unsolicited SAML response rejected")

    pending = await db.sso_saml_requests.find_one_and_update(
        {"request_id": in_response_to, "used": False, "expires_at": {"$gt": now}},
        {"$set": {"used": True, "used_at": now}},
    )
    if not pending:
        raise HTTPException(401, "Invalid or expired SAML request correlation")

    identity = validate_saml_response(SAMLResponse, expected_request_id=in_response_to)

    # Replay protection on assertion ID
    replay = await db.sso_saml_assertions.find_one_and_update(
        {"assertion_id_hash": _sha256(identity["assertion_id"])},
        {
            "$setOnInsert": {
                "assertion_id_hash": _sha256(identity["assertion_id"]),
                "seen_at": now,
                "expires_at": now + timedelta(hours=24),
            }
        },
        upsert=True,
    )
    # find_one_and_update with upsert returns the doc before update when not ReturnDocument.AFTER;
    # if a prior document existed, this is a replay.
    if replay is not None and replay.get("seen_at"):
        raise HTTPException(401, "SAML assertion replay detected")

    email = identity["email"]
    subject = identity["subject"]
    tenant = identity["tenant"]
    role = identity["role"]
    idp = settings.SAML_IDP_ENTITY_ID.strip()

    user = await db.users.find_one({"saml_idp": idp, "saml_subject": subject})
    if not user:
        user = await db.users.find_one({"email": email})
        if user and not settings.SAML_ALLOW_EMAIL_LINKING:
            raise HTTPException(403, "Existing account requires explicit SAML provider linking")
    if user:
        if user.get("saml_idp") and user.get("saml_idp") != idp:
            raise HTTPException(403, "Account is bound to a different identity provider")
        if user.get("tenant") != tenant:
            raise HTTPException(403, "SAML tenant mapping does not match the account")
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"saml_idp": idp, "saml_subject": subject, "saml_last_login_at": now}},
        )
    else:
        user_id = secrets.token_hex(16)
        await db.users.insert_one({
            "id": user_id,
            "email": email,
            "name": identity["name"],
            "role": role,
            "tenant": tenant,
            "saml_idp": idp,
            "saml_subject": subject,
            "saml_last_login_at": now,
            "created_at": now.isoformat(),
        })
        user = await db.users.find_one({"id": user_id})

    session_id, refresh_jti = await create_bound_auth_session(user["id"], request)
    access = create_access_token(user["id"], user["email"], user["role"], user["tenant"], session_id)
    refresh = create_refresh_token(user["id"], session_id, refresh_jti)
    response = RedirectResponse(settings.SAML_SUCCESS_REDIRECT_URL, status_code=303)
    set_auth_cookies(response, access, refresh)
    await write_audit(user["email"], "saml_login", "auth", request, user["tenant"])
    return response
