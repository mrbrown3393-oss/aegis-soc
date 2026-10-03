# Federated SSO — SAML 2.0 & OIDC Setup

Aegis SOC supports federated single sign-on for enterprise tenants. Federation is the **required** production authentication method (AEG-AC-001 §1.2); local passwords remain only as a break-glass fallback for `owner`/`admin`.

## Architecture

```
Browser ──▶ Aegis (SP / RP) ──▶ IdP (Okta, Entra ID, Keycloak, ADFS…)
   ◀── httpOnly JWT session cookies ── SAML assertion / OIDC code flow ──▶
```

- On successful federation, Aegis issues its normal short-lived session (JWT access 12 h + refresh 7 d in httpOnly/Secure cookies) — no downstream code changes needed.
- Users are provisioned **just-in-time** with least privilege (`viewer`/`private` by default). Group-claim mapping can grant `admin`.
- Federated users get `password_hash = None` — local login is impossible for them.
- Every federation event is written to `audit_logs` (`sso_login_oidc` / `sso_login_saml`).

## OIDC

```bash
OIDC_ENABLED=true
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_ISSUER=https://idp.example.com
OIDC_REDIRECT_URI=https://aegis.example.com/api/auth/sso/oidc/callback
OIDC_ADMIN_GROUP=aegis-admins   # optional
```

Endpoints: `GET /api/auth/sso/oidc/login` → `GET /api/auth/sso/oidc/callback`.
Requires the Starlette session middleware (installed by `backend/security_setup.py`) for OAuth state/nonce storage, and `authlib` + `httpx` from `backend/requirements.txt`.

## SAML 2.0

```bash
SAML_ENABLED=true
SAML_SP_ENTITY_ID=https://aegis.example.com/api/auth/sso/saml/metadata
SAML_SP_ACS_URL=https://aegis.example.com/api/auth/sso/saml/acs
SAML_IDP_ENTITY_ID=https://idp.example.com/entity
SAML_IDP_SSO_URL=https://idp.example.com/sso
SAML_IDP_X509_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
```

1. Download SP metadata: `GET /api/auth/sso/saml/metadata` and register it at your IdP.
2. Configure the IdP to send `email` (or NameID-email) and optionally a `groups` attribute.
3. Test: `GET /api/auth/sso/saml/login`.

Hardened by default: strict mode, signed assertions AND messages required, SHA-256 signature/digest only, deprecated algorithms rejected.
Requires `python3-saml` (system packages: `libxml2-dev libxmlsec1-dev libxmlsec1-openssl`).

## Operations

- **MFA** is enforced at the IdP — do not build app-level MFA for federated users.
- **IdP compromise**: run `POST /api/security/quarantine` with `action=freeze_idp` to immediately disable a federation trust (see quarantine engine).
- **Deprovisioning**: disable the user at the IdP; Aegis rejects sessions whose user record is `disabled` on the next request (session revalidation).
