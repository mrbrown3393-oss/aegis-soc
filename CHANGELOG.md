# Changelog

## v2.2.0 — 2026-10-05

### Added
- **Production SAML 2.0 federation** (SP-initiated HTTP-Redirect AuthnRequest + HTTP-POST ACS)
  - XML signature verification against configured IdP X.509 certificate (`signxml`)
  - Issuer, audience, destination, recipient, and time-condition validation
  - InResponseTo request correlation with one-time server-side request records
  - Assertion-ID replay protection (24h TTL index)
  - Explicit tenant/role attribute mapping with allowlists
  - Fail-closed production startup validation when `SAML_ENABLED=true`
  - Audit logging (`saml_login`)
- Regression tests for forged, expired, wrong-audience, and valid signed assertions

### Security
- Remote security edge Phase 4 merged (ingress credential enforcement)
- Dependabot major frontend bumps deferred (TypeScript 7, Tailwind 4, Recharts 3, lucide 1, plugin-react 6)

### Dependencies
- `lxml==6.0.2`
- `signxml==4.2.0`

## v2.1.0

- Zero Trust enforcement, device-bound sessions, step-up MFA
- Production OIDC SSO
- Remote security edge Phases 1–3
- Atomic auth lockouts and refresh rotation
