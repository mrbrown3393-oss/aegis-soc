# Aegis SOC — Security Hardening Guide

**Version**: 1.1 · **Effective**: 2026-10-04 · **Owner**: William Brown  
**Companion**: `SECURITY.md` (entry point) · `SECURITY_DOSSIER.md` (control mapping)

This document is the operational hardening baseline for deploying Aegis SOC. It is **not** a certification claim.

---

## 1. Production fail-closed gates

With `AEGIS_ENV=production`, startup **rejects** the process if any of the following are true:

| Check | Requirement |
| --- | --- |
| JWT secret | Strong secret, ≥ 32 characters, not the default placeholder |
| Operator passwords | Non-default `ADMIN_PASSWORD` / `ANALYST_PASSWORD` |
| MFA | `MFA_REQUIRED=true` and `MFA_MASTER_SECRET` ≥ 32 characters |
| MongoDB TLS | `MONGO_TLS=true`; invalid certificates not allowed |
| CORS | No wildcard origins; explicit frontend origin |
| Frontend URL | Must be HTTPS |

Source: `backend/config.py` → `validate_security_settings()`.

---

## 2. Transport and headers

| Control | Where |
| --- | --- |
| TLS 1.2+ (1.3 preferred) at ingress | Buyer / platform edge |
| HSTS, CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP | `backend/security_hardening.py` + `ops/ingress/security-headers.yaml` |
| CSRF origin guard on cookie-authenticated mutations | `backend/server.py` middleware |

---

## 3. Data protection

| Control | Notes |
| --- | --- |
| MongoDB TLS | Mandatory in production (`MONGO_TLS*`) |
| WiredTiger encryption at rest | Configure via `ops/mongodb/`; encryption key from secret manager only |
| Secrets | Environment / secret manager only; never in Git |
| Password hashes | bcrypt cost 12; stripped before API serialization |

---

## 4. Identity and access

| Control | Status |
| --- | --- |
| JWT access (15m) + refresh (7d) in httpOnly cookies | Implemented |
| Server-side session revocation | Implemented (`auth_sessions`) |
| TOTP MFA | Implemented; required in production |
| SAML / OIDC | **Fail closed** until full signature, audience, issuer, replay, and JWKS validation are configured (`backend/sso.py`) |
| RBAC + tenant scoping | Server-side (`deps.py`) |

---

## 5. Supply chain and CI

| Control | Location |
| --- | --- |
| Dependabot (pip + npm) | `.github/dependabot.yml` |
| Gitleaks, pip-audit, npm audit, Trivy, CycloneDX SBOM | `.github/workflows/security.yml` |
| Dependency review on PRs | CI |

---

## 6. Observability and response

| Control | Notes |
| --- | --- |
| Audit trail | Every login, logout, and mutation → `audit_logs` |
| Telemetry fusion / quarantine | `backend/anomaly.py` — auditable, tenant-scoped |
| Platform IR | `docs/INCIDENT_RESPONSE_PLAN.md` |
| Ops runbooks | `docs/ops/` (POA&M, restore drill, secret rotation, hardening checklist) |

---

## 7. Explicit non-claims

1. No immunity claims (including XSS). httpOnly mitigates token theft via JS; defense-in-depth is required.  
2. Tenant isolation is **logical / query-level** today; database-level isolation is planned.  
3. FedRAMP / SOC 2 / ISO / CMMC are **design targets**, not authorizations.  
4. Quarantine and threat-tracing features are observable and auditable by design.

---

## 8. Pre-production checklist

Use `docs/ops/DEPLOYMENT_HARDENING_CHECKLIST.md` before go-live. Minimum gates:

- [ ] Production env vars set; fail-closed startup succeeds  
- [ ] MongoDB TLS + encryption-at-rest keys provisioned  
- [ ] Ingress security headers verified  
- [ ] MFA enrolled for operator accounts  
- [ ] Backup + restore drill recorded  
- [ ] Secret rotation procedure tested  
- [ ] Vulnerability disclosure contact reachable  

---

**William Brown** · Owner & Operator — Aegis SOC  
`william.brown@aegis-soc.io`
