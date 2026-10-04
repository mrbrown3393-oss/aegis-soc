# Aegis SOC — Evidence Catalog

**Version**: 1.0 · **Effective**: 2026-10-04 · **Platform**: v2.1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Companion**: `SECURITY_DOSSIER.md` §9 · `SECURITY.md`

Authoritative map from **IMPLEMENTED** controls to source evidence after the backend modularization (routers / `auth_helpers` / `deps` / `config` / `seed`).

---

## Application security

| Control | Evidence |
| --- | --- |
| Password hashing (bcrypt cost 12) | `backend/auth_helpers.py` → `hash_password()`, `verify_password()` |
| JWT access + refresh issuance | `backend/auth_helpers.py` → `create_access_token()`, `create_refresh_token()` |
| Server-side sessions / revocation | `backend/auth_helpers.py` → `create_auth_session`, `revoke_*`, `active_session` |
| Idle session timeout | `backend/auth_helpers.py` → `active_session()`; 15-minute rolling inactivity limit |
| Session revalidation on each request | `backend/deps.py` → `get_current_user()` |
| MFA (TOTP ±1 window) | `backend/auth_helpers.py` → `totp`, `verify_totp`; `backend/routers/auth.py` MFA routes |
| Brute-force / MFA / reset lockouts | `backend/auth_helpers.py` lockout helpers; `backend/routers/auth.py` |
| Authenticated endpoint rate limiting | `backend/auth_helpers.py` → `enforce_authenticated_rate_limit()`; Mongo-backed 120 requests/minute window |
| Auth routes (register, login, logout, refresh, password reset) | `backend/routers/auth.py` |
| RBAC | `backend/deps.py` → `require_role()` |
| Tenant scoping | `backend/deps.py` → `tenant_filter()` |
| Audit writer | `backend/deps.py` → `write_audit()` |
| CSRF origin guard | `backend/server.py` → `csrf_origin_guard` |
| Production fail-closed gates | `backend/config.py` → `validate_security_settings()` |
| Security headers | `backend/security_hardening.py` |
| SSO fail-closed | `backend/sso.py` |
| Telemetry fusion / quarantine | `backend/anomaly.py` |
| Indexes + demo seed | `backend/seed.py` |
| App entrypoint / router wiring | `backend/server.py` |

## Infrastructure & ops artifacts

| Control | Evidence |
| --- | --- |
| MongoDB TLS / encryption runbook | `ops/mongodb/` |
| Ingress security headers | `ops/ingress/security-headers.yaml` |
| Security CI (Gitleaks, pip-audit, Trivy, SBOM) | `.github/workflows/security.yml` |
| Dependabot | `.github/dependabot.yml` |
| Backend security tests | `tests/test_backend_security.py` |

## Policy & compliance documents

| Document | Path |
| --- | --- |
| Security entry point | `SECURITY.md` |
| Control dossier | `SECURITY_DOSSIER.md` |
| Hardening guide | `SECURITY_HARDENING.md` |
| NIST alignment | `NIST_ALIGNMENT.md` |
| Policy pack | `docs/SECURITY_POLICY_PACK.md` |
| Incident response plan | `docs/INCIDENT_RESPONSE_PLAN.md` |
| Rules of behavior | `docs/RULES_OF_BEHAVIOR.md` |
| Ops pack index | `docs/ops/README.md` |
| POA&M tracker | `docs/ops/POAM_TRACKER.md` |
| Deployment hardening checklist | `docs/ops/DEPLOYMENT_HARDENING_CHECKLIST.md` |

## Honesty reminders

- Evidence supports **IMPLEMENTED** claims only where code or signed procedure exists.  
- Tenant isolation remains **logical / query-level** until database-level isolation ships.  
- FedRAMP / SOC 2 / ISO / CMMC references are **design targets**, not authorizations.

---

**William Brown** · Owner & Operator — Aegis SOC
