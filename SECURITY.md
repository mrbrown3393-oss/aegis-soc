# Aegis SOC — Security Documentation

**Platform**: Aegis SOC v2.1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — shareable under NDA for buyer, investor, or contracting diligence  
**Last updated**: 2026-10-04

> This document is the consolidated entry point for Aegis SOC security documentation.
> It summarizes the platform's security posture and points to the authoritative artifacts in this repository.
> It does **not** replace the detailed dossier — it orients readers to it.

---

## 1. Overview

Aegis SOC is a modular, multi-tenant Security Operations Center platform unifying threat detection, incident response, vulnerability management, asset intelligence, compliance monitoring, and append-oriented audit in a single console. It ships in three deployment postures — **Government**, **Private Sector**, and **SaaS** — each with its own visual identity and target control baseline.

| Posture | Target baselines (design targets, not certifications) |
| --- | --- |
| Government | FedRAMP Moderate, CMMC Level 2, FIPS 140-3, STIG-aligned |
| Private Sector | SOC 2 Type II, ISO 27001:2022, PCI-DSS 4.0, HIPAA |
| SaaS | Multi-tenant isolation, white-label, usage billing, API-first |

**Stack**: FastAPI + MongoDB + React 19 / Vite 6 / TypeScript, deployed behind Kubernetes ingress.

---

## 2. Security Posture (Summary)

### Authentication & Sessions
- JWT access tokens (15 min) + refresh tokens (7 d) delivered in `httpOnly`, `secure`, `SameSite` cookies — JavaScript cannot read the raw token.
- Passwords hashed with **bcrypt** (cost 12, per-password salt).
- Brute-force protection: 5 failed attempts per `{ip}:{email}` triggers a 15-minute lockout; source IP is derived proxy-aware from `X-Forwarded-For` only when the peer is a trusted proxy.
- Account enumeration prevention: login always returns a generic "Invalid email or password."
- Password reset uses single-use tokens with TTL expiry.
- **MFA** (TOTP) is implemented and required when `MFA_REQUIRED=true`; production startup fails closed without `MFA_MASTER_SECRET`.
- SSO (SAML 2.0 / OIDC) endpoints exist but **fail closed** (HTTP 503) until a complete provider integration with signature, audience, issuer, replay, and JWKS validation is configured. No unsigned SAML AuthnRequest is ever emitted.

### Authorization & Tenancy
- Server-side RBAC: `owner` (cross-tenant), `admin` (tenant admin), `analyst` (triage + patch), `viewer` (read-only). Enforced via `Depends(require_role(...))` on every privileged endpoint.
- Tenant isolation is **logical / query-level**: every record carries a `tenant` field and `tenant_filter()` auto-scopes non-privileged users. Database-level isolation (per-tenant databases or row-level security) is the documented roadmap.
- The owner account cannot be deleted through the API.

### Application Security
- All routes prefixed `/api`; Pydantic v2 validation on every request body; enumerated `Literal` types for status, severity, and tenant.
- Structured exception responses — no stack traces leaked to clients.
- MongoDB queries are fully parameterized via the Motor driver; no string concatenation.
- React auto-escaping throughout; zero `dangerouslySetInnerHTML` occurrences.
- **CSRF guard**: state-changing requests carrying Aegis auth cookies are origin-checked against configured frontend/CORS origins; cross-origin mutations are rejected with 403.
- **Security headers** (HSTS, CSP, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP) applied by `SecurityHeadersMiddleware` in the backend and mirrored at the Kubernetes ingress.
- **Production fail-closed validation**: with `AEGIS_ENV=production`, startup rejects a weak/default JWT secret, default operator passwords, disabled MongoDB TLS, invalid-cert allowance, wildcard CORS, non-HTTPS frontend origin, or a missing MFA master secret.

### Data Protection
- TLS 1.2+ required in transit (TLS 1.3 preferred); MongoDB TLS mandatory in production.
- MongoDB **WiredTiger encryption at rest** mandatory in production, with the encryption key provisioned from a secret manager — never committed to Git.
- Secrets loaded exclusively from environment variables; `.env` excluded from version control; password hashes stripped before serialization.
- Managed secret stores (Vault / cloud secret managers) are buyer-infrastructure and documented in the deployment guide.

### Audit & Monitoring
- Every login, logout, and mutating action is appended to the `audit_logs` collection with actor, IP, resource, and tenant context.
- Audit logs are append-oriented and protected against unauthorized alteration.
- Security telemetry fusion with weighted geospatial centroiding and anomaly scoring is available as a product capability.
- Asset quarantine requests are auditable, tenant-scoped, and carry evidence references.

### Supply Chain & CI
- Weekly Dependabot updates for pip and npm ecosystems.
- CI security workflow runs: Gitleaks (secret scanning), pip-audit, npm audit (high+), Trivy filesystem scan (CRITICAL/HIGH, fails the build), and CycloneDX SBOM generation for both Python and Node dependencies.
- Dependency review on pull requests.

### Testing
- `tests/test_backend_security.py` covers security-header registration, proxy-aware IP attribution, production fail-closed behavior (weak JWT secret, wildcard CORS, missing MFA secret), CSRF guard behavior, TOTP acceptance windows, tenant-filter scoping, and password-policy enforcement.

---

## 3. Honest Limitations & Non-Claims

1. **No "immune to X" claims.** `httpOnly` cookies prevent JavaScript from reading the raw JWT, but a successful XSS could still make authenticated requests via the browser-attached cookie. We claim mitigation plus defense-in-depth (CSP, auto-escaping, Pydantic validation) — not immunity.
2. **Tenant isolation is logical today.** Query-time scoping is deliberate for the prototype; database-level isolation is planned.
3. **Compliance baselines are design targets.** No Aegis deployment has been formally audited or certified against FedRAMP, SOC 2, ISO 27001, PCI-DSS, HIPAA, or CMMC as of this document's date.
4. **SSO is fail-closed by design** until provider-specific verification is configured.
5. **Rate limiting** on authenticated endpoints is planned (e.g., `slowapi`).
6. **Idle timeout** and **JWT signing-key rotation** (two-active-keys pattern) are planned.
7. **Dual approval** on high-risk actions (separation of duties) is planned for FedRAMP-aligned deployments.

---

## 4. Document Map

| Document | Path | Purpose |
| --- | --- | --- |
| **Security Dossier** | `SECURITY_DOSSIER.md` | Primary security artifact: NIST CSF 2.0 mapping, NIST SP 800-207 Zero Trust tenet-by-tenet status, application/infrastructure/tenant security tables, compliance readiness scores, evidence catalog, and POA&M. |
| **NIST Alignment** | `NIST_ALIGNMENT.md` | Detailed NIST 800-53 control appendix. |
| **Security Hardening Notes** | `SECURITY_HARDENING.md` | Release notes for the hardening branch: what was implemented and deployment notes. |
| **Information Security Policy Pack** | `docs/SECURITY_POLICY_PACK.md` | Formal policy baseline: access control, data classification, cryptography, secure development, vulnerability management (24h critical / 7d high / 30d medium / 90d low), logging, IR, BCP, supply chain, governance. |
| **Incident Response Plan** | `docs/INCIDENT_RESPONSE_PLAN.md` | Platform IR plan: SEV-1..4 severity model, roles, NIST 800-61 lifecycle, evidence handling, communications, review cadence. |
| **MongoDB Hardening** | `ops/mongodb/` | Production TLS + WiredTiger encryption-at-rest configuration and runbook. |
| **Ingress Security Headers** | `ops/ingress/security-headers.yaml` | Kubernetes ingress header baseline (HSTS, CSP, frame denial, etc.). |
| **Security CI Workflow** | `.github/workflows/security.yml` | Gitleaks, pip-audit, npm audit, Trivy, CycloneDX SBOM. |
| **Dependabot** | `.github/dependabot.yml` | Weekly dependency updates. |
| **Security Tests** | `tests/test_backend_security.py` | Automated verification of the controls above. |
| **SSO Module** | `backend/sso.py` | Fail-closed SAML/OIDC integration surface. |
| **Hardening Middleware** | `backend/security_hardening.py` | Security headers middleware + proxy-aware client IP. |

---

## 5. Vulnerability Disclosure

Report suspected vulnerabilities privately to the owner:

- **Email**: `william.brown@aegis-soc.io`
- **Console**: Operator Login on the landing page

Please include steps to reproduce, affected endpoints or components, and impact assessment where possible. Do not disclose publicly before a fix or coordinated disclosure window is agreed.

---

## 6. Contact

**William Brown** — Owner & Operator  
Email: `william.brown@aegis-soc.io`  
For acquisition, government procurement, or MSSP licensing, reach out directly.

---

© 2026 Aegis SOC · All rights reserved · Transferable commercial license available