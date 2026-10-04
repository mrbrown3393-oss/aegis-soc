# Aegis SOC — FedRAMP Customer Responsibility Matrix (CRM) & Parameter Register

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Aligned to**: `docs/FEDRAMP_MODERATE_BASELINE.md` v1.0 · `SECURITY_DOSSIER.md` v1.1 · `NIST_ALIGNMENT.md` v1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> **Not an SSP, not a FedRAMP authorization package, not an ATO.**  
> This document defines **who does what** (CRM) and **organization-defined parameter values** Aegis ships or plans for a FedRAMP Moderate *design target*. Agency Authorizing Officials may override parameters; CSP inheritance depends on the chosen hosting model.

**Related:** baseline map `docs/FEDRAMP_MODERATE_BASELINE.md` · control catalog `NIST_ALIGNMENT.md` · POA&M `SECURITY_DOSSIER.md` §10

---

## 1. Roles used in this CRM

| Role | Meaning |
| --- | --- |
| **Aegis (SP)** | Software provider — implements control in product code, defaults, or shipped config/docs |
| **Customer** | Agency, MSSP, or enterprise that deploys or subscribes to Aegis and operates it for their mission |
| **CSP / Host** | Cloud or infrastructure provider running compute, network edge, and (often) managed MongoDB |
| **Shared** | Two or more parties must each complete part of the control |
| **N/A** | Control outside the Aegis software authorization boundary as defined in the baseline map |

**Deployment variants**

| Variant | Who is “CSP / Host” |
| --- | --- |
| **A — Customer-hosted** | Customer (or their IaaS) runs K8s/VMs + Mongo; Aegis supplies software + hardening guides |
| **B — Aegis-operated SaaS** | Aegis (or Aegis-contracted CSP) operates the stack; customer consumes the service |

Rows below assume **Variant A** unless noted. For Variant B, many “Customer” infrastructure rows shift to **Aegis** or **Aegis + CSP**.

---

## 2. Responsibility codes

| Code | Definition |
| --- | --- |
| **I** | **Implemented by** — party builds/operates the technical or procedural control |
| **C** | **Configured by** — party sets parameters, accounts, policies, or integrations |
| **R** | **Responsible for** — accountable for residual risk / compliance evidence |
| **U** | **Uses / inherits** — relies on another party’s implementation |

A single cell may combine codes (e.g. **I/C** = implements and configures).

---

## 3. Customer Responsibility Matrix (by control family)

### 3.1 Access Control (AC)

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| AC-2 | Account Management | **I** — invite/remove API, roles, unique email | **C/R** — approve operators, joiner/leaver process | — | Owner cannot be deleted via API |
| AC-3 | Access Enforcement | **I** — `require_role`, `tenant_filter` | **C** — assign roles/tenants | — | Only `owner` may cross tenants |
| AC-6 | Least Privilege | **I** — role model + hard tenant scope | **C/R** — grant minimum roles | — | |
| AC-7 | Unsuccessful Logon Attempts | **I** — 5 fails / 15-min lockout | **C** — set `TRUSTED_PROXY_IPS` | **U** — load balancer IP path | Proxy-aware only if trusted proxies configured |
| AC-8 | System Use Notification | **PLANNED I** | **C/R** — legal banner text | — | Not yet in product |
| AC-11 | Session Lock / Idle Timeout | **PLANNED I** | **C** — may require stricter agency value | — | Target 15 min |
| AC-12 | Session Termination | **I** — logout, `auth_sessions` revoke | **C** — force off-boarding | — | |
| AC-14 | Actions Without Identification | **I** — minimal public routes | **R** — network exposure policy | **I** — edge allow-lists | |
| AC-17 | Remote Access | **I** — HTTPS app access | **C/R** — VPN/ZTNA to management plane if required | **I** — network path | No product VPN |
| AC-20 | External Systems | **I** — CORS allow-list | **C** — approved origins | — | Production rejects `*` |

### 3.2 Identification & Authentication (IA)

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| IA-2 | Org Users | **I** — local auth + JWT | **C/R** — who may have accounts | — | |
| IA-2(1)(2) | MFA | **I** — TOTP; prod `MFA_REQUIRED` | **C** — enroll tokens; **R** — user training | — | WebAuthn/PIV **PLANNED** |
| IA-2(12) | PIV | **PLANNED I** | **C/R** — PIV issuance | — | Federal path |
| IA-5 | Authenticator Mgmt | **I** — bcrypt 12, reset TTL | **C** — secret manager for `JWT_SECRET`, `MFA_MASTER_SECRET` | — | |
| IA-5(1) | Password policy | **I** — min length; complexity **PLANNED** | **C** — may impose stricter policy via IdP | — | |
| IA-5(7) | No static defaults | **I** — prod fail-closed | **C** — never deploy with defaults | — | |
| IA-8 | Non-org users | **I** — register/SSO surface | **C** — IdP integration | — | SSO fail-closed until configured |
| IA-11 | Re-auth | **PLANNED I** | **C** — which actions require step-up | — | |
| IA-12 | Identity proofing | — | **I/R** — agency proofing | — | Out of Aegis boundary |

### 3.3 Audit & Accountability (AU)

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| AU-2 / AU-12 | Event logging / generation | **I** — `write_audit` | **C** — what to export | — | |
| AU-3 | Audit content | **I** — actor, action, resource, IP, tenant, time | — | — | |
| AU-6 | Review & reporting | **I** — Audit UI / export | **I/R** — review cadence, SIEM use | — | Platform SIEM forward **PLANNED** |
| AU-8 | Time stamps | **I** — UTC | **C** — NTP on hosts | **I** — host time sync | |
| AU-9 | Protect audit info | **I** — append-oriented app writes | **C/R** — access to DB backups | **I** — storage controls | WORM/hash-chain **PLANNED** |
| AU-11 | Retention | **PLANNED I** (app policy) | **C/R** — legal retention / holds | **I** — backup retention | See parameter register |

### 3.4 System & Communications Protection (SC)

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| SC-5 | DoS protection | **PLANNED I** — API rate limits | **C** — WAF rules | **I** — edge DDoS | Shared |
| SC-7 | Boundary protection | **I** — app surface limited | **C** — NetworkPolicies, SG | **I** — VPC, firewalls | |
| SC-8 | Transmission confidentiality | **I** — TLS-oriented defaults, HSTS | **C** — certs if customer-hosted | **I** — ingress TLS | Prod requires HTTPS frontend |
| SC-12 | Key management | **I** — code uses env secrets | **I/C/R** — secret store, rotation | **U** — KMS if used | JWT rotation **PLANNED** |
| SC-13 | Cryptographic protection | **I** — bcrypt, TLS, JWT | **C** — FIPS platform choice | **I** — FIPS host images if required | FIPS modules **PLANNED** |
| SC-23 | Session authenticity | **I** — httpOnly cookies, CSRF origin guard, server sessions | — | — | |
| SC-28 | Protection at rest | **I** — WiredTiger config + runbook | **I/C/R** — encryption keys, enablement | **I** — disk encryption option | **Keys never in Git** |

### 3.5 Configuration, Integrity, Risk (CM / SI / RA)

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| CM-2 / CM-6 | Baseline / settings | **I** — hardened defaults | **C** — env for deployment | **I** — OS baseline | |
| CM-3 | Change control | **I** — GitHub workflows | **C/R** — prod change approval | — | Branch protection **PLANNED** as ops |
| CM-8 | Component inventory | **I** — CycloneDX SBOM in CI | **U** — consume SBOM | — | |
| RA-5 | Vuln monitoring | **I** — Dependabot, pip-audit, npm audit, Trivy, Gitleaks | **I/R** — runtime/host scanning | **I** — infra scanning | Pipeline ≠ full runtime ConMon |
| SI-2 | Flaw remediation | **I** — patch SLAs in policy pack | **C/R** — deploy patches in their window | — | 24h / 7d / 30d / 90d targets |
| SI-10 | Input validation | **I** — Pydantic, Literals, parameterized queries | — | — | |
| SI-11 | Error handling | **I** — no stack traces to clients | — | — | |

### 3.6 Contingency, Incident, Assessment (CP / IR / CA)

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| CP-2 | Contingency plan | **PLANNED I** (doc) | **C/R** — mission RTO/RPO | **I** — region failover | |
| CP-9 | Backup | **I** — guidance | **I/C/R** — backup jobs, test restores | **I** — snapshot features | Drill **PLANNED** |
| CP-10 | Recovery | **PLANNED** runbooks | **I/R** — execute recovery | **U** | |
| IR-1 / IR-8 | IR policy & plan | **I** — `docs/INCIDENT_RESPONSE_PLAN.md` | **C** — insert agency contacts/SLAs | — | |
| IR-4 | Incident handling | **I** — plan + product IR workspace | **I/R** — declare customer incidents | — | Shared for platform vs mission data |
| IR-6 | Reporting | **PARTIAL I** | **I/R** — US-CERT / agency reporting as required | — | |
| CA-5 | POA&M | **I** — dossier POA&M | **C/R** — track deployment-specific findings | — | |
| CA-7 | Continuous monitoring | **PARTIAL I** | **I/R** — agency ConMon program | **I** — infra metrics | Platform ConMon dashboard **PLANNED** |
| CA-8 | Penetration testing | **R** coordinate | **C** — authorize scope | — | External 3PAO **PLANNED** |

### 3.7 Physical, Personnel, Planning, Supply Chain

| Control | Title | Aegis (SP) | Customer | CSP / Host | Notes |
| --- | --- | --- | --- | --- | --- |
| PE-* | Physical / environmental | **N/A** | **U** | **I/R** | Inherited |
| PS-* | Personnel security | **PARTIAL** (sole owner today) | **I/R** — screening of their operators | **I** — CSP staff | |
| AT-* | Awareness & training | **PLANNED** | **I/R** — user training | — | |
| PL-1 | Security policy | **I** — policy pack | **C** — adopt/supplement | — | |
| PL-2 | System security plan | **PARTIAL I** — dossier + baseline | **I/R** — authorization package for *their* system | — | |
| SR-3 / SR-4 | Supply chain / provenance | **I** — SBOM, dependency scanning | **U** | **I** — CSP supply chain | Vendor risk process **PLANNED** |

### 3.8 CRM summary (quick view)

| Area | Primarily Aegis | Primarily Customer | Primarily CSP |
| --- | --- | --- | --- |
| App authn/z, MFA, RBAC, CSRF, headers | ✓ | Configure users/IdP | — |
| Audit generation | ✓ | Review / retain / SIEM | Storage substrate |
| TLS app path | Defaults + middleware | Certs if self-hosted | Ingress / edge |
| Encryption at rest **keys** | Config only | ✓ provision & drill | Disk / KMS options |
| Host scanning, PE, DDoS | Guidance | Policy | ✓ implement |
| Agency ATO / ConMon program | Evidence support | ✓ own | CSP attestations |

---

## 4. Organization-defined parameter register

Parameters below are **Aegis product defaults or planned defaults**. An agency may require stricter values; those become **Customer** parameters layered via policy, IdP, or contract.

### 4.1 Access & session parameters

| Control | Parameter | Aegis value (current / planned) | Status | Config surface | Agency may tighten? |
| --- | --- | --- | --- | --- | --- |
| AC-7 | Consecutive failed attempts before lockout | **5** | Current | Code (`LOCKOUT_THRESHOLD`) | Yes (lower) |
| AC-7 | Lockout duration | **15 minutes** | Current | Code (`LOCKOUT_MINUTES`) | Yes (longer) |
| AC-7 | Lockout key | `{client_ip}:{email}` with proxy-aware IP | Current | `TRUSTED_PROXY_IPS` | Yes |
| AC-11 | Idle session timeout | **15 minutes** (FedRAMP-oriented target) | **PLANNED** | TBD | Yes |
| AC-12 | Access token lifetime | **15 minutes** | Current | `ACCESS_TOKEN_MINUTES` | Yes (shorter) |
| AC-12 | Refresh token lifetime | **7 days** | Current | `REFRESH_TOKEN_DAYS` | Yes (shorter) |
| AC-12 | MFA pending token lifetime | **5 minutes** | Current | Code | Yes |
| AC-8 | System use notification text | Agency-supplied banner | **PLANNED** | TBD | Required text is Customer/Agency |
| AC-20 | Allowed CORS / frontend origins | Explicit list; **no `*` in production** | Current | `CORS_ORIGINS`, `FRONTEND_URL` | Yes (narrower) |

### 4.2 Identification & authentication parameters

| Control | Parameter | Aegis value (current / planned) | Status | Config surface | Agency may tighten? |
| --- | --- | --- | --- | --- | --- |
| IA-5(1) | Minimum password length | Enforced minimum on register/invite/reset (short passwords rejected); **12+ with complexity planned** | Current / **PLANNED** | Pydantic validators | Yes |
| IA-5(1) | Password complexity | Not fully enforced beyond length / bcrypt limits | **PLANNED** | TBD | Yes |
| IA-5(1) | Password history / reuse | Not implemented | **PLANNED** | TBD | Yes |
| IA-5 | Password hash algorithm | **bcrypt**, cost **12** | Current | Code | Agency may require FIPS module path |
| IA-5 | Password-reset token | Single-use + TTL index | Current | Mongo TTL | Yes (shorter TTL) |
| IA-2(1)(2) | MFA required | **`MFA_REQUIRED=true` required in production** | Current | Env + `validate_security_settings()` | Yes |
| IA-2 | MFA method | **TOTP** (±1 time step); WebAuthn/PIV planned | Current / **PLANNED** | Code / future IdP | Yes (PIV) |
| IA-5 | JWT signing | **HS256** with `JWT_SECRET` (min 32 chars in prod) | Current | Env | Key rotation **PLANNED** |
| IA-5 | MFA master secret | Required in production (min 32 chars) | Current | `MFA_MASTER_SECRET` | — |
| IA-8 | SSO | SAML/OIDC routes **fail closed** until fully configured | Current | `SAML_*`, `OIDC_*` | Customer IdP |

### 4.3 Audit parameters

| Control | Parameter | Aegis value (current / planned) | Status | Config surface | Agency may tighten? |
| --- | --- | --- | --- | --- | --- |
| AU-8 | Time standard | **UTC** ISO-8601 | Current | Code | — |
| AU-3 | Mandatory fields | actor, action, resource, IP, tenant, timestamp | Current | `write_audit()` | Additional fields possible |
| AU-11 | Online retention | **90 days** target | **PLANNED** | Policy / ops | Yes (longer) |
| AU-11 | Archive retention | **1 year** minimum target | **PLANNED** | Policy / ops | Yes (longer) |
| AU-6 | Review frequency | Customer-defined; product provides UI/export | Partial | Process | Agency ConMon calendar |
| AU-9 | Integrity protection | Append-oriented application writes; hash-chain/WORM planned | Current / **PLANNED** | Ops | Yes |

### 4.4 Cryptography & boundary parameters

| Control | Parameter | Aegis value (current / planned) | Status | Config surface | Agency may tighten? |
| --- | --- | --- | --- | --- | --- |
| SC-8 | TLS version | **TLS 1.2+** (1.3 preferred) at ingress | Current (inherited + headers) | Ingress / CSP | Yes (1.3 only) |
| SC-8 | HSTS | `max-age=63072000; includeSubDomains; preload` | Current | Middleware + ingress | Yes |
| SC-28 | Encryption at rest | WiredTiger encryption **required in production posture**; key outside Git | Config **shipped**; ops **Customer/CSP** | `ops/mongodb/`, secret manager | Yes |
| SC-28 | MongoDB TLS | **`MONGO_TLS=true` required in production**; invalid certs forbidden | Current | Env | Yes (mTLS) |
| SC-13 | FIPS 140 modules | Not claimed; **PLANNED** where required | **PLANNED** | Build/host | Agency path |
| SC-5 | API rate limits | Per-user / per-endpoint quotas | **PLANNED** | TBD (`slowapi` or equivalent) | Yes |
| SC-7 | Public attack surface | `/`, `/api/*`, static assets | Current | Routes | Narrow via edge |

### 4.5 Vulnerability & integrity parameters

| Control | Parameter | Aegis value (current / planned) | Status | Config surface | Agency may tighten? |
| --- | --- | --- | --- | --- | --- |
| SI-2 / RA-5 | Critical remediation target | **24 hours** where feasible | Policy pack | Process | Yes |
| SI-2 | High | **7 days** | Policy pack | Process | Yes |
| SI-2 | Medium | **30 days** | Policy pack | Process | Yes |
| SI-2 | Low | **90 days** | Policy pack | Process | Yes |
| RA-5 | Dependency scan cadence | **Weekly** Dependabot + scheduled security workflow | Current | `.github/` | Yes (daily) |
| RA-5 | CI fail threshold (Trivy) | **CRITICAL, HIGH** fail build | Current | `security.yml` | Yes |
| CM-8 | SBOM format | **CycloneDX JSON** (Python + Node) | Current | CI artifacts | — |

### 4.6 Contingency parameters (targets — not yet operationalized)

| Control | Parameter | Aegis suggested target | Status | Owner to finalize |
| --- | --- | --- | --- | --- |
| CP-2 | RTO (platform control plane) | **24–72 hours** (TBD by contract) | **PLANNED** | Customer + Aegis |
| CP-2 | RPO | **≤ 24 hours** (TBD; depends on backup cadence) | **PLANNED** | Customer + Host |
| CP-9 | Backup frequency | **Daily** minimum suggested | **PLANNED** | Customer / CSP |
| CP-4 | Restore test cadence | **At least annually** + after major changes | **PLANNED** | Customer + Aegis |

### 4.7 Production fail-closed parameters (non-negotiable in `AEGIS_ENV=production`)

These are enforced in `validate_security_settings()` and are part of Aegis’s security posture—not optional “tips.”

| Check | Required value |
| --- | --- |
| `JWT_SECRET` | Not default; length ≥ 32 |
| Operator passwords | Not `change-me` |
| `MFA_REQUIRED` | `true` |
| `MFA_MASTER_SECRET` | Length ≥ 32 |
| `MONGO_TLS` | `true` |
| `MONGO_TLS_ALLOW_INVALID_CERTS` | `false` |
| `CORS_ORIGINS` | No `*` |
| `FRONTEND_URL` | Non-empty; must be `https://` |

---

## 5. How to use this register in an engagement

1. **Customer** marks each CRM row as accepted, negotiated, or blocked for their deployment variant (A or B).  
2. **Customer / Agency** copies the parameter register into their SSP and records any stricter agency values.  
3. Gaps where Aegis is **PLANNED** feed the shared POA&M (`SECURITY_DOSSIER.md` §10).  
4. **CSP** inheritance (PE, edge DDoS, managed DB) must be filled from the CSP’s FedRAMP package when the host is authorized.

---

## 6. Explicit non-claims

1. This CRM does **not** transfer residual risk without a contract and authorization decision.  
2. Parameter values are **engineering defaults / targets**, not agency-approved settings.  
3. Completing Customer columns is **necessary but not sufficient** for FedRAMP Moderate authorization.  
4. Variant B (Aegis-operated SaaS) requires a revised CRM before it is used in a package.

---

## 7. Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial CRM and organization-defined parameter register for FedRAMP Moderate design target. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`

© 2026 Aegis SOC · All rights reserved
