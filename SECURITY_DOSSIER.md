# Aegis SOC — Security & Compliance Dossier

**Document version**: 1.1
**Platform version**: v2.1.0
**Prepared**: Q1 2026 · **Revised**: 2026-10-04
**Owner**: William Brown (`william.brown@aegis-soc.io`)
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence
**Companion entry point**: `SECURITY.md` (consolidated summary). This dossier remains the detailed control mapping. `NIST_ALIGNMENT.md` remains the NIST 800-53 appendix.

---

## 0. How to Read This Dossier

### Control-status taxonomy

Every control in this dossier is marked with exactly one of four statuses. The taxonomy is strict and applied honestly — a 3PAO, SOC 2 auditor, or buyer's CISO should be able to open the referenced code and verify every `IMPLEMENTED` claim.

| Status | Meaning |
| --- | --- |
| **IMPLEMENTED** | Control is fully in effect in the current build. Code, configuration, or operational evidence is available. |
| **PARTIAL** | Some elements of the control are satisfied; others are not. Specific gap is called out. |
| **PLANNED** | Control is not yet satisfied. A documented remediation path with effort estimate exists. |
| **NOT APPLICABLE** | Control does not apply to Aegis's architecture, data, or current scope. Rationale is stated. |

### Honesty guardrails

Three framing commitments underpin this dossier:

1. **No blanket "immune to X" claims.** Where a control reduces risk but does not eliminate it, the residual risk is stated. In particular, `httpOnly` cookies prevent JavaScript from reading the raw JWT, but a successful XSS could still make authenticated requests. We do **not** claim immunity to XSS; we claim mitigation plus defense-in-depth.

2. **Tenant isolation is logical / query-level today.** Every record carries a `tenant` field and server-side filtering scopes queries. This is a deliberate prototype decision. Database-level isolation (per-tenant databases or row-level security) is **PLANNED**, documented in §5 Tenant Security.

3. **Compliance baselines are design targets, not certifications.** The three tenant modes (Government, Private Sector, SaaS) list compliance frameworks they are **designed to align with** (FedRAMP Moderate, CMMC L2, FIPS 140-3, SOC 2 Type II, ISO 27001, PCI-DSS). No Aegis deployment has been formally audited or certified against any of these as of this document's date. See §8 Compliance for honest readiness scores.

---

## Table of Contents

1. [NIST CSF 2.0 — Executive View](#1-nist-csf-20--executive-view)
2. [Zero Trust Architecture — NIST SP 800-207 Mapping](#2-zero-trust-architecture--nist-sp-800-207-mapping)
3. [Application Security](#3-application-security)
4. [Infrastructure Security](#4-infrastructure-security)
5. [Tenant Security](#5-tenant-security)
6. [Security Operations](#6-security-operations)
7. [Secure Development](#7-secure-development)
8. [Compliance — Honest Readiness](#8-compliance--honest-readiness)
9. [Evidence Catalog](#9-evidence-catalog)
10. [POA&M — Consolidated Remediation Plan](#10-poam--consolidated-remediation-plan)
11. [Revision History](#11-revision-history)

---

## 1. NIST CSF 2.0 — Executive View

NIST Cybersecurity Framework 2.0 (February 2024) organizes cybersecurity outcomes into six functions. This section is the executive index; detailed control implementation lives in §3-§7.

### 1.1 GOVERN (GV)

| Area | Status | Notes |
| --- | --- | --- |
| Organizational cybersecurity strategy | **PARTIAL** | Sole-owner structure; this dossier + `SECURITY.md` + `docs/SECURITY_POLICY_PACK.md` constitute the current policy baseline. A full multi-policy ISMS (AC, IR, CM, SA, CP, RA, CA, AT) remains **PLANNED** — 3 PW. |
| Risk management strategy | **PARTIAL** | §10 POA&M is the current risk register. Formal annual risk assessment process is **PLANNED** — 1 PW. |
| Roles, responsibilities, authorities | **PARTIAL** | Owner responsible for all security decisions. Will formalize on first hire. |
| Policy | **IMPLEMENTED** | Formal Information Security Policy Pack at `docs/SECURITY_POLICY_PACK.md` (v1.0, effective 2026-10-03). Expanded multi-policy ISMS still **PLANNED**. |
| Oversight | **PARTIAL** | Owner is the oversight function. Board / advisory structure to be established post-investment. |
| Cybersecurity supply chain risk | **PARTIAL** | Dependabot, SBOM, secret scanning, and vulnerability SLAs **IMPLEMENTED**; formal vendor risk management process still **PLANNED**. See §7. |

### 1.2 IDENTIFY (ID)

| Area | Status | Notes |
| --- | --- | --- |
| Asset management — platform's own | **IMPLEMENTED** | `requirements.txt` + `package.json` inventory; CycloneDX SBOMs generated in CI (`.github/workflows/security.yml`) for Python and Node. |
| Asset management — customer workloads | **IMPLEMENTED** | Assets module is a first-class product feature. |
| Risk assessment | **PARTIAL** | This dossier is the current artifact. Formalize cadence — 1 PW. |
| Improvement | **IMPLEMENTED** | POA&M (§10) is the active improvement plan. |

### 1.3 PROTECT (PR)

| Area | Status | Notes |
| --- | --- | --- |
| Identity management & authentication | **PARTIAL** | Password + bcrypt + JWT + TOTP MFA **IMPLEMENTED** (MFA required in production); full SSO (SAML/OIDC) endpoints exist but **fail closed** until provider validation is configured; WebAuthn/PIV **PLANNED**. See §3.1. |
| Access control | **IMPLEMENTED** | Server-side RBAC + tenant filtering. See §3.2. |
| Data security | **PARTIAL** | TLS in transit **IMPLEMENTED**; MongoDB TLS client enforcement **IMPLEMENTED**; WiredTiger encryption-at-rest configuration **IMPLEMENTED** (`ops/mongodb/`) — buyer must provision keys. See §4.2 / §4.4. |
| Platform security | **IMPLEMENTED** | Hardened defaults; input validation; secure cookies. |
| Technology infrastructure resilience | **PARTIAL** | Multi-replica MongoDB and BCP are **PLANNED**. See §4.6. |
| Awareness & training | **PLANNED** | On first hire. |

### 1.4 DETECT (DE)

| Area | Status | Notes |
| --- | --- | --- |
| Continuous monitoring — customer workloads | **IMPLEMENTED** | Threat module + live threat tape + severity scoring. |
| Continuous monitoring — platform itself | **PARTIAL** | Audit logs capture every mutation. SIEM forwarding + anomaly alerting on the platform's own logs is **PLANNED** — 1 PW. |
| Adverse event analysis | **IMPLEMENTED** (product) · **PLANNED** (platform-level) |

### 1.5 RESPOND (RS)

| Area | Status | Notes |
| --- | --- | --- |
| Incident response — customer workloads | **IMPLEMENTED** | Incident Response workspace with kill-chain, status workflow, assignee, audit trail. |
| Incident response — platform itself | **IMPLEMENTED** | Platform Incident Response Plan at `docs/INCIDENT_RESPONSE_PLAN.md` (SEV-1..4, NIST 800-61 lifecycle, evidence handling). |
| Incident reporting & communication | **PARTIAL** | Communications section in `docs/INCIDENT_RESPONSE_PLAN.md`. Contractual notification SLAs remain **PLANNED** — 0.5 PW. |
| Analysis & mitigation | **PARTIAL** | Product-side **IMPLEMENTED**; platform IR plan **IMPLEMENTED**; platform playbooks and tooling drills remain ongoing. |

### 1.6 RECOVER (RC)

| Area | Status | Notes |
| --- | --- | --- |
| Recovery planning | **PLANNED** | BCP/DR documentation **PLANNED** — 2 PW. |
| Recovery communications | **PLANNED** | — |
| Backups | **PARTIAL** (inherited) | MongoDB native backup available. Documented restore runbook + first drill is **PLANNED** — 2 PW. |

---

## 2. Zero Trust Architecture — NIST SP 800-207 Mapping

NIST SP 800-207 defines Zero Trust Architecture (ZTA) around seven tenets. Aegis's current architecture is a **ZT-aligned prototype**, not a fully implemented ZTA. The table below is honest about where we are on the spectrum.

### 2.1 ZTA tenet-by-tenet

| # | 800-207 Tenet | Status | Evidence / Gap |
| --- | --- | --- | --- |
| 1 | All data sources and computing services are considered resources | **IMPLEMENTED** | Every API endpoint is treated as a protected resource behind `get_current_user`. No "open" authenticated-area endpoints. |
| 2 | All communication is secured regardless of network location | **PARTIAL** | TLS 1.3 at ingress **IMPLEMENTED**. MongoDB TLS client settings and production WiredTiger encryption config **IMPLEMENTED** (`MONGO_TLS*`, `ops/mongodb/`). SCRAM-SHA-256 and in-cluster mTLS remain buyer/ops configuration. |
| 3 | Access to individual enterprise resources is granted on a per-session basis | **IMPLEMENTED** | JWT access tokens expire after 15 minutes; every request is authenticated independently; `get_current_user` revalidates the user and active session in Mongo on each call. |
| 4 | Access to resources is determined by dynamic policy — including observable state of client identity, application / service, and the requesting asset — and may include other behavioral and environmental attributes | **PARTIAL** | Policy today = role + tenant. **PLANNED**: device posture (certificate on client), time-of-day, geo-velocity, user-behavior scoring. |
| 5 | The enterprise monitors and measures the integrity and security posture of all owned and associated assets | **PARTIAL** | Audit logs capture every mutation. **PLANNED**: platform self-monitoring with SIEM forwarding and anomaly alerting. |
| 6 | All resource authentication and authorization are dynamic and strictly enforced before access is allowed | **PARTIAL** | Authentication = password + TOTP MFA + JWT. Dynamic step-up (re-auth on sensitive actions) is **PLANNED** — see §3.3. |
| 7 | The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture | **PARTIAL** | Platform-side telemetry is minimal today. **PLANNED**: APM + SIEM forwarding. |

### 2.2 ZTA logical components (800-207 §3.2)

| Component | Status | Notes |
| --- | --- | --- |
| Policy Engine (PE) | **PARTIAL** | `require_role()` and `tenant_filter()` are the current policy engine. Attribute-based access control (ABAC) is **PLANNED**. |
| Policy Administrator (PA) | **PARTIAL** | Admin UI (Users module) is the current PA surface. |
| Policy Enforcement Point (PEP) | **IMPLEMENTED** | Every FastAPI endpoint carries `Depends(get_current_user)` or `Depends(require_role(...))`. |
| Continuous Diagnostics & Mitigation (CDM) | **PLANNED** | External CDM feed integration. |
| Industry Compliance | **PARTIAL** | This dossier + `NIST_ALIGNMENT.md`. |
| Threat Intelligence | **PARTIAL** | Threat feed in-product; external TI integration **PLANNED**. |
| Activity Logs | **IMPLEMENTED** | `audit_logs` collection. |
| Data Access Policy | **PARTIAL** | `tenant_filter()` + RBAC. Database-level isolation **PLANNED** (see §5). |
| PKI | **NOT APPLICABLE** today | Smart-card / PIV support is **PLANNED** for government deployments. |
| ID Management | **IMPLEMENTED** | `users` collection with unique email index + UUID `id`. |
| SIEM | **IMPLEMENTED** (as a product) · **PLANNED** (as a platform consumer of its own logs). |

### 2.3 ZTA deployment variants (800-207 §3.1)

Aegis is best described as a **"Device Agent / Gateway"-based ZTA** when deployed in a government or MSSP context: the Aegis backend is itself the PEP for every protected API call. There is no VPN concentrator or SDP controller shipped with the platform; those remain the buyer's responsibility.

---

## 3. Application Security

### 3.1 Authentication

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Password hashing with bcrypt (cost 12, per-password salt) | **IMPLEMENTED** | `server.py` → `hash_password()`, `verify_password()` |
| JWT access tokens (15m, HS256) | **IMPLEMENTED** | `server.py` → `create_access_token()`; `ACCESS_TOKEN_MINUTES = 15` |
| JWT refresh tokens (7d) | **IMPLEMENTED** | `server.py` → `create_refresh_token()` |
| Credentials transmitted over TLS 1.3 only | **IMPLEMENTED** | `secure` cookie flag + ingress TLS |
| Minimum password length | **IMPLEMENTED** | Enforced on register, invite, and password-reset confirm (rejects short passwords; bcrypt 72-byte limit respected). Complexity rules beyond length remain **PLANNED**. |
| Password complexity policy | **PLANNED** | — |
| Password reset with single-use tokens + TTL expiry | **IMPLEMENTED** | `password_reset_tokens` collection with TTL index |
| Account enumeration prevention | **IMPLEMENTED** | Login always returns generic "Invalid email or password" |
| Brute-force lockout (5 attempts → 15 min) | **IMPLEMENTED** | Logic in login path; client IP via `forwarded_client_ip()` using `X-Forwarded-For` only when peer is in `TRUSTED_PROXY_IPS`. Configure trusted proxies in production. |
| Multi-factor authentication (TOTP) | **IMPLEMENTED** | TOTP with ±1 step window; MFA pending cookie; `MFA_REQUIRED=true` enforced in production via `validate_security_settings()`. WebAuthn **PLANNED**. |
| SSO (SAML + OIDC — Okta, Azure AD, Google Workspace) | **PARTIAL** | Routes in `backend/sso.py` with configuration surface; all login/callback/ACS paths **fail closed** (HTTP 503) until signed requests, assertion validation, JWKS, and tenant mapping are configured. Full integration **PLANNED** — 3 PW. |
| PIV / smart card | **PLANNED** | Required for federal civilian agencies. 4 PW |

### 3.2 Authorization / RBAC

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Server-side role enforcement | **IMPLEMENTED** | `server.py` → `require_role(...)` dependency on every privileged endpoint |
| Role model (owner / admin / analyst / viewer) | **IMPLEMENTED** | Enforced in `require_role` and `tenant_filter` |
| Owner protected from deletion | **IMPLEMENTED** | `DELETE /api/users/{id}` rejects any user with `role=owner` |
| Least-privilege default — non-owner roles hard-scoped to own tenant | **IMPLEMENTED** | `tenant_filter()`: only `owner` may cross tenants; `admin` / `analyst` / `viewer` are hard-scoped to `user.tenant` |
| Separation of duties — dual approval on high-risk actions | **PLANNED** | For FedRAMP, destructive actions should require second approver. 2 PW |
| Re-authentication on high-risk actions | **PLANNED** | Prompt for password on user delete / role change. 0.5 PW |
| Attribute-based access control (ABAC) | **PLANNED** | — |

### 3.3 Session Management

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| JWT in `httpOnly`, `secure`, SameSite cookies | **IMPLEMENTED** | `set_auth_cookies()`: `secure` + `SameSite=strict` in production; `lax` in development |
| JavaScript cannot read raw token | **IMPLEMENTED** | `httpOnly` flag; verified in browser dev-tools |
| Short-lived access tokens (15m) + refresh (7d) | **IMPLEMENTED** | Server-side session store (`auth_sessions`) enables immediate revocation |
| Session revalidation on each request | **IMPLEMENTED** | `get_current_user` re-fetches user from Mongo and checks active session on every call |
| Logout clears both cookies | **IMPLEMENTED** | `POST /api/auth/logout` + audit entry |
| Session termination on logout / password change | **IMPLEMENTED** | Server-side `auth_sessions` with `revoke_session` / `revoke_user_sessions`; access tokens checked against active session on every request. |
| Idle timeout (15 min for FedRAMP) | **PLANNED** | 1 PW |
| JWT signing key rotation (two-active-keys pattern) | **PLANNED** | 2 PW |
| **Explicit non-claim** on XSS | **DOCUMENTED** | `httpOnly` prevents JavaScript from reading the token. A successful XSS could still make authenticated requests via the browser-attached cookie. XSS defense-in-depth (CSP, output encoding, no `dangerouslySetInnerHTML`, Pydantic validation) is applied in addition — not instead of. |

### 3.4 API Security

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| All backend routes prefixed `/api` | **IMPLEMENTED** | `api_router = APIRouter(prefix="/api")` |
| Pydantic v2 validation on all request bodies | **IMPLEMENTED** | `RegisterRequest`, `LoginRequest`, `IncidentUpdate`, `UserInvite` models |
| Enumerated `Literal` types for status / severity / tenant | **IMPLEMENTED** | Prevents injection of unexpected values |
| Structured FastAPI exception responses — no stack-trace leakage | **IMPLEMENTED** | — |
| Rate limiting on authenticated endpoints | **PLANNED** | Add `slowapi` with per-user per-endpoint quotas. 1 PW |
| OpenAPI spec auto-generated | **IMPLEMENTED** | FastAPI `/docs` + `/openapi.json` |
| API versioning strategy | **PARTIAL** | Current API is implicitly v1; formal versioning (`/api/v1/...`) **PLANNED** before public API publication |
| Idempotency keys on mutating endpoints | **PLANNED** | For external integrations |

### 3.5 Input Validation

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Email format via `EmailStr` | **IMPLEMENTED** | `pydantic.EmailStr` on register / login / invite |
| Password minimum length (validated on write paths) | **IMPLEMENTED** | Rejects short passwords on register/invite/reset; see §3.1 |
| Role / tenant / status via `Literal` types | **IMPLEMENTED** | Rejects any non-whitelisted value |
| MongoDB queries parameterized (motor driver) | **IMPLEMENTED** | No string concatenation anywhere in `server.py` |
| React auto-escaping | **IMPLEMENTED** | All UI text rendered as React children |
| No `dangerouslySetInnerHTML` in codebase | **IMPLEMENTED** | Verified by grep; zero occurrences |

### 3.6 CORS, CSRF, and related

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| CORS `allow_origins` whitelisted (not `*`) with credentials | **IMPLEMENTED** | `allow_origins=[FRONTEND_URL, "http://localhost:3000"]` |
| CORS `allow_credentials=true` | **IMPLEMENTED** | Required for cookie-based auth |
| CSRF protection via SameSite + Origin/Referer check | **IMPLEMENTED** | `csrf_origin_guard` middleware rejects state-changing requests that carry auth cookies unless Origin/Referer matches configured frontend/CORS origins (403). SameSite=strict in production. |
| `X-Content-Type-Options: nosniff` header | **IMPLEMENTED** | `SecurityHeadersMiddleware` + `ops/ingress/security-headers.yaml` |
| `X-Frame-Options: DENY` | **IMPLEMENTED** | Same |
| `Referrer-Policy: strict-origin-when-cross-origin` | **IMPLEMENTED** | Same |
| `Content-Security-Policy` (strict) | **IMPLEMENTED** | default-src self; frame-ancestors none; object-src none; upgrade-insecure-requests |
| `Strict-Transport-Security` (HSTS) | **IMPLEMENTED** | max-age=63072000; includeSubDomains; preload |

### 3.7 Secrets Management

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| No secrets in source code | **IMPLEMENTED** | Verified by grep; all secrets in environment |
| Secrets loaded from environment variables | **IMPLEMENTED** | `load_dotenv()` + `os.environ[...]` |
| Secrets not logged | **IMPLEMENTED** | `password_hash` popped from user dict before any serialization |
| `.env` excluded from version control | **IMPLEMENTED** | Standard template |
| Managed secrets store (Vault, AWS Secrets Manager, GCP Secret Manager) | **PLANNED** | Required for production deployment. Buyer-infra. Document in deployment guide. |
| Secret rotation runbook | **PLANNED** | 0.5 PW |

---

## 4. Infrastructure Security

### 4.1 Network Architecture

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Backend bound to `0.0.0.0:8001`, exposed only through K8s ingress | **IMPLEMENTED** | Supervisor config |
| TLS termination at ingress | **IMPLEMENTED** (inherited) | Kubernetes ingress |
| Public attack surface limited to `/`, `/api/*`, and static assets | **IMPLEMENTED** | FastAPI route tree |
| Internal network segmentation | **PARTIAL** (inherited) | Buyer configures K8s NetworkPolicies |
| Egress controls | **PLANNED** (inherited) | Default K8s allows all egress; buyer should restrict |
| WAF at ingress (ModSecurity CRS / AWS WAF / Cloudflare) | **PLANNED** (inherited) | Documented in deployment hardening checklist |
| DDoS protection | **PLANNED** (inherited) | Cloud-provider-level |

### 4.2 MongoDB Security

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| MongoDB connection via env var (`MONGO_URL`) | **IMPLEMENTED** | Environment configuration |
| Database name via env var (`DB_NAME`) | **IMPLEMENTED** | Not hardcoded |
| Unique index on `users.email` | **IMPLEMENTED** | `on_startup()` in `server.py` |
| TTL index on `password_reset_tokens.expires_at` | **IMPLEMENTED** | — |
| Compound index on `(tenant, timestamp)` for all time-series collections | **IMPLEMENTED** | threats, incidents, vulnerabilities, assets, audit_logs |
| TLS between backend and MongoDB | **IMPLEMENTED** | `MONGO_TLS` (default true); CA/cert key files supported; production rejects TLS off or invalid-cert allowance |
| MongoDB SCRAM-SHA-256 authentication | **PLANNED** (production) | Buyer configures |
| MongoDB application user scoped to the single database (no admin) | **PLANNED** (production) | Buyer configures |
| MongoDB audit log enabled, shipped to tamper-evident store | **PLANNED** (production) | Buyer configures |
| WiredTiger encryption at rest | **PARTIAL** | Production configuration and runbook at `ops/mongodb/` **IMPLEMENTED**. Buyer must provision encryption key via secret manager and start mongod with the supplied config — key material never in Git. |
| Field-level encryption for PII fields | **PLANNED** | Not currently required by current data model, but evaluate for government deployments |

### 4.3 Container / Kubernetes Hardening

Aegis today runs under supervisord in a container. The hardening below describes the recommended production deployment, which is **PLANNED** for a full Kubernetes manifest to be shipped with the first commercial release.

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Container runs as non-root | **PLANNED** | — |
| Read-only root filesystem | **PLANNED** | — |
| Dropped Linux capabilities (`drop: ["ALL"]`) | **PLANNED** | — |
| `securityContext` with `allowPrivilegeEscalation: false` | **PLANNED** | — |
| Pod `seccompProfile: RuntimeDefault` | **PLANNED** | — |
| Resource requests + limits set | **PLANNED** | — |
| NetworkPolicies restricting pod-to-pod | **PLANNED** | — |
| Pod Security Standards (restricted profile) | **PLANNED** | — |
| Image signed + verified (cosign / sigstore) | **PLANNED** | — |
| Filesystem / dependency scanning (Trivy) in CI | **IMPLEMENTED** | `.github/workflows/security.yml` — Trivy fs scan, fails on CRITICAL/HIGH |
| Secrets injected via mounted secret (not env literal) | **PLANNED** | — |

### 4.4 Transport Layer Security

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| TLS 1.3 at ingress | **IMPLEMENTED** (inherited) | Kubernetes ingress |
| HTTP → HTTPS redirect | **IMPLEMENTED** (inherited) | Ingress |
| Modern cipher suites only | **IMPLEMENTED** (inherited) | — |
| HSTS with preload | **IMPLEMENTED** | App middleware + ingress annotations |
| mTLS backend ↔ MongoDB | **PLANNED** | — |
| mTLS between services in-cluster | **PLANNED** | Service mesh (Istio / Linkerd) for FedRAMP High |
| Certificate automation (cert-manager / Let's Encrypt) | **IMPLEMENTED** (inherited) | — |
| FIPS 140-3 validated crypto modules | **PLANNED** | 1 PW for FIPS Python build + ingress config |

### 4.5 Logging & Monitoring (platform-level)

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Structured logging via Python `logging` | **IMPLEMENTED** | — |
| Audit trail written to Mongo on every mutation | **IMPLEMENTED** | `write_audit()` |
| Alerting on log anomalies (brute-force spikes, 5xx surges) | **PLANNED** | 1 PW |
| SIEM forwarding of platform logs | **PLANNED** | 1 PW |

### 4.6 Resilience & Recovery

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| MongoDB native backup available | **PARTIAL** (inherited) | — |
| Documented restore runbook | **PLANNED** | 1 PW |
| First restoration drill performed | **PLANNED** | 1 PW |
| Business Continuity Plan (BCP) | **PLANNED** | 2 PW |
| Disaster Recovery Plan (DRP) | **PLANNED** | 2 PW |
| Immutable WORM copy of audit logs (S3 Object Lock) | **PLANNED** | 0.5 PW to document |

---

## 5. Tenant Security

### 5.1 Tenant Boundaries — Current State

**Status**: **PARTIAL — Logical / query-level today.**

Every multi-tenant collection carries a `tenant` field (`government | private | saas`). Server-side `tenant_filter(user, requested)` function in `server.py` applies the correct filter to every query:

- Only `owner` can filter by any tenant (including `all` for cross-tenant visibility)
- `admin`, `analyst`, and `viewer` are **hard-scoped** to their own `user.tenant` — any `?tenant=` override is ignored
- The filter is applied at the FastAPI endpoint layer, not at the database or network layer

### 5.2 Tenant Boundary Controls

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Every tenant-scoped record carries `tenant` field | **IMPLEMENTED** | Models: Threat, Vulnerability, Incident, Asset, Compliance, AuditLog, User |
| Server-side tenant filter on all queries | **IMPLEMENTED** | `tenant_filter()` in `server.py` |
| Non-privileged users cannot escape their own tenant | **IMPLEMENTED** | Verified by backend test suite |
| Owner cross-tenant access is explicit (via `?tenant=` parameter); admin is hard-scoped | **IMPLEMENTED** | Matches `tenant_filter()` in `server.py` and security tests |
| Tenant-isolation enforced at the database layer | **PLANNED** | Database-level isolation (per-tenant database or MongoDB row-level security) is the roadmap item below |

### 5.3 Privileged Access

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Owner cannot be deleted | **IMPLEMENTED** | `DELETE /api/users/{id}` rejects `role=owner` |
| Owner / admin actions are audited (actor, action, resource, IP, tenant, timestamp) | **IMPLEMENTED** | `write_audit()` on every mutation |
| Dual approval on destructive actions | **PLANNED** | 2 PW for workflow + UI |
| Owner / admin credential separation | **PLANNED** | — |
| Session recording for privileged users | **PLANNED** | Only required for FedRAMP High |

### 5.4 Cross-Tenant Access Controls

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Only owner can cross tenants | **IMPLEMENTED** | Admin cannot escape own tenant |
| Cross-tenant access is audited | **IMPLEMENTED** | Audit log includes resolved tenant per query |
| Cross-tenant metrics aggregation is explicit (requires `?tenant=all`) | **IMPLEMENTED** | — |
| Separation of tenant encryption keys | **PLANNED** | Per-tenant data encryption keys for high-side deployments |

### 5.5 Database-Level Isolation Roadmap

The current logical isolation is **appropriate for a prototype and early SaaS tenants** but is **not sufficient** for high-sensitivity government deployments. The roadmap:

| Phase | Approach | Effort | When |
| --- | --- | --- | --- |
| **Current** | Logical isolation — single database, `tenant` field per record, server-side filter | ✅ Shipping | — |
| **Phase 1** | Schema-level isolation — one MongoDB collection prefix per tenant (`gov_threats`, `priv_threats`, `saas_threats`) | 1 PW | Pre-first-government-deal |
| **Phase 2** | Database-level isolation — one Mongo database per tenant | 2 PW | At CMMC L2 assessment |
| **Phase 3** | Cluster-level isolation — one Mongo replica set per tenant, optionally in separate K8s namespaces | 3 PW | At FedRAMP Moderate ATO |
| **Phase 4** (optional) | Air-gapped deployments — fully separate installations per tenant | 1 PW integration + customer infrastructure | FedRAMP High / classified |

The current `tenant_filter()` abstraction is intentionally shaped so a database-level isolation migration is a drop-in replacement — the API contract to the frontend does not change.

---

## 6. Security Operations

### 6.1 Threat Detection (Product)

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Threat feed with severity, geo, confidence, source IP | **IMPLEMENTED** | Threats module |
| Severity distribution + 7-day trend | **IMPLEMENTED** | Overview module |
| Live threat tape (polled real-time simulator) | **IMPLEMENTED** | `/api/threats/live` |
| MITRE ATT&CK technique mapping | **PLANNED** | 2 PW |
| Behavioral anomaly scoring with ML | **PLANNED** | Research + 4 PW |

### 6.2 Vulnerability Management (Product)

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| CVE catalog with CVSS 3.1 score | **IMPLEMENTED** | Vulnerabilities module |
| Affected asset mapping | **IMPLEMENTED** | — |
| Patch tracking | **IMPLEMENTED** | `POST /api/vulnerabilities/{id}/patch` |
| Automatic CVE enrichment from NVD / OSV | **PLANNED** | 1 PW |
| Exploit prediction scoring (EPSS) | **PLANNED** | — |

### 6.3 Incident Response (Product)

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Incident workspace with kill-chain, status, assignee | **IMPLEMENTED** | Incidents module |
| 4-step status workflow | **IMPLEMENTED** | — |
| Platform IR plan (for Aegis itself) | **IMPLEMENTED** | `docs/INCIDENT_RESPONSE_PLAN.md` |

### 6.4 Audit

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Append-oriented audit trail | **IMPLEMENTED** | `audit_logs` |
| Actor, IP, resource, tenant, timestamp on mutations | **IMPLEMENTED** | `write_audit()` |
| Audit retention policy (90 days online + 1 year archive minimum) | **PLANNED** | 0.5 PW to document |
| Hash-chained / WORM audit storage | **PLANNED** | See POA&M |

---

## 7. Secure Development

### 7.1 Dependency Management

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Pinned dependencies where practical | **PARTIAL** | — |
| License compliance scanning (FOSSA / Snyk Open Source) | **PLANNED** | 0.5 PW |

### 7.2 SBOM

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| SBOM produced at build time | **IMPLEMENTED** | CycloneDX JSON for Python (`cyclonedx-py`) and Node (`@cyclonedx/cyclonedx-npm`) in security workflow; artifacts uploaded |
| SBOM published alongside releases | **PARTIAL** | Generated as CI artifacts; formal release attachment process **PLANNED** |
| SBOM shared with customers on request | **IMPLEMENTED** | Available under NDA / on request from CI artifacts |

### 7.3 Vulnerability Scanning (of the Aegis platform itself)

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Dependency CVE scanning (Dependabot / pip-audit / npm audit) | **IMPLEMENTED** | Weekly Dependabot; pip-audit + npm audit (high+) in CI |
| Filesystem scanning (Trivy) | **IMPLEMENTED** | Trivy action fails CI on CRITICAL/HIGH |
| Secret scanning in commits (gitleaks) | **IMPLEMENTED** | `gitleaks/gitleaks-action@v2` on push/PR/schedule |
| Documented patch SLA (24h critical / 7d high / 30d medium / 90d low) | **IMPLEMENTED** | `docs/SECURITY_POLICY_PACK.md` vulnerability management section |

### 7.4 SAST / DAST

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Static analysis (bandit for Python, ESLint-security for JS) | **PLANNED** | 0.5 PW to wire |
| Semgrep / CodeQL rules | **PLANNED** | 0.5 PW |
| Dynamic application security testing (OWASP ZAP) | **PLANNED** | 1 PW |
| Automated DAST in CI nightly | **PLANNED** | — |

### 7.5 Penetration Testing

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Third-party pen test by a Tier 1 firm (NCC, Bishop Fox, Trail of Bits) | **PLANNED** | External engagement. $25K-$80K + 2 weeks |
| Internal red-team exercises | **PLANNED** | After first external pen test |
| Bug bounty program | **PLANNED** | Launch after SOC 2 Type II |

### 7.6 CI/CD Security

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Automated backend test suite (pytest) | **IMPLEMENTED** | Backend security tests in `tests/test_backend_security.py` cover headers, CSRF, MFA TOTP, tenant filter, production fail-closed, and proxy IP attribution |
| Automated frontend test suite (Playwright) | **IMPLEMENTED** | **100% of 30+ core flows passing** at v2.1.0 — landing, login, all 8 dashboard modules, patch, incident workflow, invite, tenant switcher, logout |
| CI pipeline (GitHub Actions) | **IMPLEMENTED** | `.github/workflows/ci.yml` and `security.yml`; `.gitlab-ci.yml` also present |
| Required status checks on PRs | **PARTIAL** | Workflows run on PR; branch protection rules are buyer/ops configuration |
| Signed commits (`git commit -S`) | **PLANNED** | — |
| Signed container images (cosign) | **PLANNED** | — |
| Protected main branch | **PLANNED** | Buyer/ops GitHub settings |
| Deployment approval gates | **PLANNED** | — |

### 7.7 Release & Change Management

| Control | Status | Evidence / Gap |
| --- | --- | --- |
| Versioned releases (semver) | **PARTIAL** | Platform at v2.1.0. Document release cadence. |
| Changelog maintained | **PARTIAL** | Dossier revision history (§11); platform changelog **PLANNED** |
| Backwards-compatibility policy | **PLANNED** | For public API |
| Deprecation policy | **PLANNED** | For public API |
| Feature flags | **PLANNED** | — |
| Blue/green or canary deployments | **PLANNED** (inherited) | Buyer K8s configuration |
| Rollback runbook | **PLANNED** | 0.5 PW |

---

## 8. Compliance — Honest Readiness

**Critical framing**: The sections below describe which frameworks Aegis is **designed to align with**. No Aegis deployment has yet been **formally audited or certified** against any of these frameworks as of this document's date. All timelines and cost estimates reference publicly available third-party pricing (Vanta, Drata, Secureframe, and typical 3PAO ranges).

### 8.1 NIST Cybersecurity Framework 2.0

- **Alignment status**: PARTIAL (foundation in place; see §1 for function-by-function status)
- **Certification needed?** No — CSF 2.0 is a framework, not a certification scheme
- **Use**: internal governance baseline for Aegis's own ISMS

### 8.2 NIST SP 800-53 rev 5

- **Alignment status**: Control coverage improved by the 2026-10 hardening branch (MFA, headers, CSRF, Mongo TLS, IR plan, policy pack, CI scanning). See `NIST_ALIGNMENT.md` for the detailed appendix — that appendix should be refreshed in a follow-on pass.
- **Certification needed?** Not directly — but is the control catalog underlying FedRAMP and FISMA

### 8.3 ISO 27001:2022

- **Current status**: PARTIAL
- **Direct controls met today**: A.5.17 (authentication), A.5.18 (access rights), A.8.5 (secure authentication), A.8.15 (logging), A.8.24 (cryptography), plus policy pack and IR plan artifacts
- **Main gaps**: Full multi-policy ISMS, supplier relationships, human resources security
- **Target certification**: ISO 27001:2022 Stage 1 + Stage 2
- **Timeline estimate**: 6-9 months
- **Cost estimate**: $35K-$70K audit + ~$500/mo platform (Vanta/Drata/Secureframe)
- **Status**: PLANNED

### 8.4 SOC 2 Type II

- **Current status**: PARTIAL
- **Direct Common Criteria met today**: CC5 (control activities), CC6.1 (logical access), CC6.2 (credentials), CC6.3 (RBAC), CC6.6 (encryption in transit), CC6.7 (data isolation at logical level), plus documented policy pack and IR plan supporting CC1/CC7
- **Main gaps**: Continuous monitoring of the platform itself, formal risk assessment cadence, BCP/DR drills
- **Status**: PLANNED

### 8.5 FedRAMP Moderate / CMMC Level 2

- **Current status**: PARTIAL — design target, not authorized
- **Recent progress**: TOTP MFA (production-required), MongoDB TLS enforcement, WiredTiger config docs, security headers, CSRF origin guard, IR plan, policy pack
- **Remaining blockers**: Buyer-provisioned encryption keys + restore drill, complete SSO for enterprise IdPs, FIPS modules for High, database-level tenant isolation for high-side, formal ConMon
- **Certification**: ❌ not yet

### 8.6 Summary table

| Framework | Readiness | Certified? | Typical timeline | Typical cost |
| --- | --- | --- | --- | --- |
| NIST CSF 2.0 | PARTIAL | n/a (framework) | ongoing | internal |
| ISO 27001:2022 | PARTIAL | ❌ not yet | 6-9 months | $35K-$70K |
| SOC 2 Type II | PARTIAL | ❌ not yet | 6-12 months | $30K-$80K |
| FedRAMP Moderate | PARTIAL | ❌ not yet | 12-18 months | $100K-$300K |
| CMMC Level 2 | PARTIAL | ❌ not yet | 6-12 months | $100K-$300K |
| HIPAA | PARTIAL | ❌ not yet | 60-90 days | $10K-$25K |
| PCI-DSS 4.0 | NOT APPLICABLE | n/a | post-Stripe | — |

---

## 9. Evidence Catalog

For every `IMPLEMENTED` claim in this dossier, the following direct evidence is available for an assessor's inspection:

| Evidence class | Location |
| --- | --- |
| Backend source (all auth, RBAC, audit, tenant filter, API) | `backend/server.py` |
| Password hashing | `backend/server.py` → `hash_password()`, `verify_password()` |
| JWT token issuance | `backend/server.py` → `create_access_token()`, `create_refresh_token()` |
| Session validation | `backend/server.py` → `get_current_user()`, `auth_sessions` |
| RBAC decorator | `backend/server.py` → `require_role()` |
| Tenant filter | `backend/server.py` → `tenant_filter()` |
| Audit log writer | `backend/server.py` → `write_audit()` |
| Brute-force lockout | `backend/server.py` → login endpoint + `login_attempts` |
| MFA (TOTP) | `backend/server.py` → `_totp`, `_verify_totp`, MFA pending flow |
| CSRF guard | `backend/server.py` → `csrf_origin_guard` |
| Production fail-closed validation | `backend/server.py` → `validate_security_settings()` |
| Security headers middleware | `backend/security_hardening.py` |
| SSO fail-closed module | `backend/sso.py` |
| MongoDB TLS + encryption runbook | `ops/mongodb/` |
| Ingress security headers | `ops/ingress/security-headers.yaml` |
| Security CI workflow | `.github/workflows/security.yml` |
| Dependabot config | `.github/dependabot.yml` |
| Written security policy (summary) | `SECURITY.md` |
| Information Security Policy Pack | `docs/SECURITY_POLICY_PACK.md` |
| Platform Incident Response Plan | `docs/INCIDENT_RESPONSE_PLAN.md` |
| Security hardening release notes | `SECURITY_HARDENING.md` |
| Commercial license | `LICENSE.md` |
| NIST 800-53 detailed appendix | `NIST_ALIGNMENT.md` |
| This dossier | `SECURITY_DOSSIER.md` |
| Test suite — backend security | `tests/test_backend_security.py` (headers, CSRF, MFA, tenant filter, production fail-closed, proxy IP) |
| Test suite — frontend | Playwright, 100% of 30+ core flows passing at v2.1.0 |

Full source access is granted under NDA. A guided walkthrough with the owner is included in any serious engagement.

---

## 10. POA&M — Consolidated Remediation Plan

This POA&M is the **single authoritative** remediation roadmap. Items are ordered first by **framework blocker severity**, then by **effort / impact ratio**.

| # | Gap | Primary ref | Severity | Effort (PW) | Dependencies |
| --- | --- | --- | ---: | ---: | --- |
| 1 | WebAuthn / hardware-bound MFA (beyond TOTP) | §3.1, FedRAMP IA-2(1)(2), CMMC AC.L2-3.5.3 | High | 1.5 | TOTP already shipping |
| 2 | Buyer-provisioned WiredTiger encryption key + verified restore drill | §4.2, FedRAMP SC-28, CMMC MP.L2-3.8.9 | **Blocker** (ops) | 0.5 | `ops/mongodb/` config ready |
| 3 | Expanded multi-policy ISMS (beyond current policy pack) | §1 GOVERN, SOC 2 CC1 | High | 3 | Policy pack v1.0 done |
| 4 | Business Continuity + Disaster Recovery Plan + first drill | §1 RECOVER, §4.6, SOC 2 CC7 | High | 3 | #3 |
| 5 | Complete SSO (SAML + OIDC) with assertion/JWKS validation | §3.1, enterprise requirement | High | 3 | Fail-closed routes exist |
| 6 | Rate limiting on authenticated endpoints | §3.4, FedRAMP SC-5 | High | 1 | — |
| 7 | System Use Notification banner on login | FedRAMP AC-8 | Medium | 0.25 | — |
| 8 | Idle timeout (15 min for FedRAMP) | §3.3, FedRAMP AC-11 | Medium | 1 | — |
| 9 | JWT key rotation (two-active-keys pattern) | §3.3, FedRAMP SC-12 | Medium | 2 | — |
| 10 | FIPS 140-3 validated crypto modules | §4.4, FedRAMP IA-7/SC-13 | Medium | 1 | — |
| 11 | Audit log forwarding to SIEM / WORM | §6.4, FedRAMP AU-6/-9 | Medium | 1 | Buyer SIEM |
| 12 | Hash-chained audit logs (SHA-256 chain) | §6.4, FedRAMP AU-9 | Medium | 2 | — |
| 13 | Re-authentication for high-risk actions | §3.2, FedRAMP IA-11 | Medium | 0.5 | — |
| 14 | Password complexity policy (beyond minimum length) | §3.1, FedRAMP IA-5(1) | Low | 0.25 | Min length enforced |
| 15 | Formal SBOM attachment to release artifacts | §7.2, FedRAMP CM-8/SR-4 | Low | 0.25 | CI SBOM generation done |
| 16 | Vendor Risk Management process | §1 GOVERN, FedRAMP SA-9, SOC 2 CC9 | Low | 1 | — |
| 17 | ConMon dashboard (internal) | §4.5, FedRAMP CA-7, SOC 2 CC4 | Medium | 2 | #11 |
| 18 | Awareness training program | FedRAMP AT-2 | Low | 0.5 | — |
| 19 | PIV / smart-card authentication | §3.1 | Low (High for FedRAMP High) | 4 | — |
| 20 | Tenant isolation Phase 1 (schema-level collection prefix) | §5.5 | Medium | 1 | — |
| 21 | Tenant isolation Phase 2 (database-level) | §5.5 | Medium (High for government) | 2 | #20 |
| 22 | Container hardening (non-root, read-only FS, dropped caps, PSS restricted) | §4.3 | Medium | 1 | — |
| 23 | Branch protection + required status checks | §7.6 | Medium | 0.25 | CI workflows exist |
| 24 | Third-party penetration test | §7.5, FedRAMP CA-8 | High | external $25K-$80K | Phase 1 hardening complete |
| 25 | Dual approval on destructive actions | §3.2, FedRAMP separation of duties | Medium | 2 | — |

### Closed since v1.0 (2026-10 hardening branch)

| Closed item | Evidence |
| --- | --- |
| TOTP multi-factor authentication + production MFA fail-closed | `server.py` MFA helpers; `MFA_REQUIRED` / `MFA_MASTER_SECRET` validation |
| Origin/Referer CSRF guard on cookie-authenticated mutations | `csrf_origin_guard` middleware + tests |
| Security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, COOP/CORP) | `backend/security_hardening.py`, `ops/ingress/security-headers.yaml` |
| Proxy-aware brute-force IP attribution | `forwarded_client_ip()` + `TRUSTED_PROXY_IPS` |
| Platform Incident Response Plan | `docs/INCIDENT_RESPONSE_PLAN.md` |
| Information Security Policy Pack | `docs/SECURITY_POLICY_PACK.md` |
| MongoDB TLS client enforcement + WiredTiger config docs | `MONGO_TLS*` settings; `ops/mongodb/` |
| Dependabot, pip-audit, npm audit, Trivy, Gitleaks, CycloneDX SBOM | `.github/workflows/security.yml`, `.github/dependabot.yml` |
| Server-side session revocation | `auth_sessions` collection; revoke on logout |
| Consolidated SECURITY.md entry point | Root `SECURITY.md` |

**Remaining internal engineering effort (open items above, excluding external pen test)**: approximately **28 person-weeks ≈ 7 person-months** of dedicated security engineering.

**Cash cost of in-house remediation** (one dedicated senior security engineer at ~$180K fully loaded): approximately **$100K-$130K**, plus the external pen test (~$50K average) and the SOC 2 / FedRAMP audit fees (quoted in §8).

---

## 11. Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.1 | 2026-10-04 | Synchronized control statuses with hardening branch: TOTP MFA, CSRF Origin guard, security headers, proxy-aware lockout IP, MongoDB TLS + WiredTiger config, policy pack, platform IR plan, CI security scanning (Gitleaks/Trivy/pip-audit/SBOM), server-side session revocation. Corrected JWT lifetime to 15m, tenant cross-scope to owner-only, and SameSite cookie policy. Closed completed POA&M items; refreshed evidence catalog. Companion `SECURITY.md` published as entry point. | William Brown / Grok |
| 1.0 | 2026-02 | Initial release. Structured per NIST CSF 2.0 + ZTA (NIST SP 800-207) + six operational domains + honest compliance posture. Introduced strict IMPLEMENTED / PARTIAL / PLANNED / NOT APPLICABLE taxonomy. Explicitly removed any "immune to XSS" phrasing; explicitly framed tenant isolation as logical/query-level with database-level isolation as a documented roadmap; explicitly separated certification claims from design-baseline alignment. | William Brown |

---

## Contact

For any question on a control assessment, to request a diligence walk-through, to arrange a 3PAO/C3PAO engagement, or to request source-code access under NDA:

**William Brown** · Owner & Operator — Aegis SOC
Email: `william.brown@aegis-soc.io`

© 2026 Aegis SOC · All rights reserved · Transferable commercial license available
