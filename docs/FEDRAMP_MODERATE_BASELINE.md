# Aegis SOC — FedRAMP Moderate Baseline Mapping

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Aligned to**: `SECURITY_DOSSIER.md` v1.1 · `NIST_ALIGNMENT.md` v1.0 (2026-10-04)  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> **This is not a System Security Plan, not a FedRAMP package, and not an Authorization to Operate (ATO).**  
> It maps Aegis SOC’s *current engineering posture* against the **FedRAMP Moderate** control baseline (NIST SP 800-53 Revision 5, as selected for Moderate impact) so a buyer CISO, 3PAO, or agency assessor can see readiness and residual gaps honestly.

---

## 1. Scope and framing

### 1.1 What this baseline covers

| Item | Statement |
| --- | --- |
| Target baseline | **FedRAMP Moderate** (cloud SaaS / multi-tenant SOC platform) |
| System type (intended) | Software-as-a-Service (SaaS) application; agency or prime would authorize *their* deployment of Aegis |
| Impact level | Confidentiality **Moderate** · Integrity **Moderate** · Availability **Moderate** (design target) |
| Inheritance model | **Customer / CSP shared**: physical (PE), facility, underlying IaaS/PaaS boundary, and agency-specific continuous monitoring are **inherited or customer-responsible** unless Aegis operates the hosting stack under contract |
| Status taxonomy | Same as dossier: **IMPLEMENTED** · **PARTIAL** · **PLANNED** · **NOT APPLICABLE** / **INHERITED** |

### 1.2 Honest readiness

| Question | Answer |
| --- | --- |
| Is Aegis FedRAMP authorized? | **No.** |
| Is this an SSP or SAR? | **No.** |
| Can this document support pre-ATO diligence? | **Yes** — as an engineering control map under NDA. |
| Primary remaining blockers | Buyer encryption-key ops + restore drill; complete enterprise SSO; formal BCP/DR + ConMon; database-level tenant isolation for high-side; independent assessment (3PAO) |

Detailed POA&M: `SECURITY_DOSSIER.md` §10.  
Control-by-control 800-53 appendix: `NIST_ALIGNMENT.md`.

---

## 2. Authorization boundary (conceptual)

```
┌─────────────────────────────────────────────────────────────┐
│  Agency / Customer responsibility                           │
│  · Agency ATO process · continuous monitoring sponsorship   │
│  · Identity proofing for agency users · PIV where required  │
│  · Network path to Aegis · data classification decisions      │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS
┌────────────────────────────▼────────────────────────────────┐
│  Aegis authorization boundary (product)                     │
│  · React console · FastAPI /api · JWT/MFA sessions          │
│  · Tenant-scoped data plane · audit trail · product SIEM UX │
│  · Application security controls listed below               │
└────────────────────────────┬────────────────────────────────┘
                             │ TLS (required in production)
┌────────────────────────────▼────────────────────────────────┐
│  Data store (MongoDB)                                       │
│  · TLS client config · WiredTiger encryption-at-rest config │
│  · Keys & certificates provisioned outside Git (buyer/ops)  │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  Hosting / CSP (INHERITED unless Aegis is the CSP)          │
│  · PE controls · hypervisor · region · DDoS · facility     │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. FedRAMP Moderate — family readiness summary

FedRAMP Moderate selects a large subset of 800-53 Rev 5 controls and enhancements. The table below summarizes **Aegis-owned** posture by family for a SaaS software boundary. Counts are approximate and scoped to controls that typically apply to an application layer (not full CSP PE/CM inventories).

| Family | Focus | Overall | Notes |
| --- | --- | --- | --- |
| **AC** Access Control | RBAC, tenancy, lockout, sessions | **Strong / PARTIAL** | RBAC + tenant hard-scope + lockout + session revoke **IMPLEMENTED**; AC-8 banner & idle timeout **PLANNED** |
| **AU** Audit | Logging, protection, retention | **PARTIAL** | Event generation **IMPLEMENTED**; SIEM forward, WORM, formal retention **PLANNED** |
| **AT** Awareness & Training | Personnel training | **PLANNED** | Sole-owner; formal AT on first hire |
| **CM** Configuration Management | Baseline, inventory, change | **PARTIAL** | SBOM + CI **IMPLEMENTED**; signed images, full CM plan **PLANNED** |
| **CP** Contingency Planning | Backup, DR, testing | **PARTIAL / weak** | Mongo backup capability; BCP/DR docs + drill **PLANNED** (blocker for ops readiness) |
| **IA** Identification & Auth | MFA, authenticators, PIV | **Strong / PARTIAL** | TOTP MFA prod-required **IMPLEMENTED**; PIV/WebAuthn & full SSO **PLANNED** |
| **IR** Incident Response | Plan, handling, reporting | **Strong / PARTIAL** | Platform IR plan **IMPLEMENTED**; tabletop & contractual SLAs **PLANNED** |
| **MA** Maintenance | Controlled maintenance | **PARTIAL** | Remote admin via authenticated console only |
| **MP** Media Protection | Storage, sanitization | **PARTIAL** | Encryption config; physical media N/A |
| **PE** Physical | Facility | **INHERITED** | Buyer / CSP |
| **PL** Planning | Policies, SSP | **PARTIAL** | Policy pack + dossier; formal SSP for ATO **PLANNED** |
| **PS** Personnel | Screening, termination | **PLANNED / PARTIAL** | Process maturity on first hire |
| **RA** Risk Assessment | Vuln scanning, risk | **Strong / PARTIAL** | CI scanning **IMPLEMENTED**; formal annual RA cadence **PLANNED** |
| **CA** Assessment & Auth | POA&M, ConMon, pen test | **PARTIAL** | POA&M **IMPLEMENTED**; ConMon dashboard & 3PAO **PLANNED** |
| **SA** System Acquisition | SDLC, testing | **PARTIAL** | Security tests + CI **IMPLEMENTED**; formal SDLC policy **PLANNED** |
| **SC** System & Comm Protection | TLS, crypto, boundary | **Strong / PARTIAL** | TLS, headers, CSRF **IMPLEMENTED**; FIPS modules & rate limit **PLANNED**; at-rest keys buyer-ops |
| **SI** System Integrity | Flaw remediation, validation | **Strong / PARTIAL** | Patch SLAs + input validation **IMPLEMENTED**; platform self-monitoring **PLANNED** |
| **SR** Supply Chain | SBOM, provenance | **PARTIAL** | SBOM + scanning **IMPLEMENTED**; formal vendor risk program **PLANNED** |

---

## 4. Priority FedRAMP Moderate controls (application boundary)

The following are high-visibility Moderate controls for a SaaS application. Status mirrors `NIST_ALIGNMENT.md` and dossier v1.1.

### 4.1 Access Control (AC)

| Control | FedRAMP Moderate relevance | Status | Evidence |
| --- | --- | --- | --- |
| AC-2 Account Management | Required | **IMPLEMENTED** | Invite/remove users; unique email; roles |
| AC-3 Access Enforcement | Required | **IMPLEMENTED** | `require_role`, `tenant_filter` |
| AC-6 Least Privilege | Required | **IMPLEMENTED** | Non-owner hard-scoped to tenant |
| AC-7 Unsuccessful Logon Attempts | Required | **IMPLEMENTED** | 5 / 15-min; proxy-aware IP |
| AC-8 System Use Notification | Required | **PLANNED** | Login banner |
| AC-11 Session Lock | Required | **PLANNED** | Idle timeout |
| AC-12 Session Termination | Required | **IMPLEMENTED** | Cookie clear + `auth_sessions` revoke |
| AC-17 Remote Access | Required | **PARTIAL** | HTTPS production; no product VPN |
| AC-14 Permitted Actions w/o ID | Required | **IMPLEMENTED** | Minimal public surface |

### 4.2 Identification and Authentication (IA)

| Control | FedRAMP Moderate relevance | Status | Evidence |
| --- | --- | --- | --- |
| IA-2 Organizational Users | Required | **IMPLEMENTED** | Email/password + JWT |
| IA-2(1) MFA Privileged | Required | **IMPLEMENTED** | TOTP; production `MFA_REQUIRED` |
| IA-2(2) MFA Non-Privileged | Required | **IMPLEMENTED** | Same when MFA required |
| IA-2(12) Acceptance of PIV | Often required for federal users | **PLANNED** | Smart-card path |
| IA-5 Authenticator Management | Required | **IMPLEMENTED** | bcrypt 12; reset TTL tokens |
| IA-5(1) Password-Based Auth | Required | **PARTIAL** | Min length yes; complexity **PLANNED** |
| IA-5(7) No Embedded Static Authenticators | Required | **IMPLEMENTED** | Production fail-closed on defaults |
| IA-8 Non-Organizational Users | As applicable | **PARTIAL** | Register path; SSO fail-closed until configured |
| IA-11 Re-Authentication | Required (enhancements vary) | **PLANNED** | Step-up on destructive actions |

### 4.3 Audit and Accountability (AU)

| Control | Status | Evidence |
| --- | --- | --- |
| AU-2 Event Logging | **IMPLEMENTED** | `write_audit` on security-relevant events |
| AU-3 Content of Audit Records | **IMPLEMENTED** | Actor, action, resource, IP, tenant, time |
| AU-6 Review, Analysis, Reporting | **PARTIAL** | Product audit UI; platform SIEM forward **PLANNED** |
| AU-8 Time Stamps | **IMPLEMENTED** | UTC |
| AU-9 Protection of Audit Information | **PARTIAL** | Append-oriented; hash-chain/WORM **PLANNED** |
| AU-11 Retention | **PLANNED** | Formal schedule |
| AU-12 Audit Generation | **IMPLEMENTED** | Server-side |

### 4.4 System and Communications Protection (SC)

| Control | Status | Evidence |
| --- | --- | --- |
| SC-5 DoS Protection | **PARTIAL** | App rate limiting **PLANNED**; CSP/WAF inherited |
| SC-7 Boundary Protection | **PARTIAL** | Ingress TLS; NetworkPolicies buyer |
| SC-8 Transmission Confidentiality | **IMPLEMENTED** | TLS; production HTTPS frontend |
| SC-12 Key Management | **PARTIAL** | Env secrets; JWT rotation **PLANNED**; buyer secret manager |
| SC-13 Cryptographic Protection | **PARTIAL** | Industry crypto; **FIPS 140 validated modules PLANNED** |
| SC-23 Session Authenticity | **IMPLEMENTED** | httpOnly cookies + server sessions + CSRF origin guard |
| SC-28 Protection at Rest | **PARTIAL** | WiredTiger config + runbook; **buyer must provision keys** |

### 4.5 Configuration, Integrity, Risk (CM / SI / RA)

| Control | Status | Evidence |
| --- | --- | --- |
| CM-8 Component Inventory | **IMPLEMENTED** | CycloneDX SBOM in CI |
| RA-5 Vulnerability Monitoring | **IMPLEMENTED** | Dependabot, pip-audit, npm audit, Trivy, Gitleaks |
| SI-2 Flaw Remediation | **IMPLEMENTED** | Policy pack SLAs 24h/7d/30d/90d |
| SI-10 Input Validation | **IMPLEMENTED** | Pydantic, Literals, parameterized queries |
| SI-11 Error Handling | **IMPLEMENTED** | No stack traces to clients |

### 4.6 Contingency, Incident, Assessment (CP / IR / CA)

| Control | Status | Evidence |
| --- | --- | --- |
| CP-2 Contingency Plan | **PLANNED** | — |
| CP-9 System Backup | **PARTIAL** | Mongo capability; runbook/drill **PLANNED** |
| IR-1 / IR-8 IR Policy & Plan | **IMPLEMENTED** | `docs/INCIDENT_RESPONSE_PLAN.md` |
| IR-4 Incident Handling | **IMPLEMENTED** | Documented lifecycle + product IR workspace |
| CA-5 POA&M | **IMPLEMENTED** | Dossier §10 |
| CA-7 Continuous Monitoring | **PARTIAL** | Audit + product telemetry; ConMon dashboard **PLANNED** |
| CA-8 Penetration Testing | **PLANNED** | External 3PAO-style engagement |

### 4.7 Supply Chain (SR)

| Control | Status | Evidence |
| --- | --- | --- |
| SR-3 Supply Chain Controls | **PARTIAL** | CI scanning + Dependabot |
| SR-4 Provenance | **IMPLEMENTED** | SBOM artifacts |
| SR-6 Supplier Assessments | **PLANNED** | Formal vendor risk |

---

## 5. FedRAMP Moderate gap matrix (authorization-oriented)

| Priority | Gap | Related controls | Severity | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | Encryption-at-rest keys provisioned + restore/decryption drill | SC-28, CP-9, CP-10 | **Blocker (ops)** | Buyer / hosting | Config in `ops/mongodb/` is ready; keys never in Git |
| 2 | Complete enterprise SSO (SAML/OIDC) with full assertion validation | IA-2, IA-8, AC-2 | High | Aegis | Routes exist; fail-closed until configured |
| 3 | BCP/DR documentation + first backup restore drill | CP-2, CP-4, CP-9, CP-10 | High | Aegis + buyer | — |
| 4 | Continuous Monitoring dashboard for *platform* logs | CA-7, AU-6, SI-4 | High | Aegis | Product monitoring ≠ platform ConMon |
| 5 | FIPS 140 validated cryptographic modules (where required) | SC-13, IA-7 | Medium–High | Aegis | Depends on agency path |
| 6 | PIV / smart-card acceptance for federal users | IA-2(12) | Medium–High | Aegis | Government posture |
| 7 | Database-level tenant isolation (beyond query filter) | AC-3, AC-4, SC-4 | Medium (High for high-side) | Aegis | Roadmap Phase 1–3 in dossier §5.5 |
| 8 | System use notification (AC-8) + idle timeout (AC-11) | AC-8, AC-11 | Medium | Aegis | Low engineering cost |
| 9 | Rate limiting on authenticated APIs | SC-5 | Medium | Aegis | — |
| 10 | Independent penetration test + 3PAO assessment | CA-2, CA-8 | High (process) | External | Required for authorization package |
| 11 | Formal SSP, policies expansion, personnel security | PL-2, PS-*, AT-* | High (process) | Aegis | Policy pack v1.0 exists; full ISMS still open |
| 12 | Branch protection + deployment gates | CM-3, SA-10 | Medium | Aegis / ops | CI workflows exist |

---

## 6. Inheritance and shared responsibility

| Control area | Aegis | Customer / CSP |
| --- | --- | --- |
| Application authn/z, MFA, RBAC, tenancy (logical) | **Responsible** | Configure IdP / users |
| Application audit generation | **Responsible** | Consume / retain per agency policy |
| TLS to browser | **Responsible** (ingress config) | DNS, certificates if customer-hosted |
| MongoDB TLS + encryption-at-rest *configuration* | **Responsible** (ship config) | **Responsible** for keys, certs, runtime |
| Physical, facility, media, environmental | **N/A** | **Inherited / CSP** |
| Hypervisor, region isolation, DDoS at edge | **N/A** unless Aegis is CSP | **CSP / agency** |
| Agency continuous monitoring program | Supports with logs/APIs | **Agency** |
| Data classification & retention legal holds | Provides capabilities | **Agency data owner** |

---

## 7. Path toward Moderate authorization (engineering view)

This is a **product readiness sequence**, not a FedRAMP PMO plan.

| Phase | Objective | Exit criteria |
| --- | --- | --- |
| **A — Harden (done / in progress)** | MFA, headers, CSRF, Mongo TLS client, IR plan, policy pack, CI scanning, SBOM | Reflected in dossier v1.1 |
| **B — Ops readiness** | Encryption keys, backup/restore drill, rate limits, AC-8/AC-11, branch protection | Gap matrix items 1, 3, 8, 9, 12 closed |
| **C — Enterprise identity** | Production SSO + optional PIV | Gap items 2, 6 |
| **D — Tenancy depth** | Schema- or DB-level isolation for government deals | Gap item 7 Phase 1+ |
| **E — Assess** | Pen test, ConMon story, SSP draft, 3PAO | Gap items 4, 10, 11 |
| **F — Authorize** | Agency sponsor, FedRAMP path (JAB or agency ATO) | Outside pure engineering |

Estimated remaining internal engineering after Phase A: see dossier POA&M (~28 PW), of which FedRAMP-critical ops items are a subset.

---

## 8. Evidence index (FedRAMP-oriented)

| Artifact | Path |
| --- | --- |
| Security summary | `SECURITY.md` |
| Full dossier + POA&M | `SECURITY_DOSSIER.md` |
| NIST 800-53 appendix | `NIST_ALIGNMENT.md` |
| This baseline map | `docs/FEDRAMP_MODERATE_BASELINE.md` |
| Policy pack | `docs/SECURITY_POLICY_PACK.md` |
| Incident response plan | `docs/INCIDENT_RESPONSE_PLAN.md` |
| MongoDB encryption/TLS runbook | `ops/mongodb/` |
| Ingress headers | `ops/ingress/security-headers.yaml` |
| Security CI | `.github/workflows/security.yml` |
| Security tests | `tests/test_backend_security.py` |
| Application code | `backend/server.py`, `backend/security_hardening.py`, `backend/sso.py` |

---

## 9. Explicit non-claims

1. Aegis SOC holds **no FedRAMP authorization** as of this document’s date.  
2. Design alignment with Moderate **does not** equal residual-risk acceptance by any agency.  
3. Controls marked **INHERITED** depend on the hosting CSP and deployment model chosen by the customer.  
4. **SC-28** is not complete until encryption keys are provisioned and restore procedures are tested outside this repository.  
5. **IA-2 MFA** is TOTP-based today; PIV/WebAuthn remain planned for stricter federal paths.

---

## 10. Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial FedRAMP Moderate baseline mapping aligned to dossier v1.1 and NIST appendix v1.0. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`

© 2026 Aegis SOC · All rights reserved · Transferable commercial license available
