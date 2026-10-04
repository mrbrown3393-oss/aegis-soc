# Aegis SOC — NIST SP 800-53 Revision 5 Alignment Appendix

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Aligned to**: `SECURITY_DOSSIER.md` v1.1 (2026-10-04)  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> This appendix maps Aegis SOC platform controls to selected NIST SP 800-53 Revision 5 families that are material to a multi-tenant SOC product targeting FedRAMP Moderate and CMMC Level 2 design baselines.
>
> **It is not a System Security Plan (SSP), not a 3PAO package, and not a certification claim.**  
> Status values match the dossier taxonomy: **IMPLEMENTED** · **PARTIAL** · **PLANNED** · **NOT APPLICABLE**.
>
> For the **FedRAMP Moderate** design-target view (boundary, inheritance, gap matrix, authorization path), see `docs/FEDRAMP_MODERATE_BASELINE.md`.

---

## How to use this document

1. Treat each row as a **platform control claim** about the Aegis product and its own security posture — not about customer workloads monitored *by* Aegis.
2. Verify every **IMPLEMENTED** claim against the Evidence column (source path or artifact).
3. Cross-read `SECURITY_DOSSIER.md` for narrative context, residual risk, and the POA&M.
4. `SECURITY.md` is the short entry point; this file is the 800-53 control catalog appendix.
5. `docs/FEDRAMP_MODERATE_BASELINE.md` selects Moderate-priority controls and shared responsibility for government diligence.

### Coverage summary (selected controls)

| Status | Count (approx.) | Meaning |
| --- | ---: | --- |
| **IMPLEMENTED** | ~42 | Code, config, or policy artifact present and verifiable |
| **PARTIAL** | ~28 | Meaningful progress; gap explicitly noted |
| **PLANNED** | ~35 | Documented remediation path in dossier POA&M |
| **NOT APPLICABLE** | ~8 | Outside current architecture or data scope |

Percentages in the dossier (~48% direct / ~79% direct+partial at v1.0) improve after the 2026-10 hardening branch (MFA, headers, CSRF, Mongo TLS, IR plan, policy pack, CI scanning). Exact percentages should be recalculated after any formal control selection for FedRAMP/CMMC scoping.

---

## AC — Access Control

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| AC-2 | Account Management | **IMPLEMENTED** | Users collection; invite / remove via API; unique email index; roles `owner`/`admin`/`analyst`/`viewer` |
| AC-2(1) | Automated System Account Management | **PARTIAL** | Automated invite + role assignment; full joiner/mover/leaver workflows **PLANNED** |
| AC-3 | Access Enforcement | **IMPLEMENTED** | `require_role()` and `tenant_filter()` on every privileged route |
| AC-3(7) | Role-Based Access Control | **IMPLEMENTED** | Four-role model enforced server-side |
| AC-4 | Information Flow Enforcement | **PARTIAL** | Tenant query scoping; network-layer flow control is buyer K8s NetworkPolicy |
| AC-6 | Least Privilege | **IMPLEMENTED** | Non-owner roles hard-scoped to own tenant; viewer is read-only |
| AC-6(1) | Authorize Access to Security Functions | **IMPLEMENTED** | Owner/admin gated for user management |
| AC-7 | Unsuccessful Logon Attempts | **IMPLEMENTED** | 5 failures → 15-min lockout per `{ip}:{email}`; proxy-aware IP via `forwarded_client_ip()` |
| AC-8 | System Use Notification | **PLANNED** | Login banner for FedRAMP |
| AC-11 | Device Lock / Session Lock | **PLANNED** | Idle timeout (15 min target) |
| AC-12 | Session Termination | **IMPLEMENTED** | Logout clears cookies; `auth_sessions` revocation; session checked on each request |
| AC-14 | Permitted Actions Without Identification | **IMPLEMENTED** | Only public auth endpoints (register/login/reset/SSO config) and health; all other `/api/*` require auth |
| AC-17 | Remote Access | **PARTIAL** | HTTPS-only in production; no VPN product shipped — buyer network |
| AC-18 | Wireless Access | **NOT APPLICABLE** | No wireless infrastructure in product scope |
| AC-19 | Access Control for Mobile Devices | **NOT APPLICABLE** | Web console; no native mobile agent in current scope |
| AC-20 | Use of External Systems | **PARTIAL** | CORS origin allow-list; production rejects wildcard |
| AC-21 | Information Sharing | **PARTIAL** | Tenant isolation prevents cross-tenant sharing by default; owner-only cross-tenant view |

---

## AU — Audit and Accountability

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| AU-2 | Event Logging | **IMPLEMENTED** | `write_audit()` on login/logout/mutations; actor, action, resource, IP, tenant, timestamp |
| AU-3 | Content of Audit Records | **IMPLEMENTED** | Structured fields as above |
| AU-3(1) | Additional Audit Information | **PARTIAL** | IP via trusted-proxy path; user-agent not always captured |
| AU-6 | Audit Record Review, Analysis, and Reporting | **PARTIAL** | Audit Logs module + CSV export in product; platform SIEM forwarding **PLANNED** |
| AU-7 | Audit Record Reduction and Report Generation | **PARTIAL** | Product UI filters; formal reduction tools **PLANNED** |
| AU-8 | Time Stamps | **IMPLEMENTED** | UTC ISO timestamps on audit and security events |
| AU-9 | Protection of Audit Information | **PARTIAL** | Append-oriented writes; hash-chain / WORM **PLANNED** |
| AU-9(2) | Store on Separate Physical Systems | **PLANNED** | Buyer SIEM / object-lock storage |
| AU-11 | Audit Record Retention | **PLANNED** | Policy pack requires retention limits; formal 90-day / 1-year schedule **PLANNED** |
| AU-12 | Audit Record Generation | **IMPLEMENTED** | Server-side generation on security-relevant events |

---

## CA — Assessment, Authorization, and Monitoring

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| CA-2 | Control Assessments | **PARTIAL** | This dossier + appendix + automated security tests; independent 3PAO **PLANNED** |
| CA-5 | Plan of Action and Milestones (POA&M) | **IMPLEMENTED** | `SECURITY_DOSSIER.md` §10 |
| CA-6 | Authorization | **PLANNED** | No ATO yet; design baseline only |
| CA-7 | Continuous Monitoring | **PARTIAL** | Product telemetry + audit trail; platform ConMon dashboard **PLANNED** |
| CA-8 | Penetration Testing | **PLANNED** | External engagement on POA&M |

---

## CM — Configuration Management

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| CM-2 | Baseline Configuration | **PARTIAL** | Pinned deps where practical; image baselines **PLANNED** |
| CM-3 | Configuration Change Control | **PARTIAL** | Git + PR workflows; formal CAB **PLANNED** |
| CM-4 | Impact Analyses | **PLANNED** | — |
| CM-6 | Configuration Settings | **PARTIAL** | Hardened defaults in code; production fail-closed validation |
| CM-7 | Least Functionality | **PARTIAL** | Docs disabled in production; unnecessary ports buyer-controlled |
| CM-8 | System Component Inventory | **IMPLEMENTED** | CycloneDX SBOM in CI for Python and Node |
| CM-9 | Configuration Management Plan | **PLANNED** | — |
| CM-10 | Software Usage Restrictions | **PARTIAL** | License compliance scanning **PLANNED** |
| CM-11 | User-Installed Software | **NOT APPLICABLE** | SaaS/console model; no end-user software install path in product |

---

## CP — Contingency Planning

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| CP-1 | Contingency Planning Policy | **PARTIAL** | Policy pack references BCP; full BCP/DR documents **PLANNED** |
| CP-2 | Contingency Plan | **PLANNED** | — |
| CP-3 | Contingency Training | **PLANNED** | — |
| CP-4 | Contingency Plan Testing | **PLANNED** | First restore drill **PLANNED** |
| CP-9 | System Backup | **PARTIAL** | MongoDB native backup available; documented runbook **PLANNED** |
| CP-10 | System Recovery and Reconstitution | **PLANNED** | — |

---

## IA — Identification and Authentication

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| IA-2 | Identification and Authentication (Organizational Users) | **IMPLEMENTED** | Email + password; JWT sessions |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | **IMPLEMENTED** | TOTP MFA; `MFA_REQUIRED=true` enforced in production |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | **IMPLEMENTED** | Same TOTP path when MFA required |
| IA-2(12) | Acceptance of PIV Credentials | **PLANNED** | Government deployments |
| IA-4 | Identifier Management | **IMPLEMENTED** | UUID user ids; unique email |
| IA-5 | Authenticator Management | **IMPLEMENTED** | bcrypt cost 12; single-use reset tokens with TTL |
| IA-5(1) | Password-Based Authentication | **PARTIAL** | Min length enforced; complexity policy **PLANNED** |
| IA-5(2) | PKI-Based Authentication | **PLANNED** | PIV / smart card |
| IA-5(6) | Protection of Authenticators | **IMPLEMENTED** | Hashes only; secrets from env; not logged |
| IA-5(7) | No Embedded Unencrypted Static Authenticators | **IMPLEMENTED** | Production rejects default passwords and weak JWT secret |
| IA-8 | Identification and Authentication (Non-Organizational Users) | **PARTIAL** | Registration path for viewers; enterprise SSO **PARTIAL** (fail-closed until configured) |
| IA-11 | Re-Authentication | **PLANNED** | Step-up on high-risk actions |
| IA-12 | Identity Proofing | **NOT APPLICABLE** | Out of band / customer responsibility for enterprise IdP |

---

## IR — Incident Response

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| IR-1 | Incident Response Policy and Procedures | **IMPLEMENTED** | `docs/INCIDENT_RESPONSE_PLAN.md` + policy pack |
| IR-2 | Incident Response Training | **PLANNED** | On first hire / team growth |
| IR-3 | Incident Response Testing | **PLANNED** | Tabletop **PLANNED** |
| IR-4 | Incident Handling | **IMPLEMENTED** | Platform IR lifecycle documented; product incident workspace for customer workloads |
| IR-5 | Incident Monitoring | **PARTIAL** | Product modules; platform self-monitoring **PLANNED** |
| IR-6 | Incident Reporting | **PARTIAL** | Communications section in IR plan; contractual SLAs **PLANNED** |
| IR-7 | Incident Response Assistance | **PARTIAL** | Owner contact; formal support tiers **PLANNED** |
| IR-8 | Incident Response Plan | **IMPLEMENTED** | `docs/INCIDENT_RESPONSE_PLAN.md` (SEV-1..4, roles, evidence, review) |

---

## MA — Maintenance

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| MA-1 | System Maintenance Policy | **PARTIAL** | Covered at high level in policy pack |
| MA-2 | Controlled Maintenance | **PLANNED** | Formal maintenance windows |
| MA-4 | Nonlocal Maintenance | **PARTIAL** | Remote admin via authenticated console only |
| MA-5 | Maintenance Personnel | **PARTIAL** | Sole-owner today |

---

## MP — Media Protection

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| MP-2 | Media Access | **PARTIAL** | Logical access via RBAC; physical media is buyer data-center scope |
| MP-4 | Media Storage | **PARTIAL** | Encryption at rest config documented; keys buyer-managed |
| MP-5 | Media Transport | **NOT APPLICABLE** | No removable media workflow in product |
| MP-6 | Media Sanitization | **PLANNED** | Controlled deletion procedures for Restricted data |
| MP-7 | Media Use | **NOT APPLICABLE** | — |

---

## PE — Physical and Environmental Protection

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| PE-* | Physical controls | **NOT APPLICABLE** / inherited | Buyer cloud / data center; Aegis is software |

---

## PL — Planning

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| PL-1 | Security Planning Policy | **IMPLEMENTED** | `docs/SECURITY_POLICY_PACK.md` |
| PL-2 | System Security Plan | **PARTIAL** | Dossier + this appendix + FedRAMP baseline map serve as interim SSP content; formal SSP for ATO **PLANNED** |
| PL-4 | Rules of Behavior | **PLANNED** | — |
| PL-8 | Security and Privacy Architectures | **PARTIAL** | Documented in dossier (ZTA mapping, tenancy model) |

---

## PM — Program Management

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| PM-1 | Information Security Program Plan | **PARTIAL** | Policy pack + dossier; full program plan **PLANNED** |
| PM-4 | Plan of Action and Milestones Process | **IMPLEMENTED** | Dossier §10 POA&M |
| PM-9 | Risk Management Strategy | **PARTIAL** | POA&M as risk register; formal annual RA **PLANNED** |
| PM-10 | Authorization Process | **PLANNED** | — |
| PM-14 | Testing, Training, and Monitoring | **PARTIAL** | Automated tests + CI; training **PLANNED** |

---

## PS — Personnel Security

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| PS-1 | Personnel Security Policy | **PLANNED** | On first hire |
| PS-2 | Position Risk Designation | **PLANNED** | — |
| PS-3 | Personnel Screening | **PLANNED** | Customer/employer responsibility for operators |
| PS-4 | Personnel Termination | **PARTIAL** | API can remove operators; formal checklist **PLANNED** |
| PS-5 | Personnel Transfer | **PLANNED** | — |
| PS-6 | Access Agreements | **PLANNED** | — |
| PS-7 | External Personnel Security | **PLANNED** | Vendor risk process |
| PS-8 | Personnel Sanctions | **PLANNED** | — |

---

## RA — Risk Assessment

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| RA-1 | Risk Assessment Policy | **PARTIAL** | Policy pack |
| RA-2 | Security Categorization | **PARTIAL** | Data classification in policy pack (Public/Internal/Confidential/Restricted) |
| RA-3 | Risk Assessment | **PARTIAL** | Dossier + POA&M; formal cadence **PLANNED** |
| RA-5 | Vulnerability Monitoring and Scanning | **IMPLEMENTED** | Dependabot, pip-audit, npm audit, Trivy, Gitleaks in CI |
| RA-5(2) | Update Vulnerabilities to Be Scanned | **IMPLEMENTED** | Weekly Dependabot + scheduled security workflow |
| RA-5(11) | Public Disclosure Program | **PARTIAL** | Private disclosure email in `SECURITY.md`; public bug bounty **PLANNED** |

---

## SA — System and Services Acquisition

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| SA-3 | System Development Life Cycle | **PARTIAL** | GitHub flow + CI; formal SDLC doc **PLANNED** |
| SA-4 | Acquisition Process | **PARTIAL** | Dependency inventory + SBOM |
| SA-8 | Security and Privacy Engineering Principles | **PARTIAL** | Secure defaults, fail-closed production, least privilege |
| SA-10 | Developer Configuration Management | **PARTIAL** | Git history; signed commits **PLANNED** |
| SA-11 | Developer Testing and Evaluation | **IMPLEMENTED** | pytest security suite + Playwright flows |
| SA-15 | Development Process, Standards, and Tools | **PARTIAL** | CI security workflow |
| SA-22 | Unsupported System Components | **PARTIAL** | Dependabot keeps components current |

---

## SC — System and Communications Protection

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| SC-5 | Denial-of-Service Protection | **PARTIAL** | Rate limiting on authenticated endpoints **PLANNED**; buyer DDoS/WAF |
| SC-7 | Boundary Protection | **PARTIAL** | Ingress TLS; network policies buyer-side |
| SC-8 | Transmission Confidentiality and Integrity | **IMPLEMENTED** | TLS at ingress; production requires HTTPS frontend |
| SC-8(1) | Cryptographic Protection | **IMPLEMENTED** | TLS 1.2+ / 1.3 preferred |
| SC-12 | Cryptographic Key Establishment and Management | **PARTIAL** | Env-based secrets; JWT key rotation **PLANNED**; buyer secret manager |
| SC-13 | Cryptographic Protection | **PARTIAL** | bcrypt, JWT HS256, TLS; FIPS modules **PLANNED** |
| SC-17 | Public Key Infrastructure Certificates | **PARTIAL** | Ingress certs (inherited); app-level PKI **PLANNED** for PIV |
| SC-18 | Mobile Code | **PARTIAL** | CSP restricts script sources |
| SC-23 | Session Authenticity | **IMPLEMENTED** | httpOnly secure cookies; server-side session binding |
| SC-28 | Protection of Information at Rest | **PARTIAL** | MongoDB WiredTiger encryption config + runbook; buyer provisions keys |
| SC-28(1) | Cryptographic Protection | **PARTIAL** | Same as SC-28 |

---

## SI — System and Information Integrity

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| SI-2 | Flaw Remediation | **IMPLEMENTED** | Patch SLAs in policy pack (24h / 7d / 30d / 90d); CI scanning |
| SI-3 | Malicious Code Protection | **PARTIAL** | Buyer host/EDR; dependency scanning reduces supply-chain malware risk |
| SI-4 | System Monitoring | **PARTIAL** | Product threat modules; platform self-monitoring **PLANNED** |
| SI-5 | Security Alerts, Advisories, and Directives | **PARTIAL** | Dependabot alerts; formal intake process **PLANNED** |
| SI-7 | Software, Firmware, and Information Integrity | **PARTIAL** | SBOM + CI integrity checks; signed images **PLANNED** |
| SI-10 | Information Input Validation | **IMPLEMENTED** | Pydantic v2, Literal enums, parameterized queries, React escaping |
| SI-11 | Error Handling | **IMPLEMENTED** | Structured errors; no stack-trace leakage to clients |
| SI-12 | Information Management and Retention | **PARTIAL** | Classification + retention principles in policy pack |

---

## SR — Supply Chain Risk Management

| Control | Title | Status | Evidence / Notes |
| --- | --- | --- | --- |
| SR-1 | Supply Chain Risk Management Policy | **PARTIAL** | Policy pack third-party section |
| SR-2 | Supply Chain Risk Management Plan | **PLANNED** | Formal vendor risk process |
| SR-3 | Supply Chain Controls and Processes | **PARTIAL** | Dependabot, SBOM, secret scanning |
| SR-4 | Provenance | **IMPLEMENTED** | CycloneDX SBOM generation in CI |
| SR-5 | Acquisition Strategies, Tools, and Methods | **PARTIAL** | Prefer maintained packages; license scan **PLANNED** |
| SR-6 | Supplier Assessments and Reviews | **PLANNED** | — |
| SR-7 | Supply Chain Operations Security | **PLANNED** | — |
| SR-11 | Component Authenticity | **PARTIAL** | Package registries + lockfiles; cosign **PLANNED** |

---

## Crosswalk: Hardening branch → controls

| Hardening deliverable | Primary 800-53 controls |
| --- | --- |
| TOTP MFA + production fail-closed | IA-2(1), IA-2(2), IA-5(7) |
| CSRF Origin/Referer guard | AC-3, SC-23 |
| Security headers (CSP, HSTS, XFO, nosniff, …) | SC-8, SC-18, SI-10 |
| Proxy-aware lockout IP | AC-7 |
| MongoDB TLS + WiredTiger config | SC-8, SC-28 |
| Policy pack | PL-1, IR-1, RA-1, SR-1, SI-2 |
| Platform IR plan | IR-1, IR-4, IR-8 |
| Gitleaks / Trivy / pip-audit / Dependabot / SBOM | RA-5, CM-8, SI-2, SR-3, SR-4 |
| Server-side session revocation | AC-12, SC-23 |
| Security test suite | CA-2, SA-11 |

---

## Explicit non-claims

1. **No FedRAMP authorization, CMMC certification, or SOC 2 report** is asserted by this mapping.
2. **Inherited controls** (physical, facility, cloud provider boundary) remain the buyer's or hosting provider's responsibility.
3. **Tenant isolation** is logical/query-level today (AC-3 / AC-4 **PARTIAL** toward database-level isolation).
4. **SSO** endpoints fail closed until provider validation is complete — not a substitute for a production IdP integration.
5. **Encryption at rest** requires buyer-provisioned WiredTiger keys; configuration alone is not a completed SC-28 implementation.

---

## Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial NIST SP 800-53 Rev 5 appendix aligned to dossier v1.1 and hardening branch (MFA, headers, CSRF, Mongo TLS, IR/policy artifacts, CI scanning). Cross-linked FedRAMP Moderate baseline map. | William Brown / Grok |

---

## Related documents

| Document | Path |
| --- | --- |
| Security summary | `SECURITY.md` |
| Security & Compliance Dossier | `SECURITY_DOSSIER.md` |
| FedRAMP Moderate baseline map | `docs/FEDRAMP_MODERATE_BASELINE.md` |
| Information Security Policy Pack | `docs/SECURITY_POLICY_PACK.md` |
| Incident Response Plan | `docs/INCIDENT_RESPONSE_PLAN.md` |
| Hardening notes | `SECURITY_HARDENING.md` |

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`

© 2026 Aegis SOC · All rights reserved
