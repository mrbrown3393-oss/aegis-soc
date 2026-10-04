# Aegis SOC — Continuous Monitoring Strategy & Contingency Minimums

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> **Planned / partial operational posture.** This document defines how ConMon and contingency *should* work for a FedRAMP Moderate design target. Items marked **CURRENT** exist today; **PLANNED** are commitments on the POA&M path — not completed ops evidence.

**Related:** `docs/INCIDENT_RESPONSE_PLAN.md` · `docs/FEDRAMP_CRM_AND_PARAMETERS.md` · `SECURITY_DOSSIER.md` §10 · `ops/mongodb/`

---

## Part A — Continuous Monitoring (CA-7) strategy

### A.1 Purpose

Provide ongoing awareness of security control effectiveness for the **Aegis platform** (not only customer workloads displayed *in* the product).

### A.2 Roles

| Role | Responsibility |
| --- | --- |
| Aegis Owner / Security Lead | Define metrics, review CI findings, maintain POA&M |
| Customer (Variant A) | Host/runtime scanning, log retention, agency ConMon program |
| CSP | Infra telemetry, edge availability, inherited control evidence |
| Agency (if federal) | Official continuous monitoring under their ATO |

### A.3 What is monitored

| Domain | Signals | Current | Planned |
| --- | --- | --- | --- |
| **Identity & access** | Failed logins, lockouts, MFA failures, session revoke | App audit_logs + lockout logic | Alert thresholds / SIEM rules |
| **Privilege & change** | User invite/delete, role changes, quarantine actions | audit_logs | Daily review checklist |
| **Application integrity** | Dependency CVEs, secrets in git, fs vulns | Gitleaks, pip-audit, npm audit, Trivy, Dependabot | Ticket auto-open to POA&M |
| **Configuration** | Production fail-closed settings, CORS, TLS flags | Startup validation | Drift detection vs baseline |
| **Availability** | API health (`/api/`), process uptime | Health endpoint | Synthetic checks + on-call |
| **Audit pipeline** | Audit write success, export access | Collection writes | Forward to Customer SIEM |
| **Infrastructure** | Host patch level, disk, cert expiry | **Customer/CSP** | Documented in CRM |

### A.4 Cadence (target)

| Activity | Frequency | Owner | Status |
| --- | --- | --- | --- |
| CI security workflow | Every push/PR + weekly schedule | Aegis | **CURRENT** |
| Dependabot review | Weekly | Aegis | **CURRENT** |
| Audit log sample review | Weekly | Aegis / Customer | **PLANNED** process |
| Vulnerability SLA triage | Continuous per SI-2 | Aegis + deployer | **CURRENT** policy; ops evidence varies |
| Access review (operators) | Quarterly | Customer + Aegis | **PLANNED** |
| Restore / backup test | At least annual | Customer + Aegis | **PLANNED** |
| Metrics report to agency | Monthly (if under ATO) | Customer/Agency | **N/A** until authorized |
| Control assessment | Annual / 3PAO | External | **PLANNED** |

### A.5 Escalation

| Severity | Example | Action |
| --- | --- | --- |
| Critical | Prod secret leak, auth bypass, ransomware indicators | IR plan SEV-1; revoke sessions; rotate secrets |
| High | Exploitable CRITICAL CVE in production dependency | Patch target 24h; POA&M entry |
| Medium | Failed control test, misconfig without active exploit | POA&M; fix in agreed window |
| Low | Informational scanner findings | Track; batch remediation |

Aligns with `docs/INCIDENT_RESPONSE_PLAN.md` severity model.

### A.6 Tools (current vs planned)

| Capability | Tooling |
| --- | --- |
| Secret scanning | Gitleaks (**CURRENT**) |
| Dependency audit | pip-audit, npm audit, Dependabot (**CURRENT**) |
| Filesystem/vuln scan | Trivy in CI (**CURRENT**) |
| SBOM | CycloneDX (**CURRENT**) |
| App audit trail | MongoDB `audit_logs` + UI (**CURRENT**) |
| Central SIEM | **PLANNED** (Customer-chosen; Aegis export/forward) |
| Runtime host scanning | **Customer/CSP** |
| ConMon dashboard (platform) | **PLANNED** |

### A.7 Deliverables under a future ATO

- Monthly vulnerability summary  
- POA&M updates  
- Inventory/SBOM delta  
- Significant change notifications  
- Incident reports per IR-6 / agency rules  

Until authorized, Aegis maintains the engineering signals above and the dossier POA&M.

---

## Part B — Contingency planning minimums (CP)

### B.1 Scope

Loss or degradation of Aegis **control plane** (API, console, auth, database) for a deployment. Customer mission SOCs may have additional dependencies outside this boundary.

### B.2 Objectives (design targets — finalize in contract)

| Objective | Suggested target | Status |
| --- | --- | --- |
| **RTO** (restore service) | 24–72 hours | **PLANNED** — set per engagement |
| **RPO** (max data loss) | ≤ 24 hours | **PLANNED** — depends on backup cadence |
| Backup frequency | Daily minimum | **PLANNED** ops |
| Restore test | At least annually + after major changes | **PLANNED** |

### B.3 Critical functions (priority order)

1. Authentication & session validation  
2. Audit log durability  
3. API read of incidents/threats/assets  
4. Console availability  
5. Non-critical metrics/seeded demo features  

### B.4 Backup strategy (minimum)

| Item | Guidance | Owner (Variant A) |
| --- | --- | --- |
| What | MongoDB data files / managed snapshots including all tenant collections and `audit_logs` | Customer / CSP |
| Where | Separate account/region or immutable store when available | Customer / CSP |
| Encryption | Backup encryption enabled; keys in secret manager | Customer / CSP |
| Retention | Align to AU retention targets (90d online / 1y archive intent) | Customer |
| Documentation | Restore command runbook from `ops/mongodb/` + host docs | Aegis + Customer |

### B.5 Recovery outline

1. **Declare** — severity per IR plan; assign Incident Commander.  
2. **Assess** — data loss window, integrity of latest backup, blast radius.  
3. **Restore** — provision clean runtime; restore Mongo from last known good; verify TLS/keys.  
4. **Validate** — login, MFA, sample tenant queries, audit write test.  
5. **Rotate** — credentials/secrets if compromise suspected.  
6. **Resume** — DNS/ingress back; monitor heightened 24–72h.  
7. **Lessons learned** — update POA&M and this plan.  

### B.6 Alternate processing

| Mode | Description | Status |
| --- | --- | --- |
| Primary | Single-region deployment | Typical today |
| Alternate | Secondary region cold/warm standby | **PLANNED** / Customer architecture |
| Manual | Export CSV/audit extracts for offline triage | Partial (product export) |

### B.7 Communications

| Audience | Trigger | Channel |
| --- | --- | --- |
| Internal operators | Any SEV-1/2 platform outage | Phone/chat as designated |
| Customers | Confirmed boundary outage or data risk | Status email / contract path |
| Regulators / US-CERT | As required by law or ATO | Customer/Agency lead |

Public statements require owner approval (IR plan).

### B.8 First restore-drill checklist (to be executed)

- [ ] Backup job verified successful within last 24–48h  
- [ ] Restore into non-production environment  
- [ ] Application boots with production-like TLS settings  
- [ ] Admin login + MFA succeeds  
- [ ] Tenant-scoped read returns expected counts  
- [ ] Audit log accepts a test write  
- [ ] Time to restore measured vs RTO target  
- [ ] Results logged; gaps → POA&M  

**Status:** Checklist defined; formal drill **PLANNED** (not yet evidence of completion).

### B.9 Dependencies

| Dependency | Contingency note |
| --- | --- |
| DNS / TLS certificates | Track expiry; CSP/Customer owns renewal |
| Secret manager | Break-glass access procedure required |
| IdP (when SSO enabled) | Local auth break-glass accounts controlled |
| GitHub / CI | Does not block runtime; blocks patch pipeline |

---

## Part C — Explicit non-claims

1. ConMon strategy is **not** a FedRAMP monthly deliverable package.  
2. RTO/RPO are **suggested targets**, not contractual SLAs unless executed in a customer agreement.  
3. No completed annual restore drill is asserted by this document.

---

## Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial ConMon strategy and contingency minimums. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`
