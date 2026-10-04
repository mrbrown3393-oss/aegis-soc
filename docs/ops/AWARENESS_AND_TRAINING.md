# Aegis SOC — Security Awareness & Training Plan

**Document version**: 1.0  
**Owner**: Security Engineering  
**Related controls:** AT-2, AT-3

---

## 1. Audience

| Audience | Training |
| --- | --- |
| Platform owner / SecEng | Deep: IR, ConMon, crypto, deploy checklist, POA&M |
| Customer administrators | Console admin, MFA, RoB, data handling |
| Analysts | Tenant scope, incident workflow, export rules |
| Viewers | RoB + need-to-know |

---

## 2. Curriculum (minimum)

### 2.1 Onboarding (before privileged access)

- Rules of Behavior (`docs/RULES_OF_BEHAVIOR.md`)  
- MFA setup  
- Phishing / credential hygiene  
- How to report incidents  
- Tenant isolation expectations (no cross-tenant curiosity)  

### 2.2 Annual refresher

- Policy pack highlights  
- IR severity levels  
- Common vulnerabilities (OWASP top risks relevant to operators)  
- Updates to FedRAMP/customer requirements  

### 2.3 Role-based (SecEng)

- Deployment hardening checklist  
- Secret rotation & restore drill runbooks  
- CI security workflow interpretation  
- POA&M maintenance  

---

## 3. Methods

- Read-and-ack documents (tracked)  
- Short live walkthrough for admins  
- Tabletop IR annually (see `docs/ops/IR_TABLETOP_RECORD.md`)  

---

## 4. Tracking template

| Person | Role | Onboarding date | RoB ack | Annual due | Completed |
| --- | --- | --- | --- | --- | --- |
| William Brown | Owner | 2026-09 | | 2027-09 | |

---

## 5. Metrics

- % privileged users with RoB ack  
- % completion annual refresher  
- Tabletop executed within last 12 months (Y/N)  

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial plan |
