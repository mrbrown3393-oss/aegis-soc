# Aegis SOC — CRM Variant B (Aegis-Operated SaaS)

**Document version**: 1.0  
**Owner**: William Brown  
**Companion to:** `docs/FEDRAMP_CRM_AND_PARAMETERS.md` (Variant A = customer-hosted)

> Use **only** when Aegis (or an Aegis-contracted CSP under Aegis’s package) operates the full stack for customers. This shifts infrastructure and data-platform rows toward Aegis. **Not authorized under FedRAMP.**

---

## 1. When Variant B applies

- Multi-tenant SaaS URL operated by Aegis  
- Aegis manages K8s/VMs, MongoDB, backups, edge TLS  
- Customer consumes browser/API only  

If the customer brings the cloud account, use **Variant A**.

---

## 2. Responsibility shifts (delta from Variant A)

| Area | Variant A | Variant B |
| --- | --- | --- |
| Compute / K8s | Customer / CSP | **Aegis / Aegis-CSP** |
| Edge TLS, WAF, DDoS | Customer / CSP | **Aegis / Aegis-CSP** |
| MongoDB admin, keys, backups | Customer / CSP | **Aegis** |
| Host patching & PE inheritance | Customer via CSP package | **Aegis** must inherit from its CSP and show chain |
| App code, MFA, RBAC, audit gen | Aegis | Aegis (unchanged) |
| Tenant operator accounts | Customer | Customer (unchanged) |
| Agency ATO / mission ConMon | Agency | Agency (unchanged) |
| Data classification of mission content | Customer | Customer (unchanged) |

---

## 3. Variant B CRM summary

| Control area | Aegis | Customer | Aegis-CSP |
| --- | --- | --- | --- |
| Application security (authn/z, headers, validation) | **I/R** | C (users) | — |
| Platform ConMon of app + infra | **I/R** | U (reports) | I (infra telemetry) |
| Encryption keys, DB TLS | **I/R** | — | U (KMS optional) |
| Backups & restore drills | **I/R** | U (RTO expectations in contract) | I (storage) |
| PE / facility | U | — | **I/R** |
| Boundary / VPC | **C/R** with CSP | — | **I** |
| Pen test of SaaS boundary | **R** (coordinate) | Authorize customer-scoped tests | Support |

---

## 4. Extra Aegis obligations under Variant B

1. Maintain CSP FedRAMP (or equivalent) inheritance matrix.  
2. Perform restore drills on the SaaS data plane annually.  
3. Publish customer-facing status/incident notifications.  
4. Separate customer tenants per logical isolation roadmap; strengthen isolation for federal deals.  
5. Revise parameter register for any SaaS-wide defaults differing from single-tenant deploy.  

---

## 5. Explicit non-claims

Variant B documentation does not create a FedRAMP authorization. Operating SaaS increases Aegis’s residual risk and evidence burden.

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial Variant B CRM delta |
