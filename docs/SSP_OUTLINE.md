# Aegis SOC — System Security Plan (SSP) Outline

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA

> **This is an outline, not a completed FedRAMP SSP.** It maps FedRAMP-style SSP sections to existing Aegis artifacts so a 3PAO or agency can see coverage and gaps.

---

## How to use

1. Copy this outline into the official FedRAMP SSP template when pursuing authorization.  
2. Replace “design target” language with deployment-specific facts (hostname, CSP, agency parameters).  
3. Attach CRM, diagrams, and evidence under NDA.

---

## SSP section map

| SSP-oriented section | Content source in repo | Status |
| --- | --- | --- |
| **1. Information system name / identification** | `docs/FIPS_199_AND_DATA_INVENTORY.md` §1 | Draft-ready |
| **2. System categorization (FIPS 199)** | `docs/FIPS_199_AND_DATA_INVENTORY.md` §2 | Design target Moderate |
| **3. System owner / authorizing contacts** | William Brown · `william.brown@aegis-soc.io` | Update per engagement |
| **4. Assignment of security responsibility** | `docs/FEDRAMP_CRM_AND_PARAMETERS.md` | Variant A complete; Variant B TBD |
| **5. System operational status** | Operational product; **not FedRAMP authorized** | Honest |
| **6. Information system type** | Multi-tenant SOC SaaS / deployable software | — |
| **7. General system description** | `README.md` · `SECURITY.md` §1 | — |
| **8. System environment / architecture** | `docs/FEDRAMP_SECURITY_ARCHITECTURE.md` | Diagrams |
| **9. System interconnections** | Architecture §1 + `docs/CRYPTO_AND_SUPPLY_CHAIN.md` Part B | — |
| **10. Laws, regulations, policies** | FedRAMP Moderate design target; agency overlays TBD | — |
| **11. Security control implementation** | `NIST_ALIGNMENT.md` · `SECURITY_DOSSIER.md` · CRM parameters | Partial |
| **12. Continuous monitoring** | `docs/CONMON_AND_CONTINGENCY.md` Part A | Planned/partial |
| **13. Contingency / backup** | `docs/CONMON_AND_CONTINGENCY.md` Part B | Minimums; drill pending |
| **14. Incident response** | `docs/INCIDENT_RESPONSE_PLAN.md` | Implemented doc |
| **15. POA&M** | `SECURITY_DOSSIER.md` §10 | Living narrative |
| **Attachments** | Policy pack, IR plan, Mongo hardening, CI workflows, test suite, SBOM artifacts | — |

---

## Control implementation narrative approach

For each control family in a full SSP:

1. **Control summary** — from `NIST_ALIGNMENT.md`  
2. **Implementation status** — IMPLEMENTED / PARTIAL / PLANNED / INHERITED  
3. **Responsible role** — from CRM  
4. **Parameters** — from parameter register  
5. **Evidence** — code path, config, or policy artifact  
6. **Gap** — link POA&M item if PARTIAL/PLANNED  

Do **not** claim inheritance from a CSP without citing that CSP’s authorization package.

---

## Minimum attachment list for diligence under NDA

- [ ] `SECURITY.md`  
- [ ] `SECURITY_DOSSIER.md`  
- [ ] `NIST_ALIGNMENT.md`  
- [ ] `docs/FEDRAMP_MODERATE_BASELINE.md`  
- [ ] `docs/FEDRAMP_CRM_AND_PARAMETERS.md`  
- [ ] `docs/FEDRAMP_SECURITY_ARCHITECTURE.md`  
- [ ] `docs/FIPS_199_AND_DATA_INVENTORY.md`  
- [ ] `docs/CONMON_AND_CONTINGENCY.md`  
- [ ] `docs/CRYPTO_AND_SUPPLY_CHAIN.md`  
- [ ] `docs/SECURITY_POLICY_PACK.md`  
- [ ] `docs/INCIDENT_RESPONSE_PLAN.md`  
- [ ] `docs/RULES_OF_BEHAVIOR.md`  
- [ ] Latest CI SBOM artifacts (on request)  
- [ ] Penetration test report (when available)  

---

## Explicit non-claims

This outline does not satisfy FedRAMP documentation completeness criteria by itself and must not be submitted as a finished SSP.

---

## Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial SSP outline mapping repo artifacts to FedRAMP-style sections. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`
