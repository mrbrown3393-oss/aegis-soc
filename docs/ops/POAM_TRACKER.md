# Aegis SOC — POA&M Tracker (Security Engineering)

**Document version**: 1.0  
**Aligned to**: `SECURITY_DOSSIER.md` §10  
**Owner**: William Brown  
**Last updated**: 2026-10-05

> Living Plan of Action & Milestones for security engineering. Update status, dates, and residual risk as work completes. This is **not** a FedRAMP-submitted POA&M spreadsheet; export to CSV/XLSX for formal packages.

**Status values:** `Open` · `In Progress` · `Deferred` · `Closed` · `Risk Accepted`

---

## Open / In Progress

| ID | Weakness / Gap | Controls | Severity | Owner | Effort | Target | Status | Residual risk if deferred | Evidence when closed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| POAM-001 | WiredTiger key provisioned + restore/decryption drill | SC-28, CP-9, CP-10 | Critical | Customer + SecEng | 0.5 PW | TBD | Open | Data recoverable unencrypted or untested restore | Drill report signed |
| POAM-002 | Complete customer/provider SSO deployment configuration | IA-2, IA-8, AC-2 | Medium | Customer + SecEng | 1 PW | TBD | Closed | Provider-specific setup remains deployment-scoped | Config guide + provider test evidence |
| POAM-003 | BCP/DR published + first restore drill executed | CP-2, CP-4, CP-9 | High | SecEng + Customer | 3 PW | TBD | Open | Untested recovery | `docs/ops/RESTORE_DRILL_RUNBOOK.md` filled |
| POAM-004 | Platform ConMon / SIEM forward | CA-7, AU-6, SI-4 | High | SecEng | 2 PW | TBD | Open | Blind to platform anomalies | Dashboard or SIEM rules |
| POAM-005 | AC-8 system use banner | AC-8 | Medium | SecEng | 0.25 PW | TBD | Open | Missing FedRAMP banner | UI screenshot + code |
| POAM-006 | AC-11 idle timeout (≤15m target) | AC-11 | Medium | SecEng | 1 PW | 2026-10-05 | Closed | — | `active_session()` + regression test |
| POAM-007 | API rate limiting | SC-5 | Medium | SecEng | 1 PW | 2026-10-05 | Closed | — | `enforce_authenticated_rate_limit()` + regression test |
| POAM-008 | Password complexity beyond min length | IA-5(1) | Low | SecEng | 0.25 PW | TBD | Open | Weaker passwords | Validator + tests |
| POAM-009 | JWT dual-key rollover support | SC-12 | Medium | SecEng | 2 PW | 2026-10-05 | Closed | Operational rotation evidence still required | `JWT_PREVIOUS_SECRET` + regression tests; runbook remains |
| POAM-010 | WebAuthn / PIV path | IA-2, IA-2(12) | High* | SecEng | 1.5–4 PW | TBD | Open | TOTP-only MFA | Feature + docs |
| POAM-011 | Branch protection + required checks | CM-3, SA-10 | Medium | SecEng | 0.25 PW | TBD | Open | Unreviewed merge to main | GitHub settings export |
| POAM-012 | Database-level tenant isolation Phase 1 | AC-3, AC-4 | Medium | SecEng | 1 PW | TBD | Open | Logical-only isolation | Design + migration |
| POAM-013 | Third-party penetration test | CA-8 | High | External | $25–80K | TBD | Open | Unknown exploitable bugs | Report under NDA |
| POAM-014 | Dual approval on destructive actions | AC-6 enhancements | Medium | SecEng | 2 PW | TBD | Open | Single-actor high-risk change | Workflow |
| POAM-015 | FIPS modules where required | SC-13 | Medium–High | SecEng | 1 PW | TBD | Open | Non-validated crypto | Build notes |
| POAM-016 | Formal vendor risk process | SR-6 | Low | SecEng | 1 PW | TBD | Open | Ad-hoc supply chain | Procedure + register updates |
| POAM-017 | Secret rotation runbook executed once | SC-12 | Medium | SecEng | 0.5 PW | TBD | Open | Stale secrets | `docs/ops/SECRET_ROTATION_RUNBOOK.md` record |
| POAM-018 | IR tabletop completed | IR-3 | Medium | SecEng | 0.5 PW | TBD | Open | Untested IR plan | `docs/ops/IR_TABLETOP_RECORD.md` |

\*Severity depends on federal PIV requirement.

---

## Closed (hardening branch / docs — maintain evidence links)

| ID | Item | Closed | Evidence |
| --- | --- | --- | --- |
| POAM-C01 | TOTP MFA + prod fail-closed | 2026-10 | `server.py`, tests |
| POAM-C02 | CSRF origin guard | 2026-10 | middleware + tests |
| POAM-C03 | Security headers | 2026-10 | `security_hardening.py`, ingress YAML |
| POAM-C04 | Proxy-aware lockout IP | 2026-10 | `forwarded_client_ip` |
| POAM-C05 | Policy pack + IR plan | 2026-10 | `docs/SECURITY_POLICY_PACK.md`, `docs/INCIDENT_RESPONSE_PLAN.md` |
| POAM-C06 | Mongo TLS client + WiredTiger config docs | 2026-10 | env flags, `ops/mongodb/` |
| POAM-C07 | CI: Gitleaks, Trivy, pip-audit, SBOM | 2026-10 | `.github/workflows/security.yml` |
| POAM-C08 | Session revocation | 2026-10 | `auth_sessions` |
| POAM-C09 | FedRAMP design-target doc set | 2026-10 | `docs/FEDRAMP_*`, FIPS 199, CRM, ConMon, crypto |
| POAM-C10 | Production SAML validation + regression coverage | 2026-10 | `backend/sso.py`, SAML tests, v2.2.0 changelog |

---

## Risk acceptance log

| ID | Item | Accepted by | Date | Review by | Conditions |
| --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — |

---

## Change log

| Date | Change | Who |
| --- | --- | --- |
| 2026-10-04 | Initial tracker seeded from dossier POA&M | SecEng / Grok |
