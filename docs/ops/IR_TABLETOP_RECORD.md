# Aegis SOC — Incident Response Tabletop Record

**Document version**: 1.0  
**Related:** `docs/INCIDENT_RESPONSE_PLAN.md`

> Template for conducting and recording a tabletop. Fill during/after the exercise. Blank completion = not yet executed.

---

## 1. Exercise metadata

| Field | Value |
| --- | --- |
| Date (UTC) | **NOT EXECUTED** |
| Facilitator | |
| Participants | |
| Duration | |
| Scenario ID | TT-001 (below) or custom |

---

## 2. Scenario library

### TT-001 — Suspected credential stuffing + admin lockout bypass attempt

**Inject 1:** Spike of failed logins across many IPs for one admin email.  
**Inject 2:** Successful login from new geo after 4 failures (just under threshold).  
**Inject 3:** Audit shows role change attempt.  

**Discuss:** Detection sources, lockout tuning, session revoke, customer notification, POA&M.

### TT-002 — Dependency CRITICAL CVE in production image

**Inject 1:** Trivy/CI fails on main after Dependabot merge lag.  
**Inject 2:** Public exploit released.  

**Discuss:** 24h SLA, emergency change, rollback, customer advisory.

### TT-003 — Database restore after ransomware on customer host

**Inject 1:** Customer reports encrypted volumes.  
**Inject 2:** Last backup is 18 hours old.  

**Discuss:** RTO/RPO, IR severity, key compromise assumptions, communications.

---

## 3. Timeline log (during exercise)

| Time | Inject / action | Decision | Owner |
| --- | --- | --- | --- |
| | | | |

---

## 4. Evaluation

| Question | Y/N / Notes |
| --- | --- |
| IR roles clear? | |
| Severity correctly assigned? | |
| Evidence preservation considered? | |
| Comms path clear? | |
| Technical controls sufficient? | |
| Gaps for POA&M? | |

---

## 5. Action items

| # | Action | POA&M ID | Due |
| --- | --- | --- | --- |
| | | | |

---

## 6. Sign-off

| Role | Name | Date |
| --- | --- | --- |
| Facilitator | | |
| Security Lead | | |

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial tabletop template + scenarios |
