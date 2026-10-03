# Incident Response Policy

| | |
|---|---|
| Document ID | AEG-IR-001 |
| Version | 1.0 |
| Parent Policy | AEG-ISP-000 |

## 1. Policy Statements

1. All security incidents affecting the Aegis SOC platform or its tenants SHALL be handled under `docs/incident-response-plan.md`.
2. Incidents are classified by severity (SEV-1 critical through SEV-4 informational) using the matrix in the IR Plan; classification drives response times and communication obligations.
3. A named Incident Commander is assigned for every SEV-1/SEV-2 incident.
4. Containment actions — including automated quarantine of assets, IPs, and accounts (`backend/security/quarantine.py`) — are pre-authorized for confirmed high-confidence threats, with mandatory human review within 1 hour.
5. Evidence SHALL be preserved with chain of custody before destructive remediation: audit logs, threat records, memory/disk captures where applicable.
6. All incidents are audit-logged end-to-end; post-incident reviews (blameless) are mandatory for SEV-1/SEV-2 within 5 business days.
7. Tenant notification: affected tenants are notified within 24 h for confirmed data-affecting incidents, or faster where law/contract requires.
8. The IR Plan is tested at least twice per year via tabletop exercise and once per year via a live simulation; findings feed the risk register.
9. Threat tracing activities operate in low-observability mode (passive collection, no attacker-visible artifacts) as defined in `backend/security/threat_tracer.py`, to avoid tipping off an active adversary during investigation.
