# Backup, Recovery & Restoration Drills Policy

| | |
|---|---|
| Document ID | AEG-BR-001 |
| Version | 1.0 |
| Parent Policy | AEG-ISP-000 |

## 1. Backup Requirements

- **Scope**: all MongoDB databases (users, threats, incidents, vulnerabilities, assets, compliance, audit_logs), configuration, and TLS/key material inventory.
- **Frequency**: full backup daily; oplog/point-in-time capture where the deployment supports it.
- **Protection**: backups encrypted (AES-256) and stored in a separate fault domain; access restricted to admin role; integrity checksum (SHA-256) recorded per backup.
- **Retention**: 30 daily, 12 monthly, 7 yearly copies unless contract requires more.
- **RPO**: ≤ 24 h (≤ 15 min with point-in-time). **RTO**: ≤ 4 h.

## 2. Restoration Drills (mandatory)

- **Quarterly full restoration drill** into an isolated environment using `scripts/backup/restore_drill.sh`; results recorded in the drill log (`docs/backup-restore-drills.md`).
- **Monthly spot check**: restore a single collection and verify document counts and checksums.
- A drill is PASSED only when: restore completes within RTO, checksums match, application health check passes against restored data, and tenant isolation queries return expected scoping.
- Failed drills open a SEV-3 incident and a corrective action with owner and due date.
- The quarterly drill is scheduled automatically by `.github/workflows/drill-reminder.yml`, which opens a tracking issue each quarter.
