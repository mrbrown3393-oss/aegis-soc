# Aegis SOC — Backup Restore Drill Runbook

**Document version**: 1.0  
**Owner**: Security Engineering + Deployment Owner  
**Related:** `docs/CONMON_AND_CONTINGENCY.md` · `ops/mongodb/`

> Execute in a **non-production** environment first. Record results in the completion section. An empty completion section means the drill has **not** been performed.

---

## 1. Preconditions

- [ ] Non-prod cluster or VM available  
- [ ] Recent backup identified (timestamp: ________)  
- [ ] Encryption keys / secret manager access for restore env  
- [ ] MongoDB tools version compatible with backup  
- [ ] Application image/tag to deploy documented  
- [ ] Stakeholders notified of drill window  

---

## 2. Procedure

### 2.1 Capture baseline (production or staging metrics — read-only)

| Metric | Value | Time (UTC) |
| --- | --- | --- |
| DB data size | | |
| Document counts (users / audit_logs sample) | | |
| App version / image digest | | |

### 2.2 Restore database

1. Provision empty MongoDB with TLS settings per `ops/mongodb/README.md`.  
2. Apply WiredTiger encryption key from secret manager (never copy prod key to laptops).  
3. Restore backup into non-prod URI.  
4. Verify `db.adminCommand({ getCmdLineOpts: 1 })` / encryption status as applicable.  
5. Confirm collections present: `users`, `auth_sessions`, `audit_logs`, tenant collections.  

Commands used (paste redacted):

```
# operator fills in
```

### 2.3 Restore application

1. Deploy API with non-prod env: strong secrets, `AEGIS_ENV` not production unless intentional.  
2. Point `MONGO_URL` at restored DB with TLS.  
3. Start API; confirm health `GET /api/`.  
4. Login as test admin; complete MFA if required.  
5. Read-only checks: metrics overview, audit log page, one tenant-scoped list.  
6. Write test: create benign audit-triggering action if safe; confirm log row.  

### 2.4 Timing

| Milestone | UTC clock | Elapsed |
| --- | --- | --- |
| Drill start | | 0 |
| DB restore complete | | |
| App healthy | | |
| Validation complete | | |
| **Measured RTO** | | |

Compare to target RTO in `docs/CONMON_AND_CONTINGENCY.md` (24–72h design target).

---

## 3. Validation checklist

- [ ] Admin login + MFA works  
- [ ] Session revoke/logout works  
- [ ] Tenant isolation still holds for non-owner user  
- [ ] Audit log readable  
- [ ] No production secrets left in drill env  
- [ ] Drill env scheduled for teardown  

---

## 4. Issues found

| # | Issue | Severity | POA&M ID |
| --- | --- | --- | --- |
| | | | |

---

## 5. Completion record

| Field | Value |
| --- | --- |
| Date (UTC) | **NOT EXECUTED** |
| Conducted by | |
| Environment | |
| Backup ID / timestamp | |
| Measured RTO | |
| Measured data loss vs RPO | |
| Pass / Fail | |
| Sign-off | |

---

## 6. Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial runbook |
