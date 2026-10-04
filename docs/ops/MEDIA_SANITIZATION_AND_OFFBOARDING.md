# Aegis SOC — Media Sanitization & Tenant / Operator Offboarding

**Document version**: 1.0  
**Owner**: Security Engineering  
**Related controls:** MP-6, AC-2, AU-11, SC-28

---

## 1. Scope

Procedures for removing access and data when:

- An operator leaves  
- A tenant is decommissioned  
- Hardware/volumes holding Aegis data are retired  

Physical media is rare in cloud deployments; volume and snapshot lifecycle dominate.

---

## 2. Operator offboarding

1. Disable or delete user via API/UI (cannot delete `owner` without ownership transfer).  
2. `revoke_user_sessions` / confirm `auth_sessions` cleared.  
3. Remove IdP group assignment if SSO enabled.  
4. Rotate any shared automation secrets the user could access.  
5. Reassign open incidents/tickets.  
6. Log completion in change ticket; retain audit trail.  

Checklist:

- [ ] Account disabled/removed  
- [ ] Sessions revoked  
- [ ] IdP updated  
- [ ] Secrets rotated if exposed  
- [ ] Audit event verified  

---

## 3. Tenant decommission

1. Legal/customer approval for data deletion vs export.  
2. Export if contract requires (CSV/API).  
3. Delete tenant-scoped collections/documents (`tenant` field match).  
4. Verify no residual documents via count queries.  
5. Retain audit logs per AU retention policy / legal hold.  
6. Record destruction certificate (date, operator, method).  

**Note:** Logical multi-tenant DB requires careful queries; Phase 2+ DB-per-tenant simplifies destruction.

---

## 4. Volume / snapshot sanitization (cloud)

| Asset | Method | Verification |
| --- | --- | --- |
| Encrypt-at-rest volume | Crypto-erase by deleting key (if unique) **or** provider volume delete | Key destruction record / console evidence |
| Snapshot | Delete snapshots; confirm lifecycle policy | Console list empty |
| Backup object | Delete objects; versioning purge if needed | Bucket listing |
| VM disk reallocated | Rely on CSP sanitization baseline | CSP policy reference |

Prefer **cryptographic erasure** when WiredTiger/customer keys are unique per deployment.

---

## 5. Workstation / admin laptop

- Full-disk encryption required for admin workstations.  
- On role end: wipe or reimage; revoke VPN/ZTNA; collect hardware if company-owned.  

---

## 6. Record template

| Field | Value |
| --- | --- |
| Asset / tenant / user | |
| Action | offboard / delete / crypto-erase |
| Date UTC | |
| Performed by | |
| Method | |
| Verification | |
| Ticket | |

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial procedure |
