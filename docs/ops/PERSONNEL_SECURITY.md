# Aegis SOC — Personnel Security Procedures

**Document version**: 1.0  
**Owner**: William Brown (sole operator today)  
**Related controls:** PS-1 through PS-8 (scaled to organization size)

> Scaled for a sole-owner product. Expand on first hire.

---

## 1. Roles requiring elevated trust

| Role | Trust level | Screening (minimum) |
| --- | --- | --- |
| Owner | Highest | Identity known; sole authority today |
| Privileged operator (admin) | High | Identity verification; customer may require additional checks |
| Analyst | Medium | Customer employment screening |
| Viewer | Standard | Customer employment screening |

Aegis does not replace **customer** employee screening for customer-tenant operators.

---

## 2. Joiner

1. Business need for account.  
2. Least-privilege role assignment.  
3. MFA enrollment before privileged data access.  
4. Rules of Behavior acknowledgment.  
5. Add to IR contact list if on-call.  

---

## 3. Mover

1. Re-evaluate role on job change.  
2. Remove entitlements same day.  
3. Audit privileged actions during transition if warranted.  

---

## 4. Leaver

Follow `docs/ops/MEDIA_SANITIZATION_AND_OFFBOARDING.md` operator offboarding same day as separation notice when possible.

---

## 5. Sanctions / violations

Violations of Rules of Behavior or security policy: suspend access pending review; document outcome; escalate criminal matters to appropriate authorities.

---

## 6. External personnel

Contractors and 3PAOs:

- Time-bounded accounts  
- NDA before source or tenant data access  
- No standing prod admin without ticket  

---

## 7. First-hire expansion checklist

- [ ] Written PS policy approved  
- [ ] Background check vendor selected (if required by customers)  
- [ ] Access agreement template  
- [ ] Training tracker  

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial sole-operator scaled procedures |
