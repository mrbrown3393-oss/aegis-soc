# Aegis SOC — Secret Rotation Runbook

**Document version**: 1.0  
**Owner**: Security Engineering  
**Related:** `docs/CRYPTO_AND_SUPPLY_CHAIN.md` · production fail-closed settings

---

## 1. Secrets in scope

| Secret | Impact of rotation | Downtime risk |
| --- | --- | --- |
| `JWT_SECRET` | Invalidates existing access/refresh tokens | Low–medium (forced re-login) |
| `MFA_MASTER_SECRET` | Changes derived TOTP secrets — **coordinate carefully** | High if done wrong |
| MongoDB credentials | App reconnect | Medium |
| TLS certificates | Edge/Mongo TLS | Medium |
| WiredTiger encryption key | **Do not rotate casually** — requires re-encrypt procedure | High |
| Operator bootstrap passwords | Account access | Low |

---

## 2. JWT_SECRET rotation (standard)

**Goal:** Replace signing key; force new sessions.

1. Schedule window; notify operators.  
2. Generate new secret (≥32 cryptographically random bytes, hex or base64).  
3. Store in secret manager as new version.  
4. Deploy app with new `JWT_SECRET`.  
5. Revoke all rows in `auth_sessions` (or rely on invalid signature + re-login).  
6. Verify login + MFA + API calls.  
7. Confirm old tokens fail.  
8. Record rotation in audit / change ticket.  

**PLANNED improvement:** dual-active keys (accept previous + current) to avoid hard cutover.

---

## 3. MFA_MASTER_SECRET rotation (high caution)

Derived per-user TOTP secrets depend on this value.

1. Prefer **user re-enrollment** flow over silent rotation.  
2. If rotation required: maintenance window; communicate MFA reset.  
3. Deploy new master secret.  
4. Invalidate MFA state; force re-bind TOTP.  
5. Verify each privileged account.  

Do **not** rotate MFA master in production without a tested re-enrollment path.

---

## 4. MongoDB credentials

1. Create new DB user with least privilege.  
2. Update secret manager URI.  
3. Rolling restart API.  
4. Disable old DB user after success.  

---

## 5. TLS certificates

Follow CSP/cert-manager procedure; verify ingress and Mongo client trust stores.

---

## 6. Rotation record

| Date | Secret class | Operator | Ticket | Result |
| --- | --- | --- | --- | --- |
| | | | | **No production rotation logged yet** |

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial runbook |
