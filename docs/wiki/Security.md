# Security

## Core Controls

- Passwords: bcrypt (cost 12), never stored in plaintext
- Tokens: JWT in `httpOnly` + `secure` + SameSite cookies
- CORS: explicit origins only (wildcard rejected in production)
- Unique index on `users.email`
- TTL indexes on reset tokens and login attempts
- Brute-force lockout (5 failures → 15 min)
- Every mutation written to append-only `audit_logs`
- Role gating enforced server-side

## Roles

| Role | Capabilities |
|------|--------------|
| `owner` | Full cross-tenant |
| `admin` | Tenant admin |
| `analyst` | Triage + patch |
| `viewer` | Read-only |

## Production Fail-Closed Checks

When `AEGIS_ENV=production` the application refuses to start if:

- JWT secret is weak/default
- Operator passwords are still default
- MongoDB TLS is disabled
- Invalid certificates are allowed
- CORS uses a wildcard
- Frontend origin is not HTTPS

## Further Reading

- [SECURITY_DOSSIER.md](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY_DOSSIER.md)
- [SECURITY.md](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY.md)
- [docs/ZERO_TRUST_ARCHITECTURE.md](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ZERO_TRUST_ARCHITECTURE.md)
- [docs/FEDRAMP_SECURITY_ARCHITECTURE.md](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/FEDRAMP_SECURITY_ARCHITECTURE.md)
