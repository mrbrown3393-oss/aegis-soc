# Security

This page describes controls present in the reviewed source. Deployment configuration, current CI results, and operational evidence are needed to evaluate an actual installation.

## Implemented controls

| Control | Current behavior |
| --- | --- |
| Password storage | Salted bcrypt hashes, cost 12 |
| Authentication cookies | `httpOnly`; production uses `Secure` and `SameSite=Strict` |
| MFA | TOTP; required by default; per-user secrets encrypted under the MFA master key |
| MFA challenge | Expiring, single-use pending challenge |
| Sessions | MongoDB-backed revocation, device-context binding, and 15-minute idle timeout |
| Token lifetime | Access 15 minutes; refresh 7 days |
| Refresh protection | Rotating refresh identifiers with replay handling |
| Step-up authentication | Enrolled TOTP; 10-minute token tied to session and device context |
| Authorization | Server-side role checks and owner-only cross-tenant queries |
| CSRF control | Allowed-origin/referer checks on mutations carrying auth cookies |
| Login protection | Five failed attempts trigger a 15-minute lockout for the IP/email key |
| Request limits | Authenticated limiter; additional MFA and reset protections |
| Audit | Application audit writes for actions including login, MFA verification, user changes, and incident updates |
| Database transport | TLS required by production startup validation |

Audit rows are append-oriented at the application layer. Database administrators can still alter stored records; this is not immutable/WORM evidence storage.

## Roles

| Role | Scope and representative permissions |
| --- | --- |
| `owner` | Cross-tenant reads and permitted privileged actions |
| `admin` | Own-tenant administration and permitted SOC mutations |
| `operator` | Own-tenant reads and telemetry fusion |
| `analyst` | Own-tenant triage, vulnerability-record updates, and quarantine requests |
| `viewer` | Protected read routes within its tenant |

Incident changes and user creation/removal require step-up authentication as well as the allowed role. Exact permissions are defined by each route, not by client menu visibility.

## Production startup gates

With `AEGIS_ENV=production`, `validate_security_settings()` rejects unsafe settings:

- The default JWT secret, or a JWT secret shorter than 32 characters.
- A configured previous JWT secret shorter than 32 characters.
- Default owner/analyst bootstrap passwords.
- Disabled MFA or an MFA master secret shorter than 32 characters.
- Disabled MongoDB TLS or acceptance of invalid MongoDB certificates.
- Wildcard or missing CORS origins, or a missing frontend origin.
- A frontend URL that does not use HTTPS.
- Incomplete or unsafe configuration for an enabled edge, OIDC, or SAML integration.

Use independently generated secrets. Meeting a length check alone does not establish secret strength.

## Deployment boundaries

Tenant isolation is logical/query-level. TLS termination, database authorization, storage encryption, network restrictions, backups, and evidence retention must be configured for the deployment.

Synthetic threat and compliance records are training content. Their scores do not establish risk or compliance for a customer environment. Quarantine requests need a separately validated enforcement path.

The reviewed backend does not provide the Grok/AI service referenced by the client. Treat that screen as an integration requiring backend work.

## Disclosure and evidence

Use the repository's [Security policy](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY.md) for the documented disclosure process. Keep credentials and sensitive customer evidence out of public wiki pages and issues.

- [Evidence catalog](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/EVIDENCE_CATALOG.md)
- [Security hardening guide](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY_HARDENING.md)
- [Deployment checklist](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/DEPLOYMENT_HARDENING_CHECKLIST.md)
- [Security errata](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY_ERRATA.md)
- [Security-focused tests](https://github.com/mrbrown3393-oss/aegis-soc/tree/main/tests)

Some older guides describe Motor, incomplete federation, a single JWT key, or derived MFA secrets. The current source uses PyMongo Async, includes configurable federation, accepts a previous JWT key, and stores encrypted per-user MFA secrets. Review the current implementation before executing an older runbook.

Source presence is not proof that CI, a penetration test, a restore drill, or a production deployment passed.
