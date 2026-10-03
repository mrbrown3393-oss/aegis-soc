# Access Control Policy

| | |
|---|---|
| Document ID | AEG-AC-001 |
| Version | 1.0 |
| Parent Policy | AEG-ISP-000 |

## 1. Policy Statements

### 1.1 Least Privilege and RBAC
- Four roles exist: `owner`, `admin`, `analyst`, `viewer`. Permissions beyond read access are granted only to `owner`/`admin` where required.
- New registrations default to `viewer` in the `private` tenant. Elevated roles are granted only via invitation by `owner`/`admin` (`POST /api/users`).
- Access reviews are performed quarterly; dormant accounts (>90 days) are disabled.

### 1.2 Authentication
- Passwords are hashed with bcrypt at cost factor 12 with per-password salt. Plaintext passwords are never stored or logged.
- Minimum password length is enforced at the schema level and SHALL be raised to 12+ with complexity for production tenants.
- Sessions use short-lived JWT access tokens (12 h) with refresh tokens (7 d) in httpOnly, Secure, SameSite cookies.
- Brute-force protection: 5 failed attempts per `{ip}:{email}` triggers a 15-minute lockout.
- Federated SSO via SAML 2.0 and OIDC is the REQUIRED authentication method for production enterprise tenants (see `docs/sso-setup.md`). Local password login is a break-glass fallback, restricted to `owner`/`admin` and fully audit-logged.
- MFA SHALL be enforced at the IdP for all federated accounts.

### 1.3 Authorization and Tenant Isolation
- Every request is authorized server-side; `tenant_filter()` hard-scopes non-privileged users to their own tenant.
- Cross-tenant visibility is restricted to `owner`/`admin`.
- Database-level tenant isolation is a tracked roadmap item; until delivered, query-level isolation is verified by automated tests.

### 1.4 Zero Trust Access
- Trust is never implied by network location. Every request carries verifiable identity, is checked against role and tenant, and is subject to continuous verification (token freshness, device posture, session risk) per the Policy Enforcement Point in `backend/zerotrust/pep.py`.
- Administrative actions (user invite/delete, quarantine release) require a recent authentication (<15 min) per the step-up rule in the PEP.

### 1.5 Account Lifecycle
- Joiner: account created via invitation with minimum necessary role; manager approval recorded in the audit log.
- Mover: role changes take effect on next token refresh; prior sessions are invalidated.
- Leaver: account disabled within 1 business hour of notice; refresh tokens revoked; audit retained per retention schedule.

### 1.6 Secrets and Service Access
- Service-to-database access uses dedicated least-privilege MongoDB roles over TLS with X.509 or SCRAM credentials stored in the secrets manager.
- API keys (e.g., XAI_API_KEY) are environment-injected, never committed, and rotated at least annually or on suspicion of exposure.
