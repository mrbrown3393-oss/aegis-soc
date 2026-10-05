# API Reference

This page describes the routes registered by the FastAPI backend at commit [2049bdeb](https://github.com/mrbrown3393-oss/aegis-soc/commit/2049bdeb8a96e8f91d3ca55d4534096650f813e2). Paths below include the full `/api` prefix.

## Request rules

- Authentication uses cookies, rather than a bearer-token API contract.
- Preserve cookies across password login, MFA verification, and later requests.
- Cookie-authenticated `POST`, `PUT`, `PATCH`, and `DELETE` requests need an allowed `Origin` or `Referer`.
- Keep device headers consistent across a session.
- `tenant=all` expands scope only for the owner.
- Errors usually use FastAPI's `detail` field.
- Resource list routes return JSON arrays, rather than `{data, total}` envelopes.
- Production disables `/docs` and `/redoc`; handle access to `/openapi.json` at ingress as appropriate.

## Identity

| Method | Full path | Requirement | Behavior |
| --- | --- | --- | --- |
| GET | `/api/` | Public | Service health and version |
| POST | `/api/auth/register` | Development only | Creates a private-tenant viewer; returns a sign-in message |
| POST | `/api/auth/login` | Public | Password check; creates an MFA challenge when MFA is required |
| GET | `/api/auth/mfa/setup` | Pending MFA cookie | First-time TOTP enrollment; returns `secret` and `otpauth` |
| POST | `/api/auth/mfa/verify` | Pending MFA cookie and TOTP | Completes the challenge and issues access/refresh cookies |
| POST | `/api/auth/step-up` | Session and enrolled TOTP | Issues a 10-minute step-up cookie |
| GET | `/api/auth/me` | Session | Current user object |
| POST | `/api/auth/refresh` | Refresh cookie | Rotates refresh identifier and renews access |
| POST | `/api/auth/logout` | Session | Revokes session and clears auth cookies |
| POST | `/api/auth/password-reset/request` | Public; rate limited | Stores a hashed, expiring reset token for an existing account |
| POST | `/api/auth/password-reset/confirm` | Valid reset token | Changes password and revokes user sessions |

The password-reset request handler currently has no email-delivery integration. Its generic response is not evidence that a reset email was delivered.

### Authentication payloads

~~~json
{"email":"YOUR_EMAIL","password":"YOUR_PASSWORD"}
~~~

MFA verification and step-up use:

~~~json
{"code":"CURRENT_TOTP_CODE"}
~~~

After completed sign-in, the auth response contains fields such as `message`, `email`, `role`, and `tenant`. It does not contain a nested `user` object. Retrieve the full user through `GET /api/auth/me`.

Registration requires `email`, `password`, and `name`. Reset confirmation requires `token` and `new_password`. New passwords accepted by the shared request models must contain 12–72 characters and must also fit within 72 UTF-8 bytes.

## SOC resources

| Method | Full path | Requirement | Behavior |
| --- | --- | --- | --- |
| GET | `/api/metrics/overview` | Session | Counts, trend, and severity distribution; optional `tenant` |
| GET | `/api/threats` | Session | Optional `tenant`, `severity`, and `limit` (1–100; default 50) |
| GET | `/api/threats/live` | owner/admin/analyst | Inserts and returns one synthetic threat record |
| GET | `/api/vulnerabilities` | Session | Optional `tenant`; sorted by CVSS |
| POST | `/api/vulnerabilities/{vuln_id}/patch` | owner/admin/analyst | Marks the database record as patched |
| GET | `/api/incidents` | Session | Optional `tenant`; newest first |
| PATCH | `/api/incidents/{incident_id}` | owner/admin/analyst plus step-up | Changes incident status |
| GET | `/api/assets` | Session | Optional `tenant`; sorted by risk score |
| GET | `/api/compliance` | Session | Optional `tenant`; stored framework records |
| GET | `/api/audit-logs` | Session | Optional `tenant` and `limit` (1–200; default 100) |
| GET | `/api/users` | owner/admin | Tenant-scoped user list |
| POST | `/api/users` | owner/admin plus step-up | Creates a user from the supplied identity, role, tenant, and password |
| DELETE | `/api/users/{user_id}` | owner/admin plus step-up | Removes an allowed user; owner accounts cannot be removed |

Marking a vulnerability record as patched does not install a patch on an endpoint. The user-create handler does not send an invitation email.

An incident update body is:

~~~json
{"status":"investigating"}
~~~

Allowed statuses are `new`, `investigating`, `contained`, and `resolved`.

A user-create body contains `email`, `name`, `role`, `tenant`, and `password`. Non-owner administrators cannot create users in another tenant or grant the owner role.

## Security analytics

| Method | Full path | Requirement | Behavior |
| --- | --- | --- | --- |
| POST | `/api/security/telemetry/fuse` | owner/admin/operator | Accepts telemetry points; stores inputs and returns centroid, spread, and anomaly score |
| POST | `/api/security/quarantine` | owner/admin/analyst | Records a quarantine request for an accessible asset |
| GET | `/api/security/quarantine` | Session | Lists tenant-scoped quarantine requests |

Each telemetry point supplies `sensor_id`, `latitude`, `longitude`, `timestamp`, `signal_strength`, and `event_type`; `source_ip` is optional. A quarantine request supplies `asset_id`, `reason`, and `severity`, with optional `evidence_ids`.

## Federation

| Method | Full path | Behavior |
| --- | --- | --- |
| GET | `/api/auth/sso/config` | Federation availability/configuration summary |
| GET | `/api/auth/sso/oidc/login` | Starts configured OIDC authentication |
| GET | `/api/auth/sso/oidc/callback` | Processes OIDC callback |
| GET | `/api/auth/sso/saml/login` | Starts configured SAML authentication |
| POST | `/api/auth/sso/saml/acs` | Accepts the `SAMLResponse` form field |

OIDC and SAML are disabled in the example environment. Enable them only with complete provider, cryptographic validation, tenant-mapping, and production settings.

The React client's `/api/ai/*`, `/api/dashboard/*`, and several other paths have no corresponding routes in the reviewed backend. See [Troubleshooting](Troubleshooting.md).

Sources: [backend routers](https://github.com/mrbrown3393-oss/aegis-soc/tree/main/backend/routers), [request models](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/models.py), [security analytics](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/anomaly.py), [SSO](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/sso.py).
