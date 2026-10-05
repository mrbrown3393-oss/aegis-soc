# Architecture

## Components and request flow

~~~mermaid
flowchart TD
    C["React client"] --> I["HTTPS ingress"]
    I --> A["FastAPI API"]
    I --> E["Optional admission edge"]
    E -->|"Signed admission decision"| I
    A --> D["MongoDB records and sessions"]
~~~

The ingress and admission edge are deployment components. Local development can connect to the API through Vite's proxy without either component. Enabling backend edge enforcement requires the ingress to supply valid decision headers.

| Component | Source | Responsibility |
| --- | --- | --- |
| React client | [client/](https://github.com/mrbrown3393-oss/aegis-soc/tree/main/client) | Browser console; Vite development server on port 5173 |
| App entry point | [backend/server.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/server.py) | Middleware, startup, and router registration |
| Configuration | [backend/config.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/config.py) | Environment settings and production startup validation |
| Database connection | [backend/database.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/database.py) | Native PyMongo Async MongoDB client |
| Authentication | [backend/auth_helpers.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/auth_helpers.py) and [auth router](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/routers/auth.py) | Passwords, JWTs, TOTP, sessions, and lockouts |
| Request authorization | [backend/deps.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/deps.py) | Current user, role checks, tenant filters, and audit writes |
| Session security | [backend/session_security.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/session_security.py) | Device-bound sessions and refresh rotation/replay handling |
| High-impact actions | [backend/step_up.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/step_up.py) | Session-bound TOTP step-up authentication |
| Federation | [backend/sso.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/sso.py) | Configurable OIDC and SAML authentication |
| Security analytics | [backend/anomaly.py](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/anomaly.py) | Telemetry fusion and quarantine-request records |
| Admission edge | [edge/](https://github.com/mrbrown3393-oss/aegis-soc/tree/main/edge) | Optional admission service and signed decisions |

## Authentication boundary

A protected API request requires an access cookie. The backend verifies the JWT and rechecks the server-side session and current user in MongoDB. Sessions carry a device-context fingerprint and support revocation and an idle timeout.

Access tokens last 15 minutes; refresh tokens last 7 days. Refresh requests rotate refresh identifiers and reject replay. In production, authentication cookies are `httpOnly`, `Secure`, and `SameSite=Strict`; development uses non-secure, `SameSite=Lax` cookies.

TOTP is required by default. Password login alone creates a pending MFA challenge; it does not create an authenticated session while MFA is enabled.

## Tenant boundary

Every tenant-scoped operational record uses `government`, `private`, or `saas`.

| Role | Query scope |
| --- | --- |
| `owner` | All tenants by default; can request an individual tenant |
| `admin`, `operator`, `analyst`, `viewer` | Their own tenant; a query parameter cannot expand that scope |

The implemented isolation is at the application query layer in one database. Separate tenant databases and stronger storage boundaries require additional deployment work.

## Data and integration boundary

MongoDB stores users, sessions, threats, vulnerabilities, incidents, assets, compliance records, audit rows, SSO state, and security analytics records. Startup creates indexes and synthetic training records.

The current React client and backend expose different contracts for several dashboard and SOC screens. See [Troubleshooting](Troubleshooting.md) for exact paths and response differences.

## Evidence

- [Zero Trust architecture](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ZERO_TRUST_ARCHITECTURE.md)
- [Remote security edge design](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/REMOTE_SECURITY_EDGE.md)
- [Evidence catalog](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/EVIDENCE_CATALOG.md)
- [Security errata](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY_ERRATA.md)

Older references to Motor or a monolithic backend are superseded by the current `database.py` and modular routers.
