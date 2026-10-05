# Troubleshooting

These entries are based on the reviewed source and are not claims that a runtime integration test has passed.

## Startup and authentication

| Symptom | Check and resolution |
| --- | --- |
| API cannot connect to a plain local MongoDB | The example defaults to `MONGO_TLS=true`. Use `MONGO_TLS=false` only for an isolated development database, or configure MongoDB TLS correctly. |
| `.env` values appear ignored | Start from `backend/`; `Settings` loads `.env` relative to the working directory. |
| Production exits before startup | Read the explicit configuration error and satisfy [Deployment](Deployment.md) settings. |
| Password login returns success but resources return 401 | Default MFA login creates a pending challenge. Complete setup if needed and verify TOTP before requesting a protected resource. |
| Authenticated mutation returns 403 | Supply an `Origin` or `Referer` matching configured origins; keep host, scheme, and port consistent. Also check role and tenant permission. |
| Incident or user mutation requires step-up | Call `POST /api/auth/step-up` with an enrolled TOTP code and retain the returned cookie. |
| Session stops working after a client switch | Device-context headers changed, the session was revoked, an idle timeout elapsed, or refresh replay was detected. Sign in again using a consistent client. |
| Admin requests `tenant=all` but sees one tenant | Only the owner may query across tenants. |
| Bootstrap password change has no effect | Existing users are not reseeded. Environment bootstrap passwords are not an account-update API. |
| Reset endpoint says an email was sent but none arrives | The current request handler does not send email. Connect and verify a reset-delivery flow before relying on this feature. |

## Development ports

The existing Vite proxy sends `/api` to `http://localhost:3000`. The [Getting Started](Getting-Started.md) guide therefore runs FastAPI on port 3000 and the client on 5173.

If using the older README's backend port 8001, update the API proxy target. Also set `FRONTEND_URL` and `CORS_ORIGINS` to the actual browser origin.

## Client/API differences requiring integration work

The frontend at [client/src/lib/api.ts](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/client/src/lib/api.ts) expects several contracts that differ from the FastAPI backend:

| Client expectation | Reviewed backend |
| --- | --- |
| `GET /api/dashboard/overview` | Metrics are at `GET /api/metrics/overview`, with a different response shape |
| `GET /api/dashboard/health` | Service health is `GET /api/` |
| `GET /api/alerts` and alert update paths | Threat list is `GET /api/threats`; no equivalent alert-update router |
| List result `{data, total}` | Core resource list routes return arrays |
| Login and MFA result `{user: ...}` | Auth returns account-summary fields; full user comes from `GET /api/auth/me` |
| `/api/assets/identities`, `/api/assets/credentials`, `/api/assets/policies` | No matching routes in the reviewed backend |
| `/api/threat/intel`, `/api/threat/events`, `/api/threat/audit` | Available related routes include `/api/threats` and `/api/audit-logs`; contracts need explicit mapping |
| `/api/ai/chat`, `/api/ai/analyze/alert/{id}`, `/api/ai/status` | No corresponding AI routes registered |
| Error field `error` | FastAPI handlers usually return `detail` |

A port change resolves the proxy destination only. Resolve paths, data models, auth response handling, and errors before claiming that all console screens work with this backend.

## Data interpretation

- Seeded scores and records are synthetic training data.
- `/api/threats/live` inserts a simulated event.
- A vulnerability marked patched is a changed database record.
- A quarantine request is recorded intent; verify real enforcement separately.
- Compliance records do not establish an assessment or certification.

## Older documentation

Where older guides disagree with code, use the current module and tests:

| Older reference | Current implementation |
| --- | --- |
| Motor database client | `backend/database.py` imports `pymongo.AsyncMongoClient` |
| All backend behavior in `server.py` | Modular `backend/routers/`, helpers, and dependencies |
| Admin may cross tenants | `tenant_filter()` permits owner-only cross-tenant scope |
| MFA secret derived per user | Randomized per-user secret stored in encrypted `mfa_secret_enc` |
| JWT previous-key support is only planned | Helpers support `JWT_PREVIOUS_SECRET` |
| All federation code is unavailable | OIDC/SAML code exists and requires complete provider configuration and verification |

Use [Security](Security.md), [API Reference](API-Reference.md), and the [evidence catalog](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/EVIDENCE_CATALOG.md) to track the current implementation.
