# Deployment

Deploy a reviewed application revision with environment-specific secrets, TLS, database access controls, and operational checks. This wiki is a deployment guide, not a record of an already completed production deployment.

## Configuration baseline

| Setting | Production requirement |
| --- | --- |
| `AEGIS_ENV` | `production` |
| `JWT_SECRET` | Independent, cryptographically random secret; at least 32 characters |
| `JWT_PREVIOUS_SECRET` | Empty, or an intentionally managed previous key of at least 32 characters |
| `ADMIN_PASSWORD` / `ANALYST_PASSWORD` | Private non-default bootstrap passwords |
| `MFA_REQUIRED` | `true` |
| `MFA_MASTER_SECRET` | Independent random secret; at least 32 characters |
| `MONGO_URL` / `DB_NAME` | Intended deployment database, with least-privilege database credentials |
| `MONGO_TLS` | `true` |
| `MONGO_TLS_ALLOW_INVALID_CERTS` | `false` |
| `MONGO_TLS_CA_FILE` | Mounted CA trust file when required |
| `MONGO_TLS_CERT_KEY_FILE` | Mounted client certificate/key when required |
| `FRONTEND_URL` | Exact HTTPS browser origin |
| `CORS_ORIGINS` | Explicit browser-origin allowlist; no wildcard |
| `TRUSTED_PROXY_IPS` | Only the reverse proxies that actually forward client addresses |

Use a secret manager or protected runtime configuration. Bootstrap environment values seed accounts only when the user collection is empty; editing a bootstrap password does not change an existing account's password.

## Application and ingress

1. Resolve the client/API differences on [Troubleshooting](Troubleshooting.md) and retain evidence of complete login, MFA, resource reads, and authorized mutations.
2. Deploy the API under a supervised service or container process without `--reload`.
3. Build the React client using `npm run build` in `client/`; serve `client/dist/` through the frontend ingress.
4. Route `/api` to FastAPI. Production does not use Vite's development proxy.
5. Configure HTTPS, security headers, trusted forwarding, and network restrictions. A shared frontend/API origin simplifies cookie routing.
6. Restrict MongoDB to the application and approved operators. Configure storage encryption through the chosen database service/deployment.
7. Define backup, log shipping, alerting, and owner recovery procedures.

Interactive `/docs` and `/redoc` routes are disabled in production. The default schema route remains `/openapi.json`; apply the intended ingress policy to it.

## Optional admission edge

When enabling `EDGE_ENFORCE_DECISION`, provision `EDGE_VERIFY_SECRET`, `EDGE_INGRESS_TOKEN`, `EDGE_AUDIENCE`, and the ingress decision-header path. Production validates key/token length and audience presence.

The backend must receive decisions bound to the request's method, path, and client address. Prevent a direct path around the ingress when relying on edge admission.

Use the [remote edge guide](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/REMOTE_SECURITY_EDGE.md) and [Nginx template](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/ops/ingress/nginx-edge.template.conf) as configuration references; validate them for the actual network.

## Optional federation

OIDC and SAML are off in `.env.example`. Configure only the provider being used, including HTTPS callbacks, issuer/entity identity, cryptographic keys/certificates, tenant allowlists, and role mapping.

Production rejects incomplete enabled federation settings and unreviewed email-linking configurations. Verify acceptance and rejection cases with the chosen provider before use.

## Release verification

Record the deployed commit/artifact and verify:

- Health response and intended network exposure.
- Owner sign-in, TOTP enrollment, logout, refresh, and revocation.
- Non-owner tenant scope and rejected role escalation.
- Step-up requirements for user changes and incident updates.
- Audit rows for the tested actions.
- Database TLS, valid certificate handling, storage encryption, and backup restoration.
- Current CI/security results and review of unresolved findings.
- Clear separation of synthetic training data from real customer evidence.

Startup currently calls the demo seeder even in production. If the intended deployment must not contain training data, resolve that startup behavior before go-live; a mode switch alone does not disable it.

References: [production checks](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/config.py), [startup seeder](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/backend/seed.py), [deployment hardening checklist](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/DEPLOYMENT_HARDENING_CHECKLIST.md), [MongoDB operations](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/ops/mongodb/README.md).
