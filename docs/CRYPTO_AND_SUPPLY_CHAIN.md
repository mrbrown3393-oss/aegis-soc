# Aegis SOC — Cryptographic Inventory & External Supply Chain Register

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> Supports SC-12, SC-13, SC-28, SR-3, SR-4 diligence. **No FIPS 140 validation is claimed** for modules in the default stack.

**Related:** `docs/FEDRAMP_CRM_AND_PARAMETERS.md` · `ops/mongodb/` · `.github/workflows/security.yml`

---

## Part A — Cryptographic inventory

### A.1 Algorithms & protocols in use

| Purpose | Mechanism | Library / component | Key / secret handling | FIPS 140 status |
| --- | --- | --- | --- | --- |
| Transport (browser ↔ ingress) | TLS 1.2+ (1.3 preferred) | Ingress / CSP TLS stack | Certs at edge (Customer/CSP) | **Inherited** from CSP module; not asserted here |
| HSTS | HTTP Strict Transport Security | App middleware + ingress annotations | N/A | N/A (policy header) |
| Transport (API ↔ MongoDB) | TLS (`MONGO_TLS`) | Motor / MongoDB driver | CA/cert paths via env | Depends on MongoDB/OpenSSL build on host |
| Password hashing | bcrypt cost factor **12** | `bcrypt` Python package | Per-password salt; hash only stored | **Not claimed** as FIPS |
| Access token | JWT **HS256** | PyJWT | `JWT_SECRET` from env (≥32 chars in prod) | **Not claimed** as FIPS |
| Refresh token | JWT **HS256** | PyJWT | Same secret; server-side session bind | **Not claimed** as FIPS |
| MFA pending token | JWT **HS256**, 5m TTL | PyJWT | Same | **Not claimed** as FIPS |
| TOTP MFA | HMAC-SHA1 based TOTP (RFC 6238 style) | Custom helpers in `server.py` | `MFA_MASTER_SECRET` derives per-user secret | **Not claimed** as FIPS |
| CSRF defense | Origin/Referer allow-list (not a MAC) | Middleware | N/A | N/A |
| Encryption at rest | MongoDB **WiredTiger** encryption | `mongod` + `ops/mongodb` config | **Key in secret manager; never in Git** | Depends on MongoDB build / host |
| SBOM / hashes in CI | Tooling digests | CycloneDX, Trivy, etc. | CI identity | N/A |

### A.2 Secrets inventory (classes)

| Secret class | Examples | Storage | Rotation |
| --- | --- | --- | --- |
| Application signing | `JWT_SECRET`, `MFA_MASTER_SECRET` | Env / secret manager | **PLANNED** formal rotation runbook; two-active JWT keys planned |
| Operator passwords | Admin/analyst bootstrap | Env at deploy; bcrypt at rest in DB | On compromise / offboarding |
| Database | `MONGO_URL` credentials | Secret manager | Customer/CSP policy |
| TLS material | Ingress certs, Mongo CA/client certs | Secret mounts | Customer/CSP |
| At-rest DB key | WiredTiger key file | Secret manager | Customer/CSP; test on restore |

### A.3 Production cryptographic policy (enforced)

From `validate_security_settings()` when `AEGIS_ENV=production`:

- Strong `JWT_SECRET` (not default, length ≥ 32)  
- `MFA_REQUIRED=true` and strong `MFA_MASTER_SECRET`  
- `MONGO_TLS=true`  
- `MONGO_TLS_ALLOW_INVALID_CERTS=false`  
- HTTPS `FRONTEND_URL`  
- No wildcard CORS  

### A.4 Gaps / POA&M alignment

| Gap | Control | Plan |
| --- | --- | --- |
| FIPS 140 validated modules | SC-13 | Planned for agency paths requiring FIPS |
| JWT key rotation (two-active keys) | SC-12 | Planned |
| PIV / smart card | IA-2(12) | Planned |
| WebAuthn | IA-2 | Planned |
| mTLS API ↔ Mongo | SC-8 / SC-13 | Optional hardening |

---

## Part B — External services & supply chain register

### B.1 Register

| Service / supplier | Purpose | Data shared | Trust tier | Notes |
| --- | --- | --- | --- | --- |
| **GitHub** | Source control, PRs, Actions | Source code, CI logs, workflow identities | High | Enable branch protection; restrict secrets |
| **GitHub Actions runners** | Build, test, scan | Repo checkout, SBOM artifacts | High | `security.yml`, `ci.yml` |
| **PyPI** | Python dependencies | Package downloads | Medium | Pinned/audited via pip-audit |
| **npm registry** | Frontend dependencies | Package downloads | Medium | npm audit in CI |
| **MongoDB** (software) | Datastore | All application data at rest | High | TLS + encryption config; operator is Customer/CSP |
| **Hosting CSP** (AWS/GCP/Azure/other) | Compute, network, optional managed DB | Runtime data, backups, logs | High | PE/edge inherited; use CSP FedRAMP package when applicable |
| **DNS / TLS CA** | Name resolution, certificates | Public names, cert requests | Medium | Customer/CSP |
| **Identity provider** (future Okta/Azure AD/etc.) | SSO | Auth assertions, emails | High | Routes fail-closed until configured |
| **Email provider** (if used for reset/notify) | Notifications | Email addresses, reset context | Medium | Not fully specified in core repo |
| **Container registries** (if used) | Image distribution | Images | Medium | Cosign signing planned |

### B.2 Software supply chain controls (current)

| Control | Implementation |
| --- | --- |
| Dependency updates | Weekly Dependabot (pip + npm) |
| Advisory scan | pip-audit, npm audit (high+) |
| Secret scan | Gitleaks on push/PR/schedule |
| Vulnerability scan | Trivy fs; fails on CRITICAL/HIGH |
| Provenance artifact | CycloneDX SBOM (Python + Node) uploaded as CI artifacts |
| Patch SLAs | Policy pack: 24h / 7d / 30d / 90d |

### B.3 Supplier assurance (planned)

| Activity | Status |
| --- | --- |
| Formal vendor risk reviews | **PLANNED** |
| Contractual security flow-downs | **PLANNED** per customer contract |
| Prefer FedRAMP-authorized CSP for federal deployments | **Recommended** |
| Signed commits / signed images | **PLANNED** |

### B.4 Customer responsibilities (supply chain)

- Choose CSP and document inheritance  
- Consume SBOM for deployment inventory  
- Run runtime/host scanners beyond CI  
- Approve IdP and email integrations  
- Restrict who can access GitHub and secret stores  

---

## Part C — Explicit non-claims

1. **No FIPS 140-2/3 validation** is claimed for bcrypt, PyJWT, or default OpenSSL/Mongo builds.  
2. SBOM generation does not equal full SR program maturity.  
3. Third-party uptime or breach is outside Aegis’s sole control; CRM applies.

---

## Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial cryptographic inventory and external supply chain register. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`
