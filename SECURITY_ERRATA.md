# Aegis SOC — Security Documentation Errata

**Date**: 2026-10-04 · **Applies to**: `SECURITY_DOSSIER.md` v1.1 body text

## Backend modularization (2026-10-04)

The FastAPI backend was split from a monolithic `server.py` into:

| Module | Responsibility |
| --- | --- |
| `backend/config.py` | Settings, production fail-closed validation |
| `backend/database.py` | Mongo client |
| `backend/auth_helpers.py` | Password, JWT, MFA, sessions, lockouts |
| `backend/deps.py` | `get_current_user`, `require_role`, `tenant_filter`, `write_audit` |
| `backend/seed.py` | Indexes + demo data |
| `backend/routers/*` | Route handlers |
| `backend/server.py` | App entrypoint, middleware, router wiring |

**Authoritative evidence map**: [`docs/EVIDENCE_CATALOG.md`](docs/EVIDENCE_CATALOG.md)

Inline references in `SECURITY_DOSSIER.md` §3 and §9 that still say `server.py → hash_password()` (etc.) should be read as the paths in the Evidence Catalog. Control **status** claims are unchanged; only file locations moved.

## Hardening guide

`SECURITY_HARDENING.md` is now an operational checklist (not release notes). Use it with `docs/ops/DEPLOYMENT_HARDENING_CHECKLIST.md` before production go-live.
