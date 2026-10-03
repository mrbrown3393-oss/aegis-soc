# Aegis SOC

> **A sovereign Security Operations Center platform — operated by signal.**
> Owned by **William Brown**. Ready to sell, rent, or license.
>
> **Stack: FastAPI + MongoDB + React (CRA).** This repository contains the
> production-shaped FastAPI backend described in `SECURITY_DOSSIER.md`.
> The previous Node/Express build has been replaced.

![Status](https://img.shields.io/badge/status-operational-10b981)![Version](https://img.shields.io/badge/version-2.1.0-22d3ee)![License](https://img.shields.io/badge/license-Commercial-f59e0b)![Owner](https://img.shields.io/badge/owner-William%20Brown-60a5fa)

---

## What Is Aegis SOC

Aegis SOC is a modular, enterprise-grade cybersecurity platform that unifies threat detection, incident response, vulnerability management, asset intelligence, continuous compliance, and immutable audit — in a single multi-tenant console with three sovereign deployment postures: **Government**, **Private Sector**, and **SaaS**.

- **Operator-first.** Dense, high-signal UI designed for tier-1 analysts.
- **Tenant-isolated.** Three distinct visual + logical tenants — switch at the sidebar, every query is scoped.
- **Commercially flexible.** Sell outright, rent monthly, or license to government.
- **Automatable.** Every endpoint prefixed `/api`; cookies are httpOnly; JWT is standard.

## Deployment Modes

### 1. Government
- **Vibe**: authoritative navy / steel · Accent: `#60a5fa`
- **Compliance baseline**: FedRAMP Moderate · CMMC Level 2 · FIPS 140-3 · STIG-hardened
- **Suited for**: federal agencies, state/local government, defense primes, intelligence community

### 2. Private Sector
- **Vibe**: corporate warm / amber · Accent: `#f5b041`
- **Compliance baseline**: SOC 2 Type II · ISO 27001:2022 · PCI-DSS 4.0 · HIPAA
- **Suited for**: Fortune 500 security teams, regulated financial / healthcare, growing enterprises

### 3. SaaS Platform
- **Vibe**: modern sharp / cyan · Accent: `#22d3ee`
- **Capabilities**: multi-tenant isolation · white-label · usage billing · API-first
- **Suited for**: MSSPs, security product companies, agencies reselling SOC-as-a-Service

## Feature Modules

| # | Module | What it does |
| --- | --- | --- |
| 1 | **Overview** | Portfolio KPIs, 7-day trend, severity donut, live threat tape, active incidents |
| 2 | **Threats** | Correlated SIEM-style events with severity, geo, confidence, source IP, affected asset |
| 3 | **Vulnerabilities** | Real CVE catalog with CVSS 3.1 scores, patch-tracking per asset |
| 4 | **Incidents** | Incident tickets with kill-chain phase, assignee, 4-step status workflow |
| 5 | **Compliance** | Continuous control monitoring across NIST 800-53, ISO 27001, SOC 2, HIPAA, FedRAMP, PCI-DSS 4.0, CMMC L2 |
| 6 | **Assets** | Discovered endpoints, servers, firewalls, routers, DBs with per-asset risk score |
| 7 | **Users** | Operators & RBAC — invite, assign role, remove |
| 8 | **Audit Logs** | Immutable action trail with CSV export |

## Architecture

```
React 19 Frontend (CRA)  --axios, httpOnly JWT cookies-->  FastAPI Backend (/api/*)
                                                              |
                                                              v
                                                         MongoDB
                                                    users · threats · vulns
                                                    incidents · assets
                                                    compliance · audit_logs
                                                    login_attempts (TTL)
```

- **Auth**: Access JWT (12h) + refresh JWT (7d) in `secure`, `httpOnly`, `samesite=none` cookies.
- **Password hashing**: `bcrypt` (cost 12).
- **Brute-force protection**: 5 failed attempts per `{ip}:{email}` triggers a 15-min lockout.
- **Audit**: Every mutating action is appended to `audit_logs` with actor, IP, resource, and tenant.
- **Mock data seeder**: Idempotent — runs once on startup and skips if data already exists.

## Tech Stack

### Backend
- **FastAPI 0.110** — async, OpenAPI-generated routes
- **Motor 3.3** — async MongoDB driver
- **PyJWT 2.10** · **bcrypt 4.1**
- **Pydantic v2** — strict validation
- **Starlette CORS** — origin-whitelisted, credentials-enabled

### Frontend
- **React 19** · **React Router 7** · **CRACO**
- **Tailwind CSS 3.4** · **Shadcn UI** (Radix primitives)
- **Recharts 3** · **framer-motion 11** · **lucide-react** · **sonner** · **axios**

### Typography
- **Chivo** — headings · **IBM Plex Sans** — body · **IBM Plex Mono** — data/logs

## Repository Layout

```
/app
├── backend/
│   ├── server.py              # All routes, auth, seeder (~850 LOC)
│   ├── requirements.txt
│   └── .env.example
├── frontend/                  # React 19 (CRA) — see README in BS Code env
├── memory/
└── README.md                  # ← you are here
```

## Getting Started

### Prerequisites

- Python 3.11+
- MongoDB 6+
- A modern browser

### Local Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # edit secrets
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

### Verify

```bash
curl http://localhost:8001/api/
curl -c c.txt -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"william.brown@aegis-soc.io","password":"AegisOwner2025!"}'
curl -b c.txt "http://localhost:8001/api/metrics/overview?tenant=all"
```

## Environment Variables

See `backend/.env.example`. All secrets load from environment — never hardcoded.

## Default Credentials (DEMO ONLY — rotate before any non-demo deployment)

| Role | Email | Password | Tenant |
| --- | --- | --- | --- |
| **Owner** | `william.brown@aegis-soc.io` | `AegisOwner2025!` | `saas` (sees all) |
| Analyst | `analyst@aegis-soc.io` | `Analyst2025!` | `government` |

## API Reference

All endpoints prefixed `/api`.

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/` | public | Health check |
| `POST` | `/auth/register` | public | Register viewer, sets cookies |
| `POST` | `/auth/login` | public | Login, sets access + refresh cookies |
| `POST` | `/auth/logout` | required | Clears cookies, writes audit |
| `GET` | `/auth/me` | required | Current user |
| `POST` | `/auth/refresh` | refresh cookie | New access token |
| `POST` | `/auth/password-reset/request` | public | Single-use reset token + TTL |
| `POST` | `/auth/password-reset/confirm` | public | Consume token, re-hash password |
| `GET` | `/metrics/overview?tenant=` | required | KPIs, severity dist, 7-day trend |
| `GET` | `/threats?limit=&severity=&tenant=` | required | List threats |
| `GET` | `/threats/live` | required | Simulates & inserts a live threat |
| `GET` | `/vulnerabilities?tenant=` | required | Sorted by CVSS desc |
| `POST` | `/vulnerabilities/{id}/patch` | required | Mark as patched |
| `GET` | `/incidents?tenant=` | required | Incident tickets |
| `PATCH` | `/incidents/{id}` | required | Body `{status}` |
| `GET` | `/assets?tenant=` | required | Assets sorted by risk |
| `GET` | `/compliance?tenant=` | required | Frameworks with scores |
| `GET` | `/audit-logs?tenant=&limit=` | required | Immutable action trail |
| `GET` | `/users` | owner/admin | List operators |
| `POST` | `/users` | owner/admin | Invite operator |
| `DELETE` | `/users/{id}` | owner/admin | Remove operator (cannot remove owner) |

## Authentication & RBAC

- **Transport**: JWT in `httpOnly`, `secure`, `samesite=none` cookies.
- **Lifetimes**: Access 12h · Refresh 7d.
- **Hashing**: bcrypt cost 12, per-password salt.
- **Lockout**: 5 failed attempts → 15-min lockout per `{ip}:{email}`.
- **Audit**: Every login/logout/mutation logs to `audit_logs`.
- **Roles**: `owner` (full cross-tenant) · `admin` (tenant admin) · `analyst` (triage + patch) · `viewer` (read-only).
- **XSS framing**: `httpOnly` prevents JavaScript from reading the raw token. A successful XSS could still make authenticated requests via the cookie — defense-in-depth (CSP target, React auto-escaping, Pydantic validation) is applied in addition. No "immune to XSS" claim.

## Multi-Tenant Model

Every record carries a `tenant` field (`government | private | saas`).
- Non-privileged users (`analyst`, `viewer`) — backend auto-filters by their own tenant. No `?tenant=` override.
- `owner` / `admin` — can filter freely with `?tenant=government|private|saas|all`.
- Logical (query-time) isolation today; database-level isolation is the documented roadmap (see `SECURITY_DOSSIER.md` §5.5).

## Seeded Demo Data

| Collection | Count | Notes |
| --- | --- | --- |
| `users` | 2 | Owner + Analyst |
| `threats` | 120 | Last 14 days, weighted severity, 3 tenants |
| `vulnerabilities` | 36 | Real CVEs × 3 tenants |
| `incidents` | 24 | Mixed statuses + kill-chain phases |
| `assets` | 60 | Workstations, servers, firewalls, routers, DBs |
| `compliance` | 21 | 7 frameworks × 3 tenants |
| `audit_logs` | 80 | Historical trail |

Seeding is **idempotent**. To re-seed, drop the collections and restart.

## Security Posture

- Passwords hashed with bcrypt (never plaintext).
- JWTs in httpOnly cookies.
- CORS origin-whitelisted (not `*`) with `allow_credentials=true`.
- Unique index on `users.email`; TTL indexes on reset tokens and login attempts.
- Brute-force lockout on login.
- All mutating actions logged to the immutable audit trail.
- Role gating enforced server-side.
- No secrets in source; `.env` excluded from version control.

## Contact

**William Brown** · Owner & Operator
- Email: `william.brown@aegis-soc.io`
- Console: open the landing page and click **Operator Login**

For acquisition, government procurement, or MSSP licensing — reach out directly.

---

© 2026 Aegis SOC · All rights reserved · Transferable commercial license available
