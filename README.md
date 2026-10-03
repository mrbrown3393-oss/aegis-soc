# Aegis SOC

> **A sovereign Security Operations Center platform — operated by signal.**
> Owned by **William Brown**. Ready to sell, rent, or license.

Aegis SOC is a modular, enterprise-grade cybersecurity platform that unifies threat detection, incident response, vulnerability management, asset intelligence, continuous compliance, and immutable audit — in a single multi-tenant console with three sovereign deployment postures: **Government**, **Private Sector**, and **SaaS**.

![Status](https://img.shields.io/badge/status-operational-10b981)![Version](https://img.shields.io/badge/version-2.1.0-22d3ee)![License](https://img.shields.io/badge/license-Commercial-f59e0b)![Owner](https://img.shields.io/badge/owner-William%20Brown-60a5fa)

---

## Table of Contents

1. [What Is Aegis SOC](#what-is-aegis-soc)
2. [Why This Platform](#why-this-platform)
3. [Deployment Modes](#deployment-modes)
4. [Feature Modules](#feature-modules)
5. [Architecture](#architecture)
6. [Tech Stack](#tech-stack)
7. [Repository Layout](#repository-layout)
8. [Getting Started](#getting-started)
9. [Environment Variables](#environment-variables)
10. [Default Credentials](#default-credentials)
11. [API Reference](#api-reference)
12. [Authentication & RBAC](#authentication--rbac)
13. [Multi-Tenant Model](#multi-tenant-model)
14. [Seeded Demo Data](#seeded-demo-data)
15. [Frontend Routes](#frontend-routes)
16. [Testing](#testing)
17. [Commercial Terms (Rent / Buy / License)](#commercial-terms-rent--buy--license)
18. [Roadmap](#roadmap)
19. [Security Posture](#security-posture)
20. [Contact](#contact)

---

## What Is Aegis SOC

Aegis SOC is a **mock/prototype-ready, production-shaped** SOC platform built from the ground up to be:

- **Operator-first.** Dense, high-signal UI designed for tier-1 analysts (not dashboards-for-executives).
- **Tenant-isolated.** Three distinct visual + logical tenants — switch at the sidebar, every query is scoped.
- **Commercially flexible.** Sell outright, rent monthly, or license to government. All three are modelled.
- **Automatable.** Every endpoint prefixed `/api`; cookies are httpOnly; JWT is standard — easy to plug into CI, SOAR, or external SIEMs.

This is not a theme over an open-source SOC. It is a **ground-up implementation**: the backend is a bespoke FastAPI service, the data model is purpose-built, and the frontend is a hand-crafted React console (no Grafana/Kibana embed).

## Why This Platform

| Legacy SIEM / SOC Tools | Aegis SOC |
| --- | --- |
| 14 tabs, 3 personas, zero cohesion | 8 modules, one shared pane of glass |
| Theme = color swap | Theme = **tenant isolation** (gov / private / saas) |
| Compliance is an afterthought | 7 frameworks tracked continuously |
| Vendor lock-in | **Transferable** license, source-included option |
| "Request a demo" | **Pre-seeded demo tenant** — log in and explore now |

## Deployment Modes

Aegis ships three sovereign tenant postures. Each has its own theme, control baseline, and go-to-market framing.

### 1. Government
- **Vibe**: authoritative navy / steel
- **Accent**: `#60a5fa`
- **Compliance baseline**: FedRAMP Moderate · CMMC Level 2 · FIPS 140-3 · STIG-hardened
- **Suited for**: federal agencies, state/local government, defense primes, intelligence community

### 2. Private Sector
- **Vibe**: corporate warm / amber
- **Accent**: `#f5b041`
- **Compliance baseline**: SOC 2 Type II · ISO 27001:2022 · PCI-DSS 4.0 · HIPAA
- **Suited for**: Fortune 500 security teams, regulated financial / healthcare, growing enterprises

### 3. SaaS Platform
- **Vibe**: modern sharp / cyan
- **Accent**: `#22d3ee`
- **Capabilities**: multi-tenant isolation · white-label · usage billing · API-first
- **Suited for**: MSSPs, security product companies, agencies reselling SOC-as-a-Service

Owners and admins can hot-switch tenants from the dashboard header. Non-privileged operators (analysts, viewers) are hard-scoped to their own tenant.

## Feature Modules

The dashboard sidebar exposes **8 modules**:

| # | Module | What it does |
| --- | --- | --- |
| 1 | **Overview** | Portfolio KPIs, 7-day trend line, severity donut, live threat tape, active incidents |
| 2 | **Threats** | Correlated SIEM-style events with severity, geo, confidence, source IP, affected asset |
| 3 | **Vulnerabilities** | Real CVE catalog with CVSS 3.1 scores, patch-tracking per asset |
| 4 | **Incidents** | Incident tickets with kill-chain phase, assignee, 4-step status workflow |
| 5 | **Compliance** | Continuous control monitoring across NIST 800-53, ISO 27001, SOC 2, HIPAA, FedRAMP, PCI-DSS 4.0, CMMC L2 |
| 6 | **Assets** | Discovered endpoints, servers, firewalls, routers, DBs with per-asset risk score |
| 7 | **Users** | Operators & RBAC — invite, assign role (owner / admin / analyst / viewer), remove |
| 8 | **Audit Logs** | Immutable action trail with CSV export |

Plus:

- **Marketing landing** with hero, tenant selector cards, 6-feature bento, Rent/Buy pricing, owner profile section
- **Operator login** with pre-filled demo credentials
- **Tenant switcher** (owner/admin only) in header

## Architecture

```
                    ┌──────────────────────────────┐
                    │   React 19 Frontend (CRA)    │
                    │  Tailwind · Shadcn · Recharts│
                    │   framer-motion · sonner     │
                    └────────────┬─────────────────┘
                                 │  axios · withCredentials
                                 │  httpOnly JWT cookies
                                 ▼
                    ┌──────────────────────────────┐
                    │   FastAPI Backend  (/api/*)  │
                    │  bcrypt · PyJWT · motor      │
                    │  CORS · Brute-force lockout  │
                    └────────────┬─────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────────┐
                    │           MongoDB            │
                    │  users · threats · vulns     │
                    │  incidents · assets          │
                    │  compliance · audit_logs     │
                    │  login_attempts (TTL)        │
                    └──────────────────────────────┘
```

- **Auth**: Short-lived access JWT (12h) + refresh JWT (7d) in `secure`, `httpOnly`, `samesite=none` cookies.
- **Password hashing**: `bcrypt` (cost 12).
- **Brute-force protection**: 5 failed attempts per `{ip}:{email}` triggers a 15-min lockout.
- **Audit**: Every mutating action (login, logout, patch, incident status change, user invite, user delete) is appended to `audit_logs` with actor, IP, resource, and tenant.
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
- **Recharts 3** — line, bar, donut, pie
- **framer-motion 11** — micro-interactions
- **lucide-react** — iconography (no emoji icons)
- **sonner** — toasts
- **axios** — `withCredentials: true` globally

### Typography
- **Chivo** — all headings (`font-heading`)
- **IBM Plex Sans** — body
- **IBM Plex Mono** — data, logs, numbers (`font-mono`)

## Repository Layout

```
/app
├── backend/
│   ├── server.py              # All routes, auth, seeder (~700 LOC)
│   ├── requirements.txt
│   └── .env                   # JWT_SECRET, ADMIN_EMAIL, MONGO_URL, ...
├── frontend/
│   ├── public/
│   │   └── index.html         # Fonts loaded here
│   ├── src/
│   │   ├── App.js             # Router + Providers
│   │   ├── index.css          # Tenant themes + Shadcn tokens
│   │   ├── contexts/
│   │   │   ├── AuthContext.jsx
│   │   │   └── TenantContext.jsx
│   │   ├── components/
│   │   │   ├── ProtectedRoute.jsx
│   │   │   └── ui/            # Shadcn components
│   │   ├── lib/api.js         # axios instance + error formatter
│   │   └── pages/
│   │       ├── Landing.jsx
│   │       ├── Login.jsx
│   │       ├── DashboardLayout.jsx
│   │       └── dashboard/
│   │           ├── Overview.jsx
│   │           ├── Threats.jsx
│   │           ├── Vulnerabilities.jsx
│n│   │           ├── Incidents.jsx
│   │           ├── Compliance.jsx
│   │           ├── Assets.jsx
│   │           ├── Users.jsx
│   │           └── AuditLogs.jsx
│   ├── package.json
│   └── .env                   # REACT_APP_BACKEND_URL
├── memory/
│   ├── PRD.md                 # Product Requirements Doc
│   └── test_credentials.md
├── auth_testing.md
└── README.md                  # ← you are here
```

## Getting Started

### Prerequisites

- Node.js 20+ with **Yarn** (not npm)
- Python 3.11+
- MongoDB 6+
- A modern browser

### Local Setup

```bash
# Backend
cd /app/backend
pip install -r requirements.txt
# Supervisor-managed in this environment; otherwise:
# uvicorn server:app --host 0.0.0.0 --port 8001 --reload

# Frontend
cd /app/frontend
yarn install
yarn start   # http://localhost:3000
```

In this hosted environment, both services are already running under **supervisor** on their standard ports (`backend:8001`, `frontend:3000`) and are proxied through Kubernetes ingress at `REACT_APP_BACKEND_URL`.

### Verify

```bash
API=$(grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d'=' -f2)

# health
curl $API/api/

# login
curl -c /tmp/c.txt -X POST $API/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"william.brown@aegis-soc.io","password":"AegisOwner2025!"}'

# fetch metrics
curl -b /tmp/c.txt "$API/api/metrics/overview?tenant=all"
```

## Environment Variables

### `backend/.env`

| Key | Description |
| --- | --- |
| `MONGO_URL` | MongoDB connection string |
| `DB_NAME` | Mongo database name |
| `JWT_SECRET` | 64-char hex secret for JWT signing |
| `ADMIN_EMAIL` | Owner email (seeded on startup) |
| `ADMIN_PASSWORD` | Owner password (idempotent re-hash on change) |
| `ANALYST_EMAIL` | Demo analyst email |
| `ANALYST_PASSWORD` | Demo analyst password |
| `FRONTEND_URL` | Allowed origin for CORS |
| `CORS_ORIGINS` | Fallback origin list (comma-separated) |

### `frontend/.env`

| Key | Description |
| --- | --- |
| `REACT_APP_BACKEND_URL` | Public backend URL (all API calls use `${REACT_APP_BACKEND_URL}/api/*`) |

**Never** hardcode URLs or secrets in source. All backend routes are prefixed `/api`.

## Default Credentials

> Change these before any non-demo deployment. They are also persisted in `/app/memory/test_credentials.md`.

| Role | Email | Password | Tenant |
| --- | --- | --- | --- |
| **Owner** (William Brown) | `william.brown@aegis-soc.io` | `AegisOwner2025!` | `saas` (sees all) |
| Analyst | `analyst@aegis-soc.io` | `Analyst2025!` | `government` |

The owner can view any tenant via the sidebar/header switcher. The analyst is hard-scoped to the `government` tenant.

## API Reference

All endpoints are prefixed with `/api`.

### Auth

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/auth/register` | public | Register new viewer, sets auth cookies |
| `POST` | `/auth/login` | public | Login, sets `access_token` + `refresh_token` cookies |
| `POST` | `/auth/logout` | required | Clears cookies, writes audit |
| `GET` | `/auth/me` | required | Returns current user |
| `POST` | `/auth/refresh` | refresh cookie | Issues a new access token |

### Metrics & Threats

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/metrics/overview?tenant=all\|government\|private\|saas` | required | KPIs, severity dist, 7-day trend |
| `GET` | `/threats?limit=&severity=&tenant=` | required | List threats |
| `GET` | `/threats/live` | required | Simulates & inserts a new live threat |

### Vulnerabilities

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/vulnerabilities?tenant=` | required | Sorted by CVSS desc |
| `POST` | `/vulnerabilities/{id}/patch` | required | Mark as patched |

### Incidents

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/incidents?tenant=` | required | Incident tickets |
| `PATCH` | `/incidents/{id}` | required | Body `{status: new\|investigating\|contained\|resolved}` |

### Assets, Compliance, Audit

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/assets?tenant=` | required | Assets sorted by risk |
| `GET` | `/compliance?tenant=` | required | Frameworks with scores |
| `GET` | `/audit-logs?tenant=&limit=` | required | Immutable action trail |

### Users (owner / admin only)

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/users` | owner/admin | List all operators |
| `POST` | `/users` | owner/admin | Invite operator (email, name, role, tenant, password) |
| `DELETE` | `/users/{id}` | owner/admin | Remove operator (cannot remove owner) |

## Authentication & RBAC

- **Transport**: JWT in `httpOnly`, `secure`, `samesite=none` cookies — browser JavaScript cannot read the raw token, so a successful XSS payload cannot directly exfiltrate it. (This is not a blanket "immune to XSS" claim: a successful XSS could still make authenticated requests via the cookie. XSS defense-in-depth is applied in addition — see §Security Posture.)
- **Lifetimes**: Access 12h · Refresh 7d.
- **Hashing**: `bcrypt` with per-password salt.
- **Lockout**: 5 failed attempts → 15-min lockout per `{ip}:{email}`.
- **Audit**: Every login/logout/mutation logs to `audit_logs` with actor + IP + tenant.
- **Roles**:
  - `owner` — full cross-tenant access, platform licensing controls (reserved for William Brown).
  - `admin` — tenant admin, user management, policy.
  - `analyst` — tier 1/2 operator, triage + patch.
  - `viewer` — read-only compliance / executive view.

## Multi-Tenant Model

Every data record carries a `tenant` field (`government | private | saas`). Query behavior:

- Non-privileged users (`analyst`, `viewer`) — backend auto-filters by their own tenant. No `?tenant=` override.
- `owner` / `admin` — can filter freely with `?tenant=government|private|saas|all`.
- The frontend's `TenantContext` persists the selected tenant in `localStorage` and reflects it in the UI theme + API query params.

This separation is logical (query-time), making it safe to prototype but easy to upgrade to database-level isolation (separate DBs or row-level security) in a production rollout.

## Seeded Demo Data

On first startup, the backend inserts:

| Collection | Count | Notes |
| --- | --- | --- |
| `users` | 2 | Owner + Analyst |
| `threats` | 120 | Last 14 days, weighted severity, 3 tenants |
| `vulnerabilities` | 36 | Real CVEs (CVE-2024-3094, CVE-2024-6387, …) × 3 tenants |
| `incidents` | 24 | Mixed statuses + kill-chain phases |
| `assets` | 60 | Workstations, servers, firewalls, routers, DBs |
| `compliance` | 21 | 7 frameworks × 3 tenants |
| `audit_logs` | 80 | Historical trail |

Seeding is **idempotent** — re-running startup never duplicates data. To re-seed, drop the collections and restart.

## Frontend Routes

| Route | Access | Component |
| --- | --- | --- |
| `/` | public | `Landing` |
| `/login` | public (auto-redirects to `/app` if logged in) | `Login` |
| `/app` | protected | `DashboardLayout` → `Overview` |
| `/app/threats` | protected | `Threats` |
| `/app/vulnerabilities` | protected | `Vulnerabilities` |
| `/app/incidents` | protected | `Incidents` |
| `/app/compliance` | protected | `Compliance` |
| `/app/assets` | protected | `Assets` |
| `/app/users` | protected (owner/admin for mutations) | `Users` |
| `/app/audit-logs` | protected | `AuditLogs` |

All interactive elements expose `data-testid` attributes for automated testing (`login-submit-btn`, `tenant-switcher`, `invite-user-btn`, etc.).

## Testing

End-to-end verification was performed via an automated testing agent:

- **Backend**: pytest suite covering auth, RBAC, tenant isolation, CRUD endpoints, brute-force lockout → **24/25 passing (96%)**.
- **Frontend**: Playwright flows for landing, login, all 8 dashboard modules, vuln patching, incident status workflow, invite modal, tenant switcher, logout → **100% passing**.

Known minor items (non-blocking):
- Brute-force lockout keys off the TCP peer, which in this K8s ingress is the ingress pod IP. P2 fix is to prefer `X-Forwarded-For`.
- Recharts emits width/height warnings on first paint before `ResponsiveContainer` settles — cosmetic.

Quick smoke test:

```bash
API=$(grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d'=' -f2)
curl $API/api/
curl -c c.txt -X POST $API/api/auth/login -H "Content-Type: application/json" \
  -d '{"email":"william.brown@aegis-soc.io","password":"AegisOwner2025!"}'
curl -b c.txt "$API/api/metrics/overview?tenant=all"
```

## Commercial Terms (Rent / Buy / License)

Aegis SOC is a **privately-held, transferable asset** owned by William Brown. Three go-to-market options are modelled on the landing page:

### 1. Rent — Monthly · **$9,800 / mo**
Full-stack SOC-as-a-Service. Cancel anytime. Includes 24/7 analyst coverage, up to 500 assets, 4-hour SLA, US-based SOC analysts, quarterly compliance reports.

### 2. Rent — Annual · **$94,000 / yr** (20% savings)
Unlimited assets, 1-hour SLA, dedicated success engineer, custom playbooks, on-prem connector.

### 3. Buy — Platform License · **$450k+** (one-time)
Full source code, perpetual license, white-label, **resell rights**, 1 year of updates. Built for MSSPs, agencies, or government procurement where the buyer wants to own the stack.

> All three paths are supported commercially. Serious inquiries — government procurement, private acquisition, or MSSP licensing — welcomed.

## Roadmap

### P1 (next)
- **Threat Map** — live geo visualization of attack arcs
- **MITRE ATT&CK enrichment** — tag every threat with technique IDs
- **SSO** — SAML 2.0 / Okta / Azure AD for enterprise & government
- **Stripe Checkout** — self-serve rent subscriptions and licensing deposits
- **AI threat triage** — LLM-powered incident summaries and anomaly explanation

### P2 (later)
- Row-level tenant isolation (per-tenant Mongo databases)
- Harden brute-force lockout against `X-Forwarded-For`
- Split `server.py` into module packages (auth / soc / users / seed)
- Live Websocket feed to replace polled `/threats/live`
- Scheduler for compliance recomputation and report distribution
- CSV/PDF scheduled executive reports

## Security Posture

Even as a prototype, Aegis follows the defaults a buyer would expect:

- Passwords hashed with `bcrypt` (never stored in plaintext).
- JWTs stored in `httpOnly` cookies — browser JavaScript cannot read the raw token, so a successful XSS cannot directly exfiltrate it. XSS defense-in-depth (strict CSP target, React auto-escaping, no `dangerouslySetInnerHTML`, Pydantic input validation) is applied in addition. Aegis does not claim immunity to XSS.
- CORS origin-whitelisted (not `*`) with `allow_credentials=true`.
- Unique index on `users.email`; TTL index on password-reset tokens.
- Brute-force lockout on login.
- All mutating actions logged to the immutable audit trail.
- Role gating enforced server-side (owner/admin for user mgmt).

## Contact

**William Brown** · Owner & Operator
- Email: `william.brown@aegis-soc.io`
- Console: open the landing page and click **Operator Login**

For acquisition, government procurement, or MSSP licensing — reach out directly.

---

© 2026 Aegis SOC · All rights reserved · Transferable commercial license available
