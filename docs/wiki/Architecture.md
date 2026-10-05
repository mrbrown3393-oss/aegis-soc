# Architecture

```
React 19 Frontend (Vite)
        │  axios + httpOnly JWT cookies
        ▼
FastAPI Backend  (/api/*)
        │
        ▼
     MongoDB
  users · threats · vulns · incidents
  assets · compliance · audit_logs
  login_attempts (TTL)
```

## Auth

- Access JWT (15 min) + Refresh JWT (7 days) in `secure`, `httpOnly`, SameSite cookies
- Password hashing: bcrypt cost 12
- Brute-force: 5 failed attempts → 15-min lockout per `{ip}:{email}`
- CSRF: origin check on state-changing requests

## Multi-Tenant Model

Every record carries `tenant` = `government | private | saas`.

- `analyst` / `viewer` → auto-filtered to their own tenant
- `owner` / `admin` → can filter with `?tenant=…` or `all`

Logical isolation today; DB-level isolation is on the roadmap (see SECURITY_DOSSIER.md §5.5).

## Tech Stack

**Backend:** FastAPI 0.110 · Motor 3.3 · PyJWT · bcrypt · Pydantic v2  
**Frontend:** React 19 · React Router 7 · Vite 6 · TypeScript · Tailwind · Recharts  
**Typography:** Chivo (headings) · IBM Plex Sans / Mono
