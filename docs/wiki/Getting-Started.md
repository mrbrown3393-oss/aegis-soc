# Getting Started

## Prerequisites

- Python 3.11+
- MongoDB 6+
- Modern browser

## Local Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # edit secrets (ADMIN_EMAIL, ADMIN_PASSWORD, JWT secret, etc.)
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

## Verify

```bash
curl http://localhost:8001/api/

# Login (replace with your credentials from .env)
curl -c c.txt -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"YOUR_ADMIN_EMAIL","password":"YOUR_ADMIN_PASSWORD"}'

curl -b c.txt "http://localhost:8001/api/metrics/overview?tenant=all"
```

## Environment Variables

See `backend/.env.example`.  
In production set `AEGIS_ENV=production` — the app fails closed on weak secrets, missing TLS, wildcard CORS, etc.

## Seeded Demo Data

Idempotent seeder creates:

| Collection        | Count | Notes                          |
|-------------------|-------|--------------------------------|
| users             | 2     | Owner + Analyst                |
| threats           | 120   | Last 14 days, 3 tenants        |
| vulnerabilities   | 36    | CVE-referenced                 |
| incidents         | 24    | Mixed statuses                 |
| assets            | 60    | Workstations → DBs             |
| compliance        | 21    | 7 frameworks × 3 tenants       |
| audit_logs        | 80    | Historical trail               |

To re-seed: drop the collections and restart the server.
