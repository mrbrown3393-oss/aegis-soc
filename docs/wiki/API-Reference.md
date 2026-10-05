# API Reference

All endpoints are prefixed `/api`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | public | Health check |
| POST | `/auth/register` | public | Register viewer |
| POST | `/auth/login` | public | Login (sets cookies) |
| POST | `/auth/logout` | required | Clears cookies + audit |
| GET | `/auth/me` | required | Current user |
| POST | `/auth/refresh` | refresh cookie | New access token |
| POST | `/auth/password-reset/request` | public | Request reset token |
| POST | `/auth/password-reset/confirm` | public | Consume token |
| GET | `/metrics/overview?tenant=` | required | KPIs + trends |
| GET | `/threats?limit=&severity=&tenant=` | required | List threats |
| GET | `/threats/live` | required | Simulate live threat |
| GET | `/vulnerabilities?tenant=` | required | Sorted by CVSS |
| POST | `/vulnerabilities/{id}/patch` | required | Mark patched |
| GET | `/incidents?tenant=` | required | Incident tickets |
| PATCH | `/incidents/{id}` | required | Update status |
| GET | `/assets?tenant=` | required | Assets by risk |
| GET | `/compliance?tenant=` | required | Framework scores |
| GET | `/audit-logs?tenant=&limit=` | required | Action trail |
| GET | `/users` | owner/admin | List operators |
| POST | `/users` | owner/admin | Invite operator |
| DELETE | `/users/{id}` | owner/admin | Remove operator |
