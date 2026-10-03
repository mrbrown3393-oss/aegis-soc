# Cryptography & Secrets Management Policy

| | |
|---|---|
| Document ID | AEG-CR-001 |
| Version | 1.0 |
| Parent Policy | AEG-ISP-000 |

## 1. Approved Algorithms

| Use | Algorithm |
|---|---|
| Password hashing | bcrypt, cost ≥ 12 |
| Data-at-rest (WiredTiger) | AES-256-GCM |
| Transport | TLS 1.2 minimum, TLS 1.3 preferred; modern cipher suites only |
| Tokens | JWT HS256 minimum (RS256 required for federated scenarios), secrets ≥ 64-char hex |
| Random values | CSPRNG only (`secrets` module / `crypto`) |

Deprecated (forbidden): MD5, SHA-1 for security purposes, TLS ≤ 1.1, DES/3DES, ECB mode, hard-coded keys.

## 2. Key Management

- The WiredTiger encryption key lives in a key file with `0600` permissions outside the database path, or in a KMIP server where available (see `deploy/mongodb/`).
- `JWT_SECRET` and database credentials are injected via environment/secrets manager; committed `.env` files are a policy violation and a SEV-3 incident.
- Key rotation: database master key annually; JWT secret on any suspected exposure (forces global re-auth, which is accepted).
- TLS certificates are managed per `docs/mongodb-encryption.md` and ingress documentation; expiry is monitored with a 30-day alert threshold.
