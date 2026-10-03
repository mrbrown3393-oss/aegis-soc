# Data Protection & Classification Policy

| | |
|---|---|
| Document ID | AEG-DP-001 |
| Version | 1.0 |
| Parent Policy | AEG-ISP-000 |

## 1. Classification Scheme

| Level | Definition | Examples | Handling |
|---|---|---|---|
| Restricted | Highest sensitivity; tenant-confined | Credentials, password hashes, reset tokens, session tokens, SSO assertions | Encrypted at rest + in transit; never logged; access admin-only |
| Confidential | Business-sensitive | Threat intel, incident records, audit logs, vulnerability data | Encrypted at rest + in transit; tenant-scoped access only |
| Internal | Operational | Configurations, playbooks, SBOMs | Access on need-to-know |
| Public | Approved for release | Marketing, public docs | Integrity controls only |

## 2. Requirements

- **At rest**: MongoDB WiredTiger native encryption (AES-256-GCM) is mandatory in all non-dev environments (see `deploy/mongodb/mongod.conf`).
- **In transit**: TLS 1.2+ for all database connections and all client/API traffic; plaintext listeners disabled outside development.
- **Logging hygiene**: secrets, tokens, password hashes, and assertion contents MUST NOT appear in logs or error responses. Error responses are generic (`Internal server error`).
- **Account enumeration resistance**: authentication and password-reset responses are uniform regardless of account existence.
- **Retention**: audit logs retained 12 months minimum; threat telemetry 13 months; backups per AEG-BR-001. TTL indexes enforce expiry where defined (e.g., password reset tokens).
- **Cross-tenant exposure** is classified as a SEV-2 incident minimum.
- **SBOM and provenance**: each release ships a CycloneDX SBOM so data-affecting dependencies are known and patchable.
