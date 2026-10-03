# Information Security Policy — Aegis SOC Platform

| | |
|---|---|
| Document ID | AEG-ISP-000 |
| Version | 1.0 |
| Owner | Platform Owner (William Brown) |
| Classification | Internal |
| Review Cycle | Annual, or upon material change |

## 1. Purpose

This policy establishes the information security management framework for the Aegis SOC platform — a multi-tenant, zero-trust security operations platform. It defines the top-level security objectives, assigns responsibility, and incorporates by reference the domain policies in this pack (`docs/policies/`).

## 2. Scope

This policy applies to:
- All Aegis SOC application components: the FastAPI backend (`backend/`), the Node/Express real-time server (`server/`), the web client (`client/`), and the MongoDB data tier.
- All tenants (government, private, saas) and their data processed by the platform.
- All personnel, contractors, and integrated third parties with access to the platform or its infrastructure.
- All environments: development, staging, and production.

## 3. Security Objectives

1. **Confidentiality** — Tenant data is isolated logically today and protected at rest (WiredTiger encryption) and in transit (TLS 1.2+). Secrets exist only in environment variables or a managed secrets store, never in source.
2. **Integrity** — All mutating actions are audit-logged with actor, action, resource, IP, tenant, and timestamp. Dependencies are continuously scanned and a CycloneDX SBOM is produced per release.
3. **Availability** — Continuous monitoring, tested backups, and scheduled restoration drills guarantee recoverability within stated RPO/RTO targets.
4. **Zero Trust** — No request is trusted by network location. Every request is authenticated, authorized, and continuously re-verified per `docs/zero-trust-architecture.md`.

## 4. Governance and Roles

| Role | Responsibility |
|---|---|
| Platform Owner | Accountable for the security program; approves policies and risk acceptance. Cannot be deleted from the system. |
| Security Administrator (admin) | Day-to-day control operation, user lifecycle, SSO/IdP configuration. |
| SOC Analyst | Monitoring, triage, incident execution under the IR Plan. |
| Viewer | Read-only access within tenant scope. |

## 5. Policy Framework

The following domain policies are incorporated and enforceable:

- **AEG-AC-001** — Access Control Policy
- **AEG-IR-001** — Incident Response Policy
- **AEG-DP-001** — Data Protection & Classification Policy
- **AEG-CR-001** — Cryptography & Secrets Management Policy
- **AEG-AU-001** — Acceptable Use Policy
- **AEG-BR-001** — Backup, Recovery & Restoration Drills Policy

## 6. Risk Management

- Risks are recorded in the risk register with owner, likelihood, impact, and treatment.
- Residual risk acceptance requires Platform Owner sign-off and an expiry date.
- The platform maintains honest non-claims: no control is represented as providing immunity (e.g., httpOnly cookies mitigate but do not eliminate XSS session-riding risk).

## 7. Compliance

The platform maps controls to NIST 800-53, ISO 27001, SOC 2, HIPAA, FedRAMP, PCI-DSS 4.0, and CMMC L2 (see `SECURITY_DOSSIER.md`). Control effectiveness is measured continuously per `docs/continuous-monitoring.md`.

## 8. Exceptions

Exceptions require a written request, compensating controls, Platform Owner approval, and an expiry date not exceeding 12 months.

## 9. Enforcement

Violations may result in access revocation, disciplinary action, and where applicable legal action. Automated enforcement (rate limiting, lockout, quarantine) operates without prior notice as documented.
