# Incident Response Plan — Aegis SOC Platform

| | |
|---|---|
| Document ID | AEG-IRP-100 |
| Version | 1.0 |
| Policy | AEG-IR-001 |
| Scope | The Aegis SOC platform itself (application, data tier, infrastructure, SSO, supply chain) |

## 1. Purpose

This plan governs response to security incidents affecting the **Aegis SOC platform as a system** — compromise of the application, its MongoDB data tier, its SSO/federation, its CI/CD and dependency supply chain, or its operators' credentials. (Tenant-facing SOC cases handled *inside* the product follow the in-app incident workflow.)

## 2. Severity Classification

| Severity | Definition | Examples | Respond | Update Cadence |
|---|---|---|---|---|
| SEV-1 | Active compromise / confirmed tenant data exposure | RCE on backend, cross-tenant data leak, WiredTiger key theft | Immediate, 24×7 | Every 30 min |
| SEV-2 | High impact, contained or imminent | Auth bypass found, IdP misconfig exposing federation, critical CVE in deployed dependency with exploit | ≤ 1 h | Hourly |
| SEV-3 | Limited impact | Committed secret, failed backup drill, lockout-bypass attempt | ≤ 4 h | Daily |
| SEV-4 | Informational | Policy violation attempt blocked, scanner noise | ≤ 24 h | Weekly |

## 3. Roles

- **Incident Commander (IC)** — owns the incident end-to-end; sole authority for containment trade-offs. Default: Platform Owner.
- **Security Lead** — technical investigation, tracing, forensics.
- **Comms Lead** — tenant, legal, and (if required) regulator notification.
- **Scribe** — timeline, evidence log, action items.

## 4. Response Phases

### 4.1 Preparation
- Controls in place: audit logging on every mutation, TLS everywhere, WiredTiger encryption, SSO federation, rate limiting, lockout, SBOM + dependency scanning, continuous monitoring (`docs/continuous-monitoring.md`).
- On-call contact tree and break-glass credentials stored in the secrets manager.

### 4.2 Detection & Analysis
- Sources: continuous monitoring alerts, audit-log anomalies, dependency scan findings, tenant reports, tracing engine output.
- Validate, classify severity, assign IC, open incident record. Preserve initial evidence (logs, DB snapshots) before changes.
- Engage the threat tracer (`backend/security/threat_tracer.py`) in **low-observability mode**: passive correlation over existing telemetry and honeypot canaries only — no active probing of the adversary, no artifacts an attacker can detect. Output: IOC graph, blast radius, affected tenants/assets.

### 4.3 Containment
- Automated pre-authorized actions via the quarantine engine (`backend/security/quarantine.py`):
  - isolate asset (tag + network policy),
  - block source IP at ingress,
  - disable/suspend identity and revoke sessions,
  - freeze federation (disable SAML/OIDC IdP trust) if IdP compromise is suspected.
- Safety rails: quarantine actions respect the protected-entity allowlist (owner account, platform control plane) and are fully reversible; every action is audit-logged with reason and trace ID.
- Human review of every automated quarantine within 1 hour (SEV-1/2).

### 4.4 Eradication & Recovery
- Rotate exposed secrets/keys (JWT secret rotation forces global re-auth — accepted).
- Patch/redeploy from clean artifacts; verify against SBOM that the vulnerable dependency version is gone.
- Restore from verified backup if integrity is in doubt (use the quarterly-drill procedure).
- Confirm eradication with the tracer: no IOC recurrence for an agreed dwell window (default 72 h).

### 4.5 Post-Incident
- Blameless post-incident review within 5 business days (SEV-1/2): timeline, root cause, control gaps.
- Update policies, detection rules, and the risk register; track corrective actions to closure.
- Notify affected tenants within 24 h for data-affecting incidents; regulators per applicable law.

## 5. Communication Templates

- Internal: severity, scope, IC, current action, next update time.
- Tenant: what happened, what data/tenants affected, what we did, what they should do, contact.

## 6. Testing

- Tabletop: twice yearly (scenarios: IdP compromise, malicious dependency, DB key theft, insider misuse).
- Live simulation: yearly, including quarantine-engine dry run against a canary asset.
