# Aegis SOC Information Security Policy Pack

Version: 1.0 | Owner: William Brown | Effective: 2026-10-03

## Information Security
Aegis protects customer, identity, telemetry, configuration, and security-event information through least privilege, encryption, secure development, monitoring, incident response, and accountable change management.

## Access Control
Access is deny-by-default. RBAC and tenant scoping are enforced server-side. Privileged access requires named accounts, strong credentials, MFA where configured, and periodic review. Shared credentials are prohibited.

## Data Classification
Public, Internal, Confidential, and Restricted data must be identified by the owning function. Restricted security telemetry and credentials require encryption in transit and at rest, least-privilege access, retention limits, and controlled deletion.

## Cryptography
TLS 1.2+ is required for transport, with TLS 1.3 preferred. MongoDB TLS is mandatory in production. MongoDB WiredTiger encryption at rest is mandatory in production. Keys and secrets stay outside source control.

## Secure Development
Dependencies are pinned where practical and scanned continuously. CI must run tests, dependency vulnerability scanning, secret scanning, and SBOM generation.

## Vulnerability Management
Critical vulnerabilities are assessed immediately and targeted for remediation within 24 hours where feasible. High severity issues target seven days, medium 30 days, and low 90 days. Exceptions require documented risk acceptance.

## Logging and Monitoring
Authentication, authorization, administrative changes, quarantine actions, telemetry fusion, and other security-relevant events are logged with UTC timestamps and tenant context. Logs must be protected against unauthorized alteration.

## Incident Response
Security incidents follow preparation, detection, analysis, containment, eradication, recovery, and lessons learned. Evidence preservation and chain of custody are required.

## Business Continuity
Critical services require documented backups, recovery objectives, tested restore procedures, and alternate operating procedures.

## Third-Party and Supply Chain
Third-party software and service providers are inventoried, risk-assessed, monitored, and subject to appropriate contractual security requirements.

## Governance
The owner approves material security exceptions, risk acceptance, and policy changes. This is a platform policy baseline, not a certification claim.
