# Aegis SOC Security Hardening Release Notes

## Implemented in this branch

- Formal Information Security Policy Pack: docs/SECURITY_POLICY_PACK.md
- Platform Incident Response Plan: docs/INCIDENT_RESPONSE_PLAN.md
- MongoDB TLS client enforcement and production WiredTiger encryption configuration: ops/mongodb/
- Strict application security headers and Kubernetes ingress header baseline: backend/security_hardening.py and ops/ingress/security-headers.yaml
- SAML/OIDC configuration endpoints with fail-closed behavior: backend/sso.py
- Dependabot, dependency review, pip-audit, Trivy, Gitleaks, and CycloneDX SBOM generation: .github/
- Proxy-aware source-IP attribution for brute-force controls
- Security telemetry fusion with weighted geospatial centroiding and anomaly scoring
- Auditable asset quarantine requests with tenant scoping and evidence references

## Deployment notes

SSO requires a registered enterprise identity provider and server-side state/signature validation. The repository deliberately fails closed when provider-specific verification configuration is absent.

MongoDB encryption at rest is enabled by the mongod configuration and a secret-managed encryption key. TLS certificates and keys must be provisioned outside Git.

Threat tracing is intentionally observable and auditable. Quarantine actions are recorded in the audit trail and are not designed to evade defenders, logging, or oversight.
