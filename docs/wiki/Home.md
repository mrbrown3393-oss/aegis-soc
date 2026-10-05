# Aegis SOC

Aegis SOC is William Brown's security operations platform. This wiki covers the FastAPI backend, MongoDB data store, React client, authentication, deployment, and operating procedures.

**Maintainer:** William Brown

**API version:** 2.2.0

**Repository:** [mrbrown3393-oss/aegis-soc](https://github.com/mrbrown3393-oss/aegis-soc)

## Start here

| Page | Use it for |
| --- | --- |
| [Getting Started](Getting-Started.md) | Local configuration, starting the API and client, and first sign-in |
| [Architecture](Architecture.md) | Components, request flow, and tenant boundaries |
| [API Reference](API-Reference.md) | Verified routes, authentication requirements, and response shapes |
| [Security](Security.md) | MFA, sessions, access controls, and security evidence |
| [Deployment](Deployment.md) | Production settings and deployment checks |
| [Operations](Operations.md) | Incident workflow, backups, and maintenance runbooks |
| [Troubleshooting](Troubleshooting.md) | Login failures, origin errors, and client/API integration gaps |

## Current implementation

The backend contains APIs for threats, vulnerabilities, incident status updates, assets, compliance records, users, audit logs, telemetry fusion, and quarantine requests. The client lives in `client/` and uses React, TypeScript, and Vite.

The tenant values are `government`, `private`, and `saas`. Only the `owner` role can query across tenants. Other roles are scoped to their own tenant by backend dependencies.

The first database startup seeds training records. Those threat, asset, vulnerability, and compliance records are synthetic; they are not findings from a real security scan. `GET /api/threats/live` also generates simulated telemetry. A quarantine request records a requested action in MongoDB; endpoint/network isolation needs an enforcement integration.

The current client and backend have API-contract differences that must be resolved before an end-to-end deployment. The [Troubleshooting](Troubleshooting.md) page names the specific differences.

## Project evidence

Use the running code and current tests to assess a release. Some older repository documents describe earlier versions.

- [Security evidence catalog](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/EVIDENCE_CATALOG.md)
- [Security documentation errata](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY_ERRATA.md)
- [Security policy](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/SECURITY.md)
- [Operations pack](https://github.com/mrbrown3393-oss/aegis-soc/blob/main/docs/ops/README.md)

Compliance documents describe design targets and supporting evidence. They do not establish FedRAMP authorization or SOC 2, ISO 27001, or CMMC certification.

**Documentation basis:** main-branch commit [2049bdeb](https://github.com/mrbrown3393-oss/aegis-soc/commit/2049bdeb8a96e8f91d3ca55d4534096650f813e2), reviewed October 5, 2026. This documentation update does not represent a new runtime test or deployment.
