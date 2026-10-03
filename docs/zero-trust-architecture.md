# Zero Trust Architecture — Aegis SOC

| | |
|---|---|
| Document ID | AEG-ZTA-001 |
| Version | 1.0 |
| Reference | NIST SP 800-207 (Zero Trust Architecture) |

## 1. Principles

1. **Never trust, always verify.** No implicit trust from network location, VPN membership, or prior authentication. Every request is verified.
2. **Assume breach.** Design as if an adversary is already inside: minimize blast radius (tenant scoping, least privilege), log everything, quarantine fast.
3. **Verify explicitly.** Authenticate and authorize using all available signals: identity, role, tenant, token freshness, device posture, and session risk.
4. **Least privilege, per-request.** Access decisions are made per request against live policy, not per session establishment.

## 2. Architecture Components

| Component | Aegis Implementation |
|---|---|
| Policy Decision Point (PDP) | RBAC + tenant filter in-app; OPA for externalized policy (`security/opa/policy.rego`) |
| Policy Enforcement Point (PEP) | `backend/zerotrust/pep.py` middleware — runs before every protected route |
| Identity Provider | SAML 2.0 / OIDC federation (docs/sso-setup.md); local bcrypt for break-glass |
| Device trust | Device posture header attestation (`X-Device-Posture`) verified at the PEP; managed-device requirement for admin actions |
| Data protection | WiredTiger AES-256-GCM at rest; TLS 1.2+ in transit; per-request tenant isolation |
| Visibility | Audit trail on every mutation; continuous monitoring (`docs/continuous-monitoring.md`) |
| Automation | Threat tracer + quarantine engine (`backend/security/`) — detection-to-containment without human latency, with human oversight |

## 3. Continuous Verification (per request)

The PEP evaluates, on every request:

1. **Identity** — valid JWT, user exists, account not disabled (session revalidation).
2. **Freshness / step-up** — administrative actions (user management, quarantine release, IdP changes) require authentication age < 15 minutes.
3. **Device posture** — requests carrying sensitive roles must present a valid managed-device attestation header.
4. **Session risk** — heuristic risk score (IP change vs. issue time, impossible velocity signals from telemetry); risk ≥ threshold forces re-authentication.
5. **Authorization** — role + tenant scope checked against the resource, server-side, every time.

Fail closed: any verification failure denies the request and writes an audit record.

## 4. Micro-segmentation

- Application tier can reach only MongoDB over TLS; database binds to private interface only.
- Tenant isolation enforced per query today; database-level isolation (per-tenant roles/collections) is the tracked next step.
- Ingress allows only HTTPS; east-west traffic requires mTLS where the mesh is deployed.

## 5. Automated Response (Zero Trust loop)

`detect → trace → decide → quarantine → verify → release`:

- **Trace** (`backend/security/threat_tracer.py`): low-observability, passive correlation over existing telemetry only — no attacker-visible probing.
- **Decide**: confidence ≥ auto-threshold AND entity not on the protected allowlist.
- **Quarantine** (`backend/security/quarantine.py`): reversible containment with full audit trail.
- **Verify**: human review within 1 h (SEV-1/2); tracer confirms no IOC recurrence during the dwell window.
- **Release**: step-up-authenticated admin action restores prior state.

## 6. Roadmap

- [ ] Per-tenant database credentials / collections (database-level isolation)
- [ ] Service mesh mTLS for all east-west traffic
- [ ] OPA sidecar as the sole PDP
- [ ] Continuous access evaluation (CAE) — token revocation on IdP signals
