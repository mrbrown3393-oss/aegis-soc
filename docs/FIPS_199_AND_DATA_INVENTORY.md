# Aegis SOC — FIPS 199 Categorization & Data Inventory

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> Design-target categorization for FedRAMP Moderate diligence. **Not an agency-approved FIPS 199 decision** and **not a FedRAMP ATO**.

**Related:** `docs/FEDRAMP_MODERATE_BASELINE.md` · `docs/FEDRAMP_SECURITY_ARCHITECTURE.md` · `docs/SECURITY_POLICY_PACK.md`

---

## 1. System identification

| Field | Value |
| --- | --- |
| System name | Aegis SOC |
| System type | Multi-tenant Security Operations Center SaaS / deployable software |
| System owner | William Brown |
| Design impact level | **Moderate** (C/I/A) |
| Authorization status | **Not authorized** under FedRAMP |

---

## 2. FIPS 199 impact determination (design target)

Per FIPS 199, impact is assessed for **confidentiality**, **integrity**, and **availability** of information and information systems.

### 2.1 Potential impact definitions (summary)

| Level | Meaning (abbreviated) |
| --- | --- |
| Low | Limited adverse effect |
| Moderate | Serious adverse effect |
| High | Severe or catastrophic adverse effect |

### 2.2 Information type → impact (Aegis product boundary)

| Information type | Examples in Aegis | C | I | A | Rationale |
| --- | --- | --- | --- | --- | --- |
| Authentication material | Password hashes, JWT secrets, MFA seeds, session ids | **M** | **M** | **M** | Compromise enables account takeover; loss of availability blocks operations |
| Operator identity | Email, name, role, tenant | **M** | **M** | **L** | PII / account binding; integrity of roles is security-critical |
| Security event telemetry | Threats, severities, source IPs, geo, confidence | **M** | **M** | **M** | SOC mission data; integrity affects response; availability affects detection |
| Vulnerability & asset records | CVE refs, CVSS, asset inventory, risk scores | **M** | **M** | **M** | Guides patch priority; tampering misleads defenders |
| Incident records | Tickets, kill-chain phase, assignees, status | **M** | **M** | **M** | Response coordination; integrity and availability matter in active incidents |
| Audit logs | Actor, action, resource, IP, tenant, timestamps | **M** | **H*** | **M** | Integrity of audit is foundational to accountability (*design target High for integrity of audit trail; system overall remains Moderate until agency categorizes) |
| Compliance scores | Framework control scores per tenant | **L** | **M** | **L** | Mostly derived metrics |
| Configuration / secrets in env | `JWT_SECRET`, DB URIs, TLS paths | **H** | **H** | **M** | Handled outside app DB; compromise is severe — protected via secret manager (Customer/CSP) |

\*Audit integrity is treated as a **heightened design objective** inside a Moderate system; formal High categorization for the whole system is **not** claimed.

### 2.3 System impact level (aggregate)

| Security objective | Design impact | Driver |
| --- | --- | --- |
| Confidentiality | **Moderate** | SOC telemetry, operator PII, auth material |
| Integrity | **Moderate** | Roles, incidents, vulnerabilities, audit |
| Availability | **Moderate** | Continuous SOC operations expectation |
| **Overall (high water mark)** | **Moderate** | |

### 2.4 When High would apply

Revisit categorization if the deployment will process:

- Classified or IL4+/IL5-equivalent data  
- National security systems requiring High  
- Large-scale sensitive identity data beyond operator accounts  
- Life-safety or critical infrastructure control telemetry as the primary workload  

---

## 3. Data inventory (application layer)

### 3.1 Data stores

| Store | Engine | Tenant-scoped | Encryption in transit | Encryption at rest |
| --- | --- | --- | --- | --- |
| Application database | MongoDB | Yes (`tenant` field; logical isolation) | TLS required in production | WiredTiger config shipped; **keys Customer/CSP** |
| Auth sessions | MongoDB `auth_sessions` | By user | TLS | Same as above |
| Audit logs | MongoDB `audit_logs` | Tenant field on events | TLS | Same as above |
| Browser | Cookies only (no local token storage intended) | N/A | TLS | N/A |

### 3.2 Data elements

| Element | Category | Collection / location | Retention intent | Access |
| --- | --- | --- | --- | --- |
| Email | PII / identity | `users` | Account lifetime | Owner/admin manage users |
| Name | PII | `users` | Account lifetime | Same |
| Password hash | Authenticator | `users.password_hash` | Account lifetime; never logged/returned | Server only |
| Role, tenant | Authorization | `users` | Account lifetime | Server + privileged UI |
| Session id / refresh jti | Session | `auth_sessions` | ≤ refresh lifetime (7d) or revoke | Server |
| Source IP | Telemetry / audit | threats, audit_logs | Per AU retention targets | Scoped by tenant/role |
| Threat / incident / vuln / asset records | Mission SOC data | Respective collections | Customer-defined; product retains while tenant active | Tenant-scoped |
| Compliance framework scores | Derived | compliance | While tenant active | Tenant-scoped |
| Env secrets | Critical | Secret manager / env — **not in Git** | Rotation policy (planned) | Operators with host access |

### 3.3 Data classification mapping (policy pack)

| Policy class | Aegis examples |
| --- | --- |
| Public | Marketing site copy, public docs without secrets |
| Internal | Architecture diagrams marked UNCLASSIFIED under NDA |
| Confidential | Tenant SOC telemetry, incident details, operator PII |
| Restricted | Password hashes, JWT/MFA secrets, encryption keys, detailed audit of privileged actions |

---

## 4. Interfaces & data flows (summary)

| Flow | Data | Protection |
| --- | --- | --- |
| Browser → Ingress → API | Credentials, session cookies, API JSON | TLS; httpOnly cookies; CSRF on mutations |
| API → MongoDB | Queries, writes | Mongo TLS in production; parameterized queries |
| API → audit_logs | Security events | Append-oriented application writes |
| CI → GitHub artifacts | SBOM, scan results | Repo access controls; no production secrets in CI logs (target) |
| Future: API → Customer SIEM | Audit/export | **PLANNED**; TLS; Customer owns SIEM |

Detailed diagrams: `docs/FEDRAMP_SECURITY_ARCHITECTURE.md`.

---

## 5. Privacy notes

- Aegis stores **operator** identity (email, name) and security operational data.  
- Customer mission data in threats/incidents/assets is **Customer-owned**.  
- No advertising ID or third-party marketing trackers are part of the security control baseline.  
- Formal Privacy Impact Assessment (PIA) remains **Customer/Agency** responsibility when required.

---

## 6. Explicit non-claims

1. This worksheet is a **vendor design-target** categorization, not an Authorizing Official decision.  
2. Overall system impact is **Moderate**; individual elements (e.g., secrets, audit integrity) may warrant stricter local handling.  
3. Encryption-at-rest is not complete until keys and restore procedures are operationalized by the party running MongoDB.

---

## 7. Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial FIPS 199 design-target worksheet and application data inventory. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`
