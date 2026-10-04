# Aegis SOC — FedRAMP Security Architecture Diagrams

**Document version**: 1.0  
**Platform version**: v2.1.0  
**Aligned to**: `docs/FEDRAMP_MODERATE_BASELINE.md` · `docs/FEDRAMP_CRM_AND_PARAMETERS.md`  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Classification**: UNCLASSIFIED — Shareable under NDA for buyer / investor / contracting diligence

> **Not an SSP diagram package and not evidence of FedRAMP authorization.**  
> These diagrams describe the *intended* Moderate-aligned security architecture for diligence and engineering alignment.

Mermaid diagrams render on GitHub. For slides or print, export from any Mermaid-compatible tool.

---

## 1. Authorization boundary (context)

High-level system context: who sits outside the Aegis product boundary, and what crosses it.

```mermaid
flowchart TB
  subgraph AGENCY["Agency / Customer responsibility"]
    USERS["Operators & analysts\n(PIV/IdP proofing — Customer)"]
    ATO["Agency ATO / ConMon program"]
    CLASS["Data classification & legal holds"]
  end

  subgraph BOUNDARY["Aegis authorization boundary — product"]
    UI["React console\n(Vite / TypeScript)"]
    API["FastAPI /api\nJWT · MFA · RBAC · CSRF · headers"]
    DATA["Tenant-scoped data plane\nthreats · incidents · assets · audit"]
  end

  subgraph DATASTORE["Data store"]
    MONGO["MongoDB\nTLS client · WiredTiger config\nKeys outside Git — Customer/CSP"]
  end

  subgraph CSP["CSP / Host — inherited unless Aegis is CSP"]
    EDGE["Ingress / TLS termination\nWAF · DDoS · DNS"]
    COMPUTE["Compute / K8s / VMs"]
    PE["PE · facility · region"]
  end

  USERS -->|HTTPS| EDGE
  EDGE --> UI
  UI -->|httpOnly cookies · same-origin API| API
  API -->|TLS required in production| MONGO
  API --- DATA
  ATO -.->|evidence / logs| API
  CLASS -.-> DATA
  COMPUTE --- API
  COMPUTE --- MONGO
  PE --- COMPUTE
```

**Boundary statement:** The Aegis product boundary includes the web console, API, application security controls, logical tenant filtering, and application-generated audit events. Physical controls, hypervisor, and edge DDoS are **inherited** from the CSP unless Aegis operates the host under contract (CRM Variant B).

---

## 2. Trust zones

```mermaid
flowchart LR
  subgraph Z0["Zone 0 — Untrusted"]
    INT["Internet"]
  end

  subgraph Z1["Zone 1 — Edge"]
    ING["TLS ingress\nHSTS · optional WAF"]
  end

  subgraph Z2["Zone 2 — Application"]
    FE["Frontend static assets"]
    BE["API process\nAuthn/z · validation · audit"]
  end

  subgraph Z3["Zone 3 — Data"]
    DB["MongoDB\nTLS · encryption-at-rest keys"]
  end

  subgraph Z4["Zone 4 — Management optional"]
    MGMT["Admin / break-glass\nCustomer ZTNA or bastion"]
  end

  INT -->|443 only| ING
  ING --> FE
  ING --> BE
  BE -->|private path · TLS| DB
  MGMT -.->|restricted| BE
  MGMT -.->|restricted| DB
```

| Zone | Trust | Primary controls |
| --- | --- | --- |
| 0 Untrusted | None | External clients, attackers |
| 1 Edge | Low | TLS 1.2+, HSTS, CSP headers, rate limits (planned), WAF (CSP/Customer) |
| 2 Application | Medium | MFA, JWT sessions, RBAC, tenant filter, CSRF origin guard, Pydantic validation |
| 3 Data | High | Mongo TLS, WiredTiger encryption config, least-privilege DB user (buyer ops) |
| 4 Management | Highest | Not product-default; Customer network isolation for host admin |

---

## 3. Logical component architecture

```mermaid
flowchart TB
  CLIENT["Browser operator"]

  subgraph FE["Presentation"]
    REACT["React 19 console\nOverview · Threats · Incidents\nAssets · Compliance · Audit · Users"]
  end

  subgraph BE["Application services — FastAPI"]
    AUTH["Auth\nlogin · refresh · logout\nMFA TOTP · password reset"]
    SSO["SSO surface\nSAML/OIDC — fail closed\nuntil configured"]
    RBAC["RBAC + tenant_filter\nowner · admin · analyst · viewer"]
    MOD["Domain modules\nthreats · vulns · incidents\nassets · compliance · metrics"]
    AUD["write_audit\nactor · IP · resource · tenant"]
    HDR["SecurityHeadersMiddleware\nCSP · HSTS · XFO · nosniff"]
    CSRF["csrf_origin_guard\nOrigin/Referer on mutations"]
  end

  subgraph STORE["Persistence"]
    USERS[(users)]
    SESS[(auth_sessions)]
    LOGS[(audit_logs)]
    TENANT[(tenant collections\nthreats · incidents · assets · …)]
  end

  CLIENT --> REACT
  REACT -->|httpOnly cookies| AUTH
  REACT --> MOD
  AUTH --> SESS
  AUTH --> USERS
  AUTH --> SSO
  MOD --> RBAC
  RBAC --> TENANT
  AUTH --> AUD
  MOD --> AUD
  AUD --> LOGS
  HDR --- BE
  CSRF --- BE
```

---

## 4. Authentication & session flow

```mermaid
sequenceDiagram
  actor Op as Operator
  participant UI as Console
  participant API as FastAPI
  participant DB as MongoDB

  Op->>UI: Submit credentials
  UI->>API: POST /api/auth/login
  API->>DB: Verify bcrypt hash · check lockout
  alt MFA required
    API-->>UI: MFA pending cookie (5m)
    Op->>UI: TOTP code
    UI->>API: MFA verify
  end
  API->>DB: Create auth_sessions row
  API-->>UI: Set access_token 15m · refresh_token 7d
  Note over UI,API: httpOnly · Secure · SameSite strict in production

  Op->>UI: API action
  UI->>API: Request + cookies
  API->>API: CSRF origin check if mutating
  API->>DB: Validate session not revoked
  API->>DB: Load user · enforce role + tenant_filter
  API->>DB: write_audit on mutation
  API-->>UI: Response + security headers
```

**Controls illustrated:** AC-7 lockout, IA-2 MFA, AC-12 session binding, SC-23 session authenticity, AU-2 audit generation, AC-3 enforcement.

---

## 5. Multi-tenant data isolation (current vs roadmap)

```mermaid
flowchart TB
  subgraph CURRENT["Current — logical / query-level isolation"]
    API1["API request + user.tenant + role"]
    TF["tenant_filter()\nowner: optional cross-tenant\nall others: hard-scoped"]
    ONE[(Single MongoDB database\ntenant field on each document)]
    API1 --> TF --> ONE
  end

  subgraph ROADMAP["Roadmap — database-level isolation"]
    API2["API — same contract"]
    P1["Phase 1: collection prefix per tenant"]
    P2["Phase 2: database per tenant"]
    P3["Phase 3: cluster / namespace per tenant"]
    API2 --> P1 --> P2 --> P3
  end
```

**FedRAMP note:** Logical isolation is acceptable for many Moderate SaaS patterns when enforced server-side and tested; high-side or high-sensitivity agency deployments should plan Phase 2+ per dossier §5.5.

---

## 6. Data flow — security-relevant events

```mermaid
flowchart LR
  subgraph IN["Ingress events"]
    L["Login success/fail"]
    M["Mutating API calls"]
    Q["Quarantine requests"]
  end

  subgraph APP["Application"]
    IP["forwarded_client_ip\nTRUSTED_PROXY_IPS"]
    POL["Policy: role + tenant"]
    AUD["audit_logs append"]
  end

  subgraph OUT["Outputs"]
    UI["Audit Logs module / CSV"]
    SIEM["SIEM forward — PLANNED"]
    POAM["POA&M / IR evidence"]
  end

  L --> IP --> AUD
  M --> POL --> AUD
  Q --> POL --> AUD
  AUD --> UI
  AUD -.-> SIEM
  AUD --> POAM
```

---

## 7. Shared responsibility layers

```mermaid
block-beta
  columns 3

  block:layer4:3
    columns 1
    A["Layer 4 — Mission & authorization\nAgency ATO · ConMon sponsorship · data classification · user proofing"]
  end

  block:layer3:3
    columns 1
    B["Layer 3 — Aegis application\nConsole · API · MFA/RBAC/tenancy · audit generation · app headers · SBOM/CI"]
  end

  block:layer2:3
    columns 1
    C["Layer 2 — Data platform ops\nMongo TLS certs · WiredTiger keys · backups · restore drills · DB users"]
  end

  block:layer1:3
    columns 1
    D["Layer 1 — Infrastructure / CSP\nCompute · network · PE · edge DDoS · host patching · region"]
  end

  A --> B
  B --> C
  C --> D
```

| Layer | Primary owner (Variant A: customer-hosted) |
| --- | --- |
| 4 Mission | Customer / Agency |
| 3 Application | **Aegis** |
| 2 Data platform ops | **Customer** (with Aegis config/runbooks) |
| 1 Infrastructure | **CSP / Customer** |

See CRM: `docs/FEDRAMP_CRM_AND_PARAMETERS.md`.

---

## 8. Encryption & key points

```mermaid
flowchart TB
  subgraph TRANSIT["In transit"]
    BROWSER["Browser"] -->|TLS 1.2+ / 1.3 preferred| INGRESS["Ingress"]
    INGRESS --> API["API"]
    API -->|MONGO_TLS required in production| MONGO["MongoDB"]
  end

  subgraph REST["At rest"]
    KEY["Encryption key\nSecret manager — never in Git"] --> WT["WiredTiger encryption\nops/mongodb config"]
    WT --> VOL["Data volume"]
  end

  subgraph APPSEC["Application secrets"]
    ENV["JWT_SECRET · MFA_MASTER_SECRET\nAdmin passwords — env / secret store"]
  end
```

**SC-28 honesty:** Shipping `ops/mongodb/` configuration is **not** complete encryption-at-rest until keys are provisioned and restore/decryption is tested by the party operating MongoDB.

---

## 9. CI/CD security supply chain (platform build)

```mermaid
flowchart LR
  DEV["Developer"] --> GIT["GitHub"]
  GIT --> CI["GitHub Actions"]
  CI --> GL["Gitleaks"]
  CI --> PA["pip-audit / npm audit"]
  CI --> TR["Trivy fs\nCRITICAL/HIGH fail"]
  CI --> SBOM["CycloneDX SBOM"]
  CI --> TEST["pytest security suite"]
  SBOM --> ART["Artifacts"]
  TEST --> ART
  ART --> DEP["Deploy — Customer/CSP pipeline"]
```

Build-time controls support CM-8, RA-5, SI-2, SR-3/SR-4. Runtime host scanning remains Customer/CSP per CRM.

---

## 10. Deployment variant overlay

```mermaid
flowchart TB
  subgraph VA["Variant A — Customer-hosted"]
    A1["Customer/CSP runs K8s + Mongo"]
    A2["Aegis supplies software + hardening docs"]
    A3["Customer owns keys, backups, edge"]
  end

  subgraph VB["Variant B — Aegis-operated SaaS"]
    B1["Aegis or contracted CSP runs stack"]
    B2["CRM shifts: many Host rows → Aegis"]
    B3["Requires revised CRM before package use"]
  end
```

---

## 11. Diagram-to-control index

| Diagram § | Primary 800-53 / FedRAMP themes |
| --- | --- |
| 1 Boundary | Authorization boundary, inheritance |
| 2 Trust zones | SC-7, SC-8, AC-17 |
| 3 Components | CM-8 inventory view |
| 4 Auth sequence | IA-2, IA-5, AC-7, AC-12, SC-23, AU-2 |
| 5 Tenancy | AC-3, AC-4, AC-6 |
| 6 Audit flows | AU-2, AU-3, AU-6, CA-7 |
| 7 Shared layers | CRM / PL-2 narrative |
| 8 Encryption | SC-8, SC-12, SC-13, SC-28 |
| 9 CI/CD | RA-5, CM-8, SI-2, SR-3, SR-4 |
| 10 Variants | Deployment model for SSP |

---

## 12. Explicit non-claims

1. Diagrams are **design-target architecture**, not a statement of residual risk acceptance.  
2. No FedRAMP ATO is implied.  
3. CSP boxes are illustrative; real inheritance comes from the CSP’s authorization package.  
4. SSO and PIV paths are shown as surfaces or planned capabilities, not completed federal IdP integrations.

---

## 13. Related documents

| Document | Path |
| --- | --- |
| FedRAMP Moderate baseline | `docs/FEDRAMP_MODERATE_BASELINE.md` |
| CRM & parameters | `docs/FEDRAMP_CRM_AND_PARAMETERS.md` |
| Security dossier | `SECURITY_DOSSIER.md` |
| NIST 800-53 appendix | `NIST_ALIGNMENT.md` |
| Security entry point | `SECURITY.md` |

---

## 14. Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial FedRAMP security architecture diagrams (boundary, zones, components, auth sequence, tenancy, audit, shared responsibility, encryption, CI/CD, variants). | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`

© 2026 Aegis SOC · All rights reserved
