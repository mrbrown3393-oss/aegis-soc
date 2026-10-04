# Aegis SOC — Configuration Management Plan

**Document version**: 1.0  
**Owner**: Security Engineering  
**Related controls:** CM-2, CM-3, CM-6, CM-8, CM-9

---

## 1. Purpose

Define how Aegis software baselines are identified, changed, reviewed, and released.

---

## 2. Configuration items (CIs)

| CI | Location | Baseline identity |
| --- | --- | --- |
| Application source | GitHub `aegis-soc` | Commit SHA, semver tag when cut |
| Backend dependencies | `backend/requirements.txt` | File hash + SBOM |
| Frontend dependencies | `client/package.json` / lockfile | Lockfile + SBOM |
| Security workflows | `.github/workflows/*` | Commit SHA |
| Mongo hardening config | `ops/mongodb/` | Commit SHA |
| Ingress header template | `ops/ingress/` | Commit SHA |
| Deployed env parameters | Secret manager + env | Versioned secret names |

---

## 3. Baselines

- **Development:** mutable; feature branches  
- **Mainline:** `main` branch; protected when POAM-011 closed  
- **Release:** annotated tags `vX.Y.Z` + SBOM artifact  
- **Production runtime:** image digest + config version recorded in change ticket  

---

## 4. Change process

1. **Propose** — issue or PR describing security impact.  
2. **Implement** — branch from `main`.  
3. **Verify** — CI must pass (`ci.yml`, `security.yml`).  
4. **Review** — at least one reviewer for security-sensitive paths (`backend/server.py`, auth, workflows).  
5. **Merge** — to `main`.  
6. **Release** — tag if production-bound.  
7. **Deploy** — Customer/CSP pipeline; complete deployment hardening checklist.  
8. **Record** — change ticket + POA&M updates if control posture changes.  

**Emergency changes:** same controls after-the-fact within 24h; document in IR/POA&M if security-related.

---

## 5. Security-sensitive paths (mandatory review)

- `backend/server.py`  
- `backend/security_hardening.py`  
- `backend/sso.py`  
- `.github/workflows/security.yml`  
- `ops/mongodb/**`  
- Auth/session cookie logic  

---

## 6. Inventory & SBOM

Every security workflow run produces CycloneDX JSON for Python and Node. Retain artifacts with the release record.

---

## 7. Tools

| Function | Tool |
| --- | --- |
| VCS | GitHub |
| CI | GitHub Actions |
| Dependency update | Dependabot |
| Scanning | Gitleaks, Trivy, pip-audit, npm audit |

---

## 8. Roles

| Role | Duty |
| --- | --- |
| Developer | Implement + test |
| Reviewer | Approve PR quality/security |
| SecEng | Policy, scanning gates, POA&M |
| Deployment owner | Production apply + checklist |

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial CM plan |
