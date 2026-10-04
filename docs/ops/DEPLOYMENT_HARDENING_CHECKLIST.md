# Aegis SOC — Deployment Hardening Checklist (Security Engineer)

**Document version**: 1.0  
**Use before:** production go-live or major environment promotion

---

## 1. Environment & secrets

- [ ] `AEGIS_ENV=production`  
- [ ] `JWT_SECRET` strong, unique, from secret manager  
- [ ] `MFA_REQUIRED=true`  
- [ ] `MFA_MASTER_SECRET` strong, unique  
- [ ] Admin/analyst passwords not defaults; rotated post-bootstrap  
- [ ] No secrets in Git, CI logs, or container env dumps  
- [ ] `FRONTEND_URL` is `https://...`  
- [ ] `CORS_ORIGINS` explicit; no `*`  

## 2. Database

- [ ] `MONGO_TLS=true`  
- [ ] `MONGO_TLS_ALLOW_INVALID_CERTS=false`  
- [ ] CA/client cert paths mounted as secrets  
- [ ] WiredTiger encryption key provisioned per `ops/mongodb/`  
- [ ] App DB user is least-privilege (no clusterAdmin for app)  
- [ ] Backup job scheduled; destination encrypted  

## 3. Network & edge

- [ ] TLS 1.2+ at ingress; HTTP→HTTPS redirect  
- [ ] Security headers present (HSTS, CSP, XFO, nosniff)  
- [ ] `TRUSTED_PROXY_IPS` set if behind LB  
- [ ] NetworkPolicies / SGs restrict Mongo to app only  
- [ ] Admin interfaces not on public Internet without ZTNA/VPN  

## 4. Application

- [ ] Production rejects weak settings at startup (smoke test)  
- [ ] `/docs` disabled or restricted in production  
- [ ] Health check monitored  
- [ ] Log shipping path defined (even if interim)  

## 5. Identity

- [ ] MFA enrollment verified for all privileged users  
- [ ] SSO left fail-closed unless fully configured and tested  
- [ ] Owner account recovery procedure documented  

## 6. Supply chain

- [ ] Deployed artifact matches CI-built version / digest  
- [ ] SBOM retained for release  
- [ ] No CRITICAL/HIGH unresolved vulns without POA&M entry  

## 7. People & process

- [ ] Operators acknowledged Rules of Behavior  
- [ ] IR contacts filled for this deployment  
- [ ] POA&M reviewed for environment-specific items  

## Sign-off

| Role | Name | Date | Result |
| --- | --- | --- | --- |
| Security Engineer | | | |
| Deployment Owner | | | |

---

## Revision History

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-10-04 | Initial checklist |
