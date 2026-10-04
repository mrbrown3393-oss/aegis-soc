# Aegis SOC — Rules of Behavior

**Document version**: 1.0  
**Effective**: 2026-10-04  
**Owner**: William Brown (`william.brown@aegis-soc.io`)  
**Applies to**: All operators, administrators, and service accounts using Aegis SOC

> Acceptable-use rules for the Aegis console and API. Customer organizations may impose stricter rules.

---

## 1. Purpose

Protect the confidentiality, integrity, and availability of Aegis SOC, customer security data, and related credentials.

---

## 2. Access and accounts

1. Use only the account issued to you; **no shared passwords**.  
2. Protect credentials and MFA devices; report loss immediately.  
3. Use MFA whenever prompted; do not disable or bypass MFA.  
4. Select the minimum role required (viewer / analyst / admin).  
5. Log out of shared or untrusted workstations when finished.  
6. Do not attempt to access tenants or data outside your authorization.

---

## 3. Acceptable use

1. Use Aegis only for authorized security operations and administration.  
2. Do not run vulnerability scans, exploits, or offensive actions **against** the Aegis platform unless explicitly approved in writing as a test.  
3. Do not export or exfiltrate tenant data except through approved channels and authority.  
4. Do not upload malware, unlawful content, or credentials into tickets/fields.  
5. Do not probe, disrupt, or overload the service (except approved performance tests).

---

## 4. Data handling

1. Treat SOC telemetry, incidents, and audit logs as **Confidential** or higher per policy.  
2. Do not post sensitive data to personal email, chat, or public repos.  
3. Follow customer retention and legal-hold instructions.  
4. Report suspected data exposure under the Incident Response Plan.

---

## 5. Remote and network access

1. Access the console only over trusted networks and HTTPS endpoints.  
2. Do not disable or ignore browser or platform security warnings without reporting them.  
3. Follow customer VPN/ZTNA requirements when provided.

---

## 6. Monitoring and privacy

1. Understand that **login, access, and administrative actions are logged**.  
2. Logs may be reviewed for security, operations, and compliance.  
3. There is no expectation of personal privacy in operational use of Aegis.

---

## 7. Incident reporting

Report immediately to the system owner or designated security contact:

- Suspected account compromise  
- Malware on an admin workstation  
- Unauthorized access or data leakage  
- Critical vulnerabilities discovered in Aegis  

Contact: `william.brown@aegis-soc.io`  
Platform IR plan: `docs/INCIDENT_RESPONSE_PLAN.md`

---

## 8. Consequences

Violation may result in account suspension, removal of access, contractual remedies, and referral for legal action where applicable.

---

## 9. Acknowledgment

By using Aegis SOC, you acknowledge that you have read and agree to these Rules of Behavior. Customer deployments may require a signed acknowledgment record.

---

## Revision History

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-10-04 | Initial Rules of Behavior. | William Brown / Grok |

---

**William Brown** · Owner & Operator — Aegis SOC  
Email: `william.brown@aegis-soc.io`
