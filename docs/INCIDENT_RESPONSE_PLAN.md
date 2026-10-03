# Aegis SOC Platform Incident Response Plan

Version: 1.0 | Effective: 2026-10-03

## Scope
This plan covers compromise, credential abuse, data exposure, malicious code, denial of service, supply-chain vulnerabilities, unauthorized access, and security-control failures affecting Aegis SOC.

## Severity
SEV-1: confirmed compromise, material data exposure, destructive activity, or prolonged loss of a critical security function.
SEV-2: credible compromise or high-impact vulnerability with limited containment.
SEV-3: contained security event or moderate vulnerability.
SEV-4: low-impact event, policy violation, or informational finding.

## Roles
Incident Commander coordinates response. Security Lead directs containment and evidence collection. Service Owner coordinates recovery. Communications Owner handles approved customer/regulatory communications. One operator may perform multiple roles, but role separation remains the operating model.

## Lifecycle
1. Prepare: maintain inventories, backups, contacts, access controls, logging, and test procedures.
2. Detect/report: create an incident record and preserve initial indicators.
3. Analyze: establish scope, affected tenants/assets, indicators, timeline, and confidence.
4. Contain: revoke compromised sessions/credentials, quarantine affected assets, isolate vulnerable components, and apply temporary controls.
5. Eradicate: remove malicious persistence, patch/replace vulnerable dependencies, rotate affected secrets, and validate clean state.
6. Recover: restore from trusted backups when required and monitor heightened telemetry.
7. Lessons learned: document root cause, evidence, impact, corrective actions, and control updates.

## Evidence
Preserve original logs and relevant telemetry. Record who collected each artifact, when, from where, and its cryptographic hash where feasible. Do not conceal or silently delete evidence.

## Communications
Escalate immediately for SEV-1/SEV-2. Customer and regulator notifications follow contractual and legal obligations. Public statements require owner approval and distinguish confirmed facts from hypotheses.

## Review
Review after every SEV-1/SEV-2 incident and at least annually.
