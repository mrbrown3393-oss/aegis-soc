# Aegis SOC — Release Readiness & Buyer Technical Due Diligence

**Assessment date:** 2026-10-04  
**Platform:** Aegis SOC v2.1.0  
**Owner:** William Brown

## Executive assessment

Aegis SOC is a functioning FastAPI + MongoDB security operations platform with React frontend, cookie-based JWT sessions, TOTP MFA, RBAC, logical tenant scoping, audit logging, security middleware, MongoDB TLS configuration, security-policy artifacts, incident-response documentation, dependency scanning, SBOM generation, and security-focused CI workflows.

The platform is suitable for a serious technical demonstration and controlled buyer evaluation. It should **not** be represented as fully production-certified, FedRAMP authorized, SOC 2 certified, ISO 27001 certified, or CMMC certified.

## Current strengths

- FastAPI backend with modular routers and centralized authentication dependencies.
- React frontend with the core SOC workflows and dashboard modules.
- MFA is required by default and production startup fails closed if MFA configuration is unsafe.
- JWT access/refresh tokens are held in httpOnly cookies.
- Server-side sessions support immediate revocation and a 15-minute rolling idle timeout.
- Authenticated request rate limiting is Mongo-backed and implemented atomically.
- Brute-force, MFA, and password-reset lockout controls exist.
- CSRF origin/referer protection covers cookie-authenticated state-changing requests.
- Strict security headers are applied by middleware and an ingress configuration is documented.
- Non-owner users are hard-scoped to their own tenant at the application query layer.
- Owner-only cross-tenant access is explicit.
- Mutating routes include audit logging.
- MongoDB TLS is enforced in production configuration and WiredTiger encryption procedures are documented.
- Gitleaks, pip-audit, npm audit, Trivy, and CycloneDX SBOM generation are defined in security CI.
- The security dossier, policy pack, incident-response plan, evidence catalog, and POA&M provide a usable diligence package.

## Findings from this release-readiness pass

### 1. Authenticated rate limiter — corrected

The code and test had diverged: the test expected an atomic MongoDB find_one_and_update implementation while the live code was still using a read-then-update sequence.

This was corrected on commit e05f3e026d838c941adca04b9b87c62c38b55bf6.

The limiter now increments and evaluates the counter atomically, eliminating the race where concurrent requests could all observe the same pre-increment count.

### 2. Tenant isolation — acceptable for current architecture, not database-isolated

The API routes reviewed use tenant_filter() for reads and tenant-qualified filters for incident/vulnerability mutations. Non-owner roles cannot request another tenant through the normal API dependency path.

This is **logical/query-level isolation**, not database-level isolation. Database-level tenant isolation remains a documented roadmap item and should be treated as a buyer requirement for higher-assurance government deployments.

### 3. Federated SSO — deliberately fail closed

OIDC and SAML endpoints are present but return HTTP 503 until complete cryptographic/provider validation is implemented.

This is the correct security posture for an incomplete federation boundary. Do not enable these routes merely to make a feature checklist look complete.

Remaining requirements include signed assertion validation for SAML and issuer/audience/JWKS/signature/nonce/state/replay validation for OIDC, plus explicit tenant and role mapping.

### 4. JWT signing-key rotation — remaining gap

The current implementation uses a single configured HS256 signing secret. Two-active-key rotation is still a POA&M item.

This should be completed before claiming mature enterprise key lifecycle management.

### 5. Motor → PyMongo Async migration — remaining engineering item

The application still uses Motor. Motor is being retained as an interim pinned dependency while the migration to the native PyMongo Async API is tracked separately.

The migration should be completed before a long-lived production support commitment.

### 6. CI verification — not currently evidenced for the latest direct commit

The repository contains GitHub Actions CI and security workflows, but the latest hardening commit did not have an associated workflow run or status returned by GitHub at the time of this assessment.

Therefore this document makes **no claim that CI passed for commit e05f3e026d838c941adca04b9b87c62c38b55bf6**.

A clean CI run should be captured before presenting the repository as a release candidate.

### 7. Legacy Node/Express concern

The current backend tree is FastAPI-based and does not contain the previously discussed Node/Express service. The current architecture should therefore be evaluated as the FastAPI implementation rather than as the earlier Express implementation.

## Buyer-facing readiness

**Ready now:** architecture walkthrough, controlled demo, source-code review under NDA, security-control walkthrough, deployment discussion, and commercial licensing discussion.

**Not ready to claim:** formal compliance certification, completed enterprise SAML/OIDC federation, database-level tenant isolation, independently verified penetration-test results, or fully verified CI on the latest commit.

## Recommended release sequence

1. Obtain a clean CI/security run for the current main branch.
2. Finish JWT key rotation.
3. Complete the Motor → PyMongo Async migration.
4. Add stronger tenant-boundary integration tests covering every authenticated router.
5. Complete OIDC and SAML only when the cryptographic validation and replay protections are fully implemented.
6. Add an external penetration test before making a high-assurance production claim.
7. Establish branch protection and required status checks.
8. Package the evidence catalog, POA&M, architecture diagram, deployment checklist, and commercial license as the buyer diligence set.

## Commercial positioning

The strongest present claim is:

> Aegis SOC is a commercially owned security operations platform with a substantial implemented security baseline and a documented enterprise hardening roadmap. It is ready for technical buyer evaluation and controlled deployment work, with remaining gaps explicitly disclosed.

That is materially stronger and more defensible than presenting Aegis as already certified or fully enterprise-complete.
