# Aegis SOC Zero Trust Architecture

## Purpose

Aegis SOC follows a Zero Trust model for the application/API boundary: no protected request is trusted solely because it reached the application, came from a known network, or carries a previously issued JWT.

Every protected request must present a valid access session. The server revalidates that session against MongoDB, re-fetches the current user record, enforces role and tenant policy, and applies authenticated request-rate controls.

## Controls implemented

### 1. Fail-closed API boundary

ZeroTrustMiddleware rejects protected /api/* requests that do not contain an access-session cookie. Public exceptions are limited to authentication bootstrap, password-reset bootstrap, MFA bootstrap, and the explicitly handled federated SSO routes.

This is defense in depth. Route dependencies remain responsible for actual authentication and authorization.

### 2. Continuous session validation

get_current_user() validates the JWT and then revalidates the corresponding server-side session. Revoked, expired, or missing sessions are rejected even if the JWT has not yet expired.

Idle-session enforcement remains active through the existing server-side session policy.

### 3. Device/browser context binding

A privacy-preserving SHA-256 fingerprint is derived from browser/device headers. The first protected use of a legacy session enrolls its fingerprint. Subsequent requests with a changed security context revoke the session and return HTTP 401.

Raw user-agent/header values are not stored.

### 4. MFA

Production configuration already requires MFA. Because access sessions are created only after MFA verification when MFA_REQUIRED=true, the Zero Trust layer treats the resulting server-side session as the trusted authentication context.

MFA enrollment secrets remain encrypted at rest using the existing AES-GCM implementation.

### 5. Tenant isolation

Non-owner roles remain hard-scoped to their assigned tenant. Owner cross-tenant access remains possible because the owner role is the platform-level administrative authority, but a tenant query must explicitly name the requested tenant when a narrower scope is selected.

Database-level tenant isolation remains a future hardening step; current isolation is enforced at application query scope.

### 6. Request correlation

Every request receives an X-Request-ID. The same identifier is written into the audit record, allowing an operator to correlate a user action with its application request.

## Security posture

This implementation is an application-layer Zero Trust control set. It does not by itself constitute FedRAMP, CMMC, FIPS, SOC 2, ISO 27001, or any other certification.

The next hardening phase should add explicit step-up authentication for especially destructive administrative actions, formal session-risk scoring, stronger machine-to-machine identity, and database/service-level tenant isolation.