# Aegis SOC Remote Security Edge

The remote security edge is a separate trust boundary that sits in front of Aegis SOC. It is deliberately not an alternate authentication authority.

Phase 1 provides a deployable admission-decision service with:

- bounded per-client rate tracking
- risk scoring for sensitive methods and paths
- fail-closed behavior for high-risk requests
- short-lived (15 second) decisions
- HMAC-SHA256 signed decisions
- strict client-IP validation
- a health endpoint for ingress orchestration

The edge does not receive Aegis passwords, refresh tokens, tenant secrets, or database credentials.

## Phase 2: signed enforcement contract

Phase 2 binds each admission decision to the exact HTTP method, path, client IP,
audience, nonce, and 15-second validity window. Aegis verifies the HMAC-SHA256
signature before application routing when EDGE_ENFORCE_DECISION=true.

The trusted ingress must:

1. Strip any client-supplied X-Aegis-Edge-* headers before calling Aegis.
2. Obtain the client IP from the ingress connection/proxy trust boundary.
3. Call the edge admission endpoint over a private authenticated channel.
4. Forward the returned decision as X-Aegis-Edge-Decision and
   X-Aegis-Edge-Signature.
5. Forward the signed client IP as X-Aegis-Edge-Client-IP.
6. Reject the request when the edge returns allow=false or the edge is unavailable.
7. Never expose EDGE_VERIFY_SECRET or EDGE_SIGNING_SECRET to browsers.

Aegis rejects missing, forged, expired, future-dated, wrong-audience, wrong-method,
wrong-path, wrong-client-IP, or replayed decisions. The edge therefore supplies
security context, while Aegis remains the authorization authority.

The admission endpoint supports an optional Bearer EDGE_INGRESS_TOKEN for
service-to-service caller authentication. Production deployments should set it
and keep the edge reachable only from the trusted ingress network. mTLS between
ingress and edge remains a later defense-in-depth phase.

The intended production flow is:

1. Client reaches the remote edge.
2. Edge evaluates request metadata and rate/risk signals.
3. Edge returns a short-lived signed admission decision.
4. The trusted ingress passes the decision to Aegis.
5. Aegis independently validates the user's session, device binding, MFA, tenant and RBAC controls.
6. High-risk traffic is rejected before it reaches the application.

This preserves the Zero Trust rule that the edge can reduce trust, but it cannot grant application authorization.

## Deployment requirements

Set EDGE_SIGNING_SECRET to a randomly generated secret of at least 32 characters. Do not reuse JWT, MFA, database or application secrets.

The in-memory rate state is intentionally a Phase 1 control. A production multi-instance deployment should move rate state to a shared, authenticated store such as Redis before claiming globally consistent edge rate limiting.

## Next phases

- signed edge-context verification inside Aegis
- reverse-proxy integration so blocked requests never reach the application
- shared rate state for multi-node edge clusters
- reputation/threat-intelligence inputs
- adaptive anomaly scoring
- live security-event streaming into the Aegis SOC dashboard
