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

## Phase 3: trusted ingress enforcement

Phase 3 adds a concrete Nginx integration using the standard auth_request module. The
ingress performs an internal subrequest to the edge before proxying traffic to Aegis.
A 204 response permits the request; an edge deny (403) or edge failure blocks the
request before the application is reached. Nginx then copies only the signed decision
headers returned by the trusted edge into the upstream Aegis request.

The reference template is `ops/ingress/nginx-edge.template.conf`. It deliberately:

1. Clears client-supplied `X-Aegis-Edge-*` headers.
2. Sends the original method, normalized URI path, and connection client IP to the edge.
3. Authenticates the ingress-to-edge call with `EDGE_INGRESS_TOKEN` when rendered.
4. Copies the edge's signed decision, signature, and client IP into the Aegis request.
5. Fails closed when the edge returns 401/403 or an unexpected status.
6. Keeps the edge endpoint internal and does not expose it as a public route.

The backend continues to verify the signed decision, so the ingress is not an
authorization authority. The signed decision is bound to the path rather than the
query string because Aegis verifies `request.url.path`; query parameters remain
available to the application independently.

The template assumes Nginx is the public TLS terminator and that `$remote_addr`
represents the real client address. If another load balancer sits in front of Nginx,
configure Nginx's real-IP trust list with only that load balancer's documented
source networks. Never trust an arbitrary client-supplied forwarding header.

Nginx must be built with `ngx_http_auth_request_module`; the module authorizes a
request from the status of an internal subrequest and can expose its upstream
response headers through `auth_request_set`.

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
