from __future__ import annotations
from ipaddress import ip_address, ip_network
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        headers = {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Content-Security-Policy": "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https:; upgrade-insecure-requests",
        }
        for key, value in headers.items():
            response.headers.setdefault(key, value)
        return response

def forwarded_client_ip(request: Request, trusted_proxy_ips: str) -> str:
    peer = request.client.host if request.client else "unknown"
    trusted = []
    for raw in trusted_proxy_ips.split(","):
        raw = raw.strip()
        if not raw: continue
        try: trusted.append(ip_network(raw, strict=False))
        except ValueError: continue
    try: peer_ip = ip_address(peer)
    except ValueError: return peer
    if any(peer_ip in network for network in trusted):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Walk the proxy chain from the immediate peer toward the client.
            # The first address that is not itself in a trusted proxy network is
            # the client address. Taking the left-most value is spoofable when
            # an untrusted client can inject an extra X-Forwarded-For entry.
            chain = [part.strip() for part in forwarded.split(",") if part.strip()]
            for candidate in reversed(chain):
                try:
                    candidate_ip = ip_address(candidate)
                except ValueError:
                    continue
                if not any(candidate_ip in network for network in trusted):
                    return candidate
            # If every forwarded hop is trusted, retain the peer rather than
            # trusting an ambiguous client-supplied chain.
    return peer
