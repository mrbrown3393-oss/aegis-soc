/**
 * Aegis SOC — Strict security headers middleware (Node/Express edge).
 * Applies a hardened Helmet profile; see deploy/k8s/ingress.yaml for the
 * ingress-level duplicate (defense in depth).
 */
import helmet from 'helmet';

export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Vite injects some inline styles
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", 'wss:', 'https:'],
        fontSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: []
      }
    },
    strictTransportSecurity: {
      maxAge: 63072000, // 2 years
      includeSubDomains: true,
      preload: true
    },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    originAgentCluster: true,
    xContentTypeOptions: true,  // X-Content-Type-Options: nosniff
    xDnsPrefetchControl: { allow: false },
    xDownloadOptions: true,
    xFrameOptions: { action: 'deny' },
    xPermittedCrossDomainPolicies: { permittedPolicies: 'none' },
    xPoweredBy: false
  });
}

/** Additional non-Helmet headers applied to every response. */
export function extraSecurityHeaders(_req, res, next) {
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
}
