import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { store } from '../data/store.js';

export function authenticate(req, res, next) {
  const token = req.cookies?.['__Host-aegis_session'];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const payload = jwt.verify(token, config.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'aegis-soc',
      audience: 'aegis-soc-api'
    });
    const user = store.users.find(u => u.id === payload.sub);
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid or inactive user' });
    if (payload.role !== user.role || payload.tenant !== user.tenant) return res.status(401).json({ error: 'Invalid session' });
    req.user = { id: user.id, email: user.email, name: user.name, role: user.role, tenant: user.tenant };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

export function tenantScope(user, item) {
  return user.role === 'admin' || user.role === 'owner' || item.tenant === user.tenant;
}

export function scoped(list, user) {
  return list.filter(item => tenantScope(user, item));
}
