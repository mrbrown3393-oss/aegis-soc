import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from '../config.js';
import { store, addAudit } from '../data/store.js';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/auth.js';

const router = Router();
const loginAttempts = new Map();
const mfaAttempts = new Map();
const MFA_STEP = 30;

const loginSchema = z.object({ body: z.object({ email: z.string().email(), password: z.string().min(8) }) });
const mfaSchema = z.object({ body: z.object({ code: z.string().regex(/^\d{6}$/) }) });

function b32(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function mfaSecretFor(user) {
  if (config.MFA_MASTER_SECRET.length < 32) {
    if (config.NODE_ENV === 'production') throw new Error('MFA master secret is not configured');
    return b32(Buffer.from(createHmac('sha256', 'development-only-mfa-master').update(user.id).digest()));
  }
  return b32(createHmac('sha256', config.MFA_MASTER_SECRET).update(user.id).digest());
}
function totp(secretB32, timestamp = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0; const bytes = [];
  for (const ch of secretB32.replace(/=+$/, '').toUpperCase()) {
    const idx = alphabet.indexOf(ch); if (idx < 0) throw new Error('Invalid MFA secret');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const key = Buffer.from(bytes);
  const counter = Math.floor(timestamp / 1000 / MFA_STEP);
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const bin = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(bin % 1000000).padStart(6, '0');
}
function verifyTotp(secret, code) {
  const now = Date.now();
  for (const drift of [-1, 0, 1]) {
    const expected = totp(secret, now + drift * MFA_STEP * 1000);
    const a = Buffer.from(expected); const b = Buffer.from(code);
    if (a.length === b.length && timingSafeEqual(a, b)) return true;
  }
  return false;
}
function signSession(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, tenant: user.tenant, mfa: true },
    config.JWT_SECRET,
    { expiresIn: config.JWT_EXPIRES_IN, algorithm: 'HS256', issuer: 'aegis-soc', audience: 'aegis-soc-api' }
  );
}
function setSession(res, token) {
  res.cookie(config.SESSION_COOKIE, token, {
    httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE,
    path: '/', maxAge: 15 * 60 * 1000
  });
}
function setPending(res, user) {
  const token = jwt.sign({ sub: user.id, role: user.role, tenant: user.tenant, type: 'mfa_pending' }, config.JWT_SECRET, {
    expiresIn: '5m', algorithm: 'HS256', issuer: 'aegis-soc', audience: 'aegis-soc-api'
  });
  res.cookie(config.MFA_COOKIE, token, {
    httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE, path: '/', maxAge: 5 * 60 * 1000
  });
}
function clearPending(res) {
  res.clearCookie(config.MFA_COOKIE, { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE, path: '/' });
}
function clientKey(req, email) { return `${req.ip}:${email.toLowerCase()}`; }
function checkLockout(req, email) {
  const item = loginAttempts.get(clientKey(req, email));
  if (item && item.until > Date.now()) return true;
  return false;
}
function recordFailure(req, email) {
  const key = clientKey(req, email); const item = loginAttempts.get(key) || { count: 0, until: 0 };
  item.count += 1; if (item.count >= 5) item.until = Date.now() + 15 * 60 * 1000;
  loginAttempts.set(key, item);
}
function clearFailures(req, email) { loginAttempts.delete(clientKey(req, email)); }
function mfaKey(req, userId) { return req.ip + ':' + userId; }
function checkMfaLockout(req, userId) { const item = mfaAttempts.get(mfaKey(req, userId)); return Boolean(item && item.until > Date.now()); }
function recordMfaFailure(req, userId) { const key = mfaKey(req, userId); const item = mfaAttempts.get(key) || { count: 0, until: 0 }; item.count += 1; if (item.count >= 5) item.until = Date.now() + 15 * 60 * 1000; mfaAttempts.set(key, item); }
function clearMfaFailures(req, userId) { mfaAttempts.delete(mfaKey(req, userId)); }

router.post('/login', validate(loginSchema), async (req, res) => {
  const { email, password } = req.body;
  if (checkLockout(req, email)) return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
  const user = store.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailure(req, email);
    addAudit(email, 'user.login', 'auth', 'denied', 'Invalid credentials', req.ip);
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  clearFailures(req, email);
  if (config.MFA_REQUIRED) {
    setPending(res, user);
    return res.json({ mfaRequired: true, mfaEnrolled: Boolean(user.mfaEnrolledAt), user: { id: user.id, email: user.email, name: user.name, role: user.role, department: user.department, tenant: user.tenant } });
  }
  const token = signSession(user); setSession(res, token);
  user.lastLogin = new Date().toISOString();
  addAudit(user.name, 'user.login', 'auth', 'success', 'password-only', req.ip);
  res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, department: user.department, tenant: user.tenant } });
});

router.get('/mfa/setup', (req, res) => {
  const pending = req.cookies?.[config.MFA_COOKIE];
  if (!pending) return res.status(401).json({ error: 'MFA setup requires a successful password step' });
  try {
    const payload = jwt.verify(pending, config.JWT_SECRET, { algorithms: ['HS256'], issuer: 'aegis-soc', audience: 'aegis-soc-api' });
    const user = store.users.find(u => u.id === payload.sub);
    if (!user) throw new Error('invalid');
    if (user.mfaEnrolledAt) return res.status(409).json({ error: 'MFA is already enrolled' });
    const secret = mfaSecretFor(user);
    const issuer = encodeURIComponent('Aegis SOC');
    const label = encodeURIComponent(user.email);
    return res.json({ secret, otpauth: `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` });
  } catch { return res.status(401).json({ error: 'Invalid MFA setup session' }); }
});

router.post('/mfa/verify', validate(mfaSchema), (req, res) => {
  const pending = req.cookies?.[config.MFA_COOKIE];
  if (!pending) return res.status(401).json({ error: 'MFA verification required' });
  try {
    const payload = jwt.verify(pending, config.JWT_SECRET, { algorithms: ['HS256'], issuer: 'aegis-soc', audience: 'aegis-soc-api' });
    const user = store.users.find(u => u.id === payload.sub);
    if (!user) return res.status(401).json({ error: 'Invalid MFA session' });
    if (checkMfaLockout(req, user.id)) return res.status(429).json({ error: 'Too many MFA attempts. Try again later.' });
    if (!verifyTotp(mfaSecretFor(user), req.body.code)) { recordMfaFailure(req, user.id); return res.status(401).json({ error: 'Invalid MFA code' }); }
    clearMfaFailures(req, user.id);
    user.mfaEnrolledAt = user.mfaEnrolledAt || new Date().toISOString();
    clearPending(res);
    setSession(res, signSession(user));
    user.lastLogin = new Date().toISOString();
    addAudit(user.name, 'user.login', 'auth', 'success', 'password+mfa', req.ip);
    res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, department: user.department, tenant: user.tenant, mfaEnabled: true } });
  } catch { return res.status(401).json({ error: 'Invalid MFA session' }); }
});

router.get('/me', authenticate, (req, res) => {
  const user = store.users.find(u => u.id === req.user.id);
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role, department: user.department, tenant: user.tenant, mfaEnabled: true, lastLogin: user.lastLogin });
});

router.post('/logout', authenticate, (req, res) => {
  addAudit(req.user.name, 'user.logout', 'auth', 'success', '', req.ip);
  res.clearCookie(config.SESSION_COOKIE, { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE, path: '/' });
  res.clearCookie(config.MFA_COOKIE, { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE, path: '/' });
  res.json({ ok: true });
});

export default router;
