/** Aegis SOC — fail-closed security configuration. */
import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const envPath = join(rootDir, '.env');

if (existsSync(envPath)) {
  const raw = readFileSync(envPath, 'utf8');
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!(key in process.env)) process.env[key] = value;
  }
}

const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || '';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '';

if (NODE_ENV === 'production') {
  if (JWT_SECRET.length < 32) throw new Error('Production requires JWT_SECRET >= 32 characters.');
  if (!CORS_ORIGIN || CORS_ORIGIN === '*') throw new Error('Production requires an explicit CORS_ORIGIN.');
  if (!/^https:\/\//i.test(CORS_ORIGIN)) throw new Error('Production CORS_ORIGIN must use HTTPS.');
}

export const config = {
  PORT: Number(process.env.PORT || 3000),
  NODE_ENV,
  JWT_SECRET: JWT_SECRET || 'development-only-secret-replace-before-deploy',
  JWT_EXPIRES_IN: '15m',
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000,
  RATE_LIMIT_MAX: 120,
  SIMULATION_MODE: true,
  CORS_ORIGIN: CORS_ORIGIN || 'http://localhost:3000',
  ORG_NAME: 'Aegis Demo Corporation',
  VERSION: '2.1.0',
  XAI_API_KEY: process.env.XAI_API_KEY || '',
  XAI_API_BASE: process.env.XAI_API_BASE || 'https://api.x.ai/v1',
  XAI_MODEL: process.env.XAI_MODEL || 'grok-4',
  XAI_TIMEOUT_MS: Number(process.env.XAI_TIMEOUT_MS || 25000),
  COOKIE_SECURE: NODE_ENV === 'production',
  COOKIE_SAMESITE: process.env.COOKIE_SAMESITE || (NODE_ENV === 'production' ? 'strict' : 'lax')
};
