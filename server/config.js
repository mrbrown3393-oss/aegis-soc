/**
 * Aegis SOC — Configuration
 * Secure defaults. Secrets come from environment / .env — never from source.
 */
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
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

export const config = {
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET || 'aegis-sim-only-change-in-production-9f3a2b1c',
  JWT_EXPIRES_IN: '8h',
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000,
  RATE_LIMIT_MAX: 300,
  SIMULATION_MODE: true,
  CORS_ORIGIN: process.env.CORS_ORIGIN || true,
  ORG_NAME: 'Aegis Demo Corporation',
  VERSION: '1.0.0',
  XAI_API_KEY: process.env.XAI_API_KEY || '',
  XAI_API_BASE: process.env.XAI_API_BASE || 'https://api.x.ai/v1',
  XAI_MODEL: process.env.XAI_MODEL || 'grok-4',
  XAI_TIMEOUT_MS: Number(process.env.XAI_TIMEOUT_MS || 25000)
};
