/**
 * Aegis SOC — Main Server
 * Defensive security operations platform with simulated telemetry.
 */
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { config } from './config.js';
import { store, generateEvent } from './data/store.js';

import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';
import alertRoutes from './routes/alerts.js';
import incidentRoutes from './routes/incidents.js';
import assetRoutes from './routes/assets.js';
import threatRoutes from './routes/threat.js';
import aiRoutes from './routes/ai.js';

const app = express();
const server = createServer(app);

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: config.CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
}));

app.use((req, res, next) => {
  res.setHeader('X-Aegis-Mode', 'SIMULATION');
  next();
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: config.VERSION, mode: 'simulation', timestamp: new Date().toISOString() });
});

app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/assets', assetRoutes);
app.use('/api/threat', threatRoutes);
app.use('/api/ai', aiRoutes);

app.use('/api/*', (_req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, _req, res, _next) => {
  console.error('[Aegis]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync } from 'fs';
const __dirname = dirname(fileURLToPath(import.meta.url));
const clientDist = join(__dirname, '../client/dist');
if (config.NODE_ENV === 'production' && existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get('*', (_req, res) => res.sendFile(join(clientDist, 'index.html')));
}

const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();
wss.on('connection', (ws) => {
  clients.add(ws);
  ws.send(JSON.stringify({ type: 'connected', mode: 'simulation', ts: new Date().toISOString() }));
  ws.on('close', () => clients.delete(ws));
  ws.on('error', () => clients.delete(ws));
});

function broadcast(msg) {
  const data = JSON.stringify(msg);
  for (const c of clients) if (c.readyState === 1) c.send(data);
}

setInterval(() => {
  const event = generateEvent();
  store.events.push(event);
  if (store.events.length > 300) store.events.shift();
  broadcast({ type: 'event', data: event });
}, 4000 + Math.random() * 3000);

setInterval(() => {
  if (Math.random() > 0.7) return;
  const templates = [
    { title: 'Anomalous login location', severity: 'medium', source: 'UEBA', category: 'identity' },
    { title: 'High volume DNS queries', severity: 'low', source: 'NDR', category: 'network' },
    { title: 'Endpoint posture drift', severity: 'medium', source: 'ZTNA', category: 'device' }
  ];
  const t = templates[Math.floor(Math.random() * templates.length)];
  const alert = {
    id: `alr-${Date.now().toString(36)}`,
    title: t.title,
    severity: t.severity,
    status: 'new',
    source: t.source,
    category: t.category,
    assetId: store.assets[Math.floor(Math.random() * store.assets.length)].id,
    riskScore: t.severity === 'medium' ? 40 + Math.floor(Math.random() * 20) : 15 + Math.floor(Math.random() * 15),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    assignee: null,
    description: `Live simulated detection: ${t.title}`,
    mitre: 'T1078',
    aiSummary: 'AI (simulated): Low confidence pattern. Monitor for escalation.'
  };
  store.alerts.unshift(alert);
  if (store.alerts.length > 100) store.alerts.pop();
  broadcast({ type: 'alert', data: alert });
}, 25000 + Math.random() * 20000);

server.listen(config.PORT, '0.0.0.0', () => {
  console.log(`Aegis SOC v${config.VERSION} · SIMULATION · http://0.0.0.0:${config.PORT}`);
  console.log('Demo: admin@aegis.demo / analyst@aegis.demo / viewer@aegis.demo  password AegisDemo2026!');
});
