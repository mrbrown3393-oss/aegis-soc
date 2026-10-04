/** Aegis SOC — Main Server */
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
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
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      formAction: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", 'https:'],
      upgradeInsecureRequests: config.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: config.CORS_ORIGIN, credentials: true, methods: ['GET','POST','PATCH','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(cookieParser());
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

const wss = new WebSocketServer({ noServer: true });
const clients = new Set();

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') return socket.destroy();
  const origin = req.headers.origin;
  if (origin && origin !== config.CORS_ORIGIN) return socket.destroy();
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(v => {
    const i = v.indexOf('=');
    return [v.slice(0, i).trim(), decodeURIComponent(v.slice(i + 1).trim())];
  }));
  const token = cookies['__Host-aegis_session'];
  try {
    const payload = jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'], issuer: 'aegis-soc', audience: 'aegis-soc-api' });
    const user = store.users.find(u => u.id === payload.sub);
    if (!user || user.status !== 'active' || payload.tenant !== user.tenant) throw new Error('unauthorized');
    wss.handleUpgrade(req, socket, head, ws => {
      ws.user = { id: user.id, role: user.role, tenant: user.tenant };
      wss.emit('connection', ws, req);
    });
  } catch {
    socket.destroy();
  }
});

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
  for (const c of clients) if (c.user && (c.user.role === 'admin' || c.user.role === 'owner' || c.user.tenant === event.tenant)) c.send(JSON.stringify({ type: 'event', data: event }));
}, 4000 + Math.random() * 3000);

setInterval(() => {
  if (Math.random() > 0.7) return;
  const templates = [
    { title: 'Anomalous login location', severity: 'medium', source: 'UEBA', category: 'identity' },
    { title: 'High volume DNS queries', severity: 'low', source: 'NDR', category: 'network' },
    { title: 'Endpoint posture drift', severity: 'medium', source: 'ZTNA', category: 'device' }
  ];
  const t = templates[Math.floor(Math.random() * templates.length)];
  const asset = store.assets[Math.floor(Math.random() * store.assets.length)];
  const alert = {
    id: `alr-${Date.now().toString(36)}`,
    tenant: asset.tenant,
    title: t.title,
    severity: t.severity,
    status: 'new',
    source: t.source,
    category: t.category,
    assetId: asset.id,
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
  console.log(`Aegis SOC v${config.VERSION} · SIMULATION · listening on port ${config.PORT}`);
});
