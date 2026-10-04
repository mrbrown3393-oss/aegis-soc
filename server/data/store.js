import { v4 as uuid } from 'uuid';
import bcrypt from 'bcryptjs';

const hoursAgo = (h) => new Date(Date.now() - h * 3600000).toISOString();
const minsAgo = (m) => new Date(Date.now() - m * 60000).toISOString();
const passwordHash = bcrypt.hashSync('AegisDemo2026!', 10);

export const store = {
  users: [
    { id: 'usr-001', email: 'admin@aegis.demo', name: 'Alex Rivera', role: 'admin', tenant: 'saas', passwordHash, mfaEnabled: true, lastLogin: minsAgo(12), status: 'active', department: 'Security Operations' },
    { id: 'usr-002', email: 'analyst@aegis.demo', name: 'Jordan Lee', role: 'analyst', tenant: 'government', passwordHash, mfaEnabled: true, lastLogin: minsAgo(45), status: 'active', department: 'Threat Hunting' },
    { id: 'usr-003', email: 'viewer@aegis.demo', name: 'Sam Patel', role: 'viewer', tenant: 'private', passwordHash, mfaEnabled: false, lastLogin: hoursAgo(3), status: 'active', department: 'Executive' }
  ],
  assets: [
    { id: 'ast-001', name: 'prod-web-01', type: 'server', os: 'Ubuntu 24.04', ip: '10.10.1.21', criticality: 'critical', status: 'healthy', owner: 'Platform', lastSeen: minsAgo(2), tags: ['prod', 'web'] },
    { id: 'ast-002', name: 'prod-db-01', type: 'database', os: 'PostgreSQL 16', ip: '10.10.2.10', criticality: 'critical', status: 'healthy', owner: 'Data', lastSeen: minsAgo(1), tags: ['prod', 'pii'] },
    { id: 'ast-003', name: 'corp-laptop-42', type: 'endpoint', os: 'Windows 11', ip: '10.20.5.42', criticality: 'medium', status: 'warning', owner: 'Jordan Lee', lastSeen: minsAgo(18), tags: ['endpoint'] },
    { id: 'ast-004', name: 'k8s-worker-07', type: 'container', os: 'Containerd', ip: '10.30.1.7', criticality: 'high', status: 'healthy', owner: 'Platform', lastSeen: minsAgo(1), tags: ['k8s'] },
    { id: 'ast-005', name: 'vpn-gateway', type: 'network', os: 'VyOS', ip: '203.0.113.10', criticality: 'critical', status: 'healthy', owner: 'Network', lastSeen: minsAgo(0), tags: ['vpn'] },
    { id: 'ast-006', name: 'dev-workstation-12', type: 'endpoint', os: 'macOS Sequoia', ip: '10.20.8.12', criticality: 'low', status: 'healthy', owner: 'Engineering', lastSeen: hoursAgo(2), tags: ['dev'] },
    { id: 'ast-007', name: 's3-audit-logs', type: 'cloud', os: 'AWS S3', ip: 'N/A', criticality: 'high', status: 'healthy', owner: 'Security', lastSeen: minsAgo(5), tags: ['cloud'] },
    { id: 'ast-008', name: 'auth-idp', type: 'saas', os: 'Okta', ip: 'N/A', criticality: 'critical', status: 'healthy', owner: 'IAM', lastSeen: minsAgo(1), tags: ['identity'] }
  ],
  identities: [
    { id: 'id-001', principal: 'admin@aegis.demo', type: 'user', provider: 'Okta', riskScore: 12, mfa: true, lastAuth: minsAgo(12), devices: 2, privileges: 'admin', anomalies: 0 },
    { id: 'id-002', principal: 'svc-backup', type: 'service', provider: 'Internal', riskScore: 45, mfa: false, lastAuth: hoursAgo(1), devices: 0, privileges: 'high', anomalies: 1 },
    { id: 'id-003', principal: 'jordan.lee@aegis.demo', type: 'user', provider: 'Okta', riskScore: 28, mfa: true, lastAuth: minsAgo(45), devices: 3, privileges: 'analyst', anomalies: 0 },
    { id: 'id-004', principal: 'contractor-ext-09', type: 'user', provider: 'Azure AD', riskScore: 67, mfa: true, lastAuth: hoursAgo(6), devices: 1, privileges: 'limited', anomalies: 2 },
    { id: 'id-005', principal: 'ci-cd-runner', type: 'service', provider: 'GitHub', riskScore: 22, mfa: false, lastAuth: minsAgo(8), devices: 0, privileges: 'deploy', anomalies: 0 },
    { id: 'id-006', principal: 'sam.patel@aegis.demo', type: 'user', provider: 'Okta', riskScore: 8, mfa: false, lastAuth: hoursAgo(3), devices: 1, privileges: 'viewer', anomalies: 0 }
  ],
  alerts: [],
  incidents: [],
  events: [],
  threatIntel: [],
  auditLog: [],
  credentials: [
    { id: 'cred-001', name: 'prod-db-master', type: 'password', owner: 'Data Platform', status: 'active', created: hoursAgo(720), expires: hoursAgo(-168), lastRotated: hoursAgo(720), risk: 'high', vault: 'HashiCorp' },
    { id: 'cred-002', name: 'aws-deploy-key', type: 'api_key', owner: 'Platform', status: 'active', created: hoursAgo(240), expires: hoursAgo(-480), lastRotated: hoursAgo(240), risk: 'medium', vault: 'AWS Secrets' },
    { id: 'cred-003', name: 'okta-api-token', type: 'token', owner: 'IAM', status: 'expiring', created: hoursAgo(480), expires: hoursAgo(-24), lastRotated: hoursAgo(480), risk: 'critical', vault: 'Internal' },
    { id: 'cred-004', name: 'github-actions-pat', type: 'token', owner: 'Engineering', status: 'active', created: hoursAgo(120), expires: hoursAgo(-600), lastRotated: hoursAgo(120), risk: 'medium', vault: 'GitHub' },
    { id: 'cred-005', name: 'vpn-shared-secret', type: 'shared_secret', owner: 'Network', status: 'active', created: hoursAgo(2160), expires: null, lastRotated: hoursAgo(2160), risk: 'high', vault: 'Network' }
  ],
  policies: [
    { id: 'pol-001', name: 'MFA Enforcement', category: 'identity', status: 'enforced', coverage: 94, violations: 3, lastEval: minsAgo(5) },
    { id: 'pol-002', name: 'Least Privilege Access', category: 'access', status: 'enforced', coverage: 87, violations: 8, lastEval: minsAgo(12) },
    { id: 'pol-003', name: 'Endpoint Encryption', category: 'device', status: 'enforced', coverage: 99, violations: 1, lastEval: minsAgo(2) },
    { id: 'pol-004', name: 'Network Segmentation', category: 'network', status: 'partial', coverage: 72, violations: 15, lastEval: minsAgo(30) },
    { id: 'pol-005', name: 'Credential Rotation 90d', category: 'secrets', status: 'enforced', coverage: 81, violations: 5, lastEval: hoursAgo(1) },
    { id: 'pol-006', name: 'Zero-Trust Device Posture', category: 'device', status: 'enforced', coverage: 91, violations: 4, lastEval: minsAgo(8) }
  ],
  health: {
    collectors: { status: 'healthy', lastHeartbeat: minsAgo(0) },
    correlation: { status: 'healthy', queueDepth: 12 },
    threatIntel: { status: 'healthy', feedsActive: 6 },
    storage: { status: 'healthy', retentionDays: 90, usedPct: 34 },
    aiEngine: { status: 'healthy', model: 'Aegis-Anomaly-v2.1 (simulated)' },
    authService: { status: 'healthy', latencyMs: 18 }
  }
};

const alertTemplates = [
  { title: 'Impossible travel detected', severity: 'high', source: 'UEBA', category: 'identity', asset: 'id-004' },
  { title: 'Brute force attempt on VPN', severity: 'critical', source: 'IDS', category: 'network', asset: 'ast-005' },
  { title: 'Unusual process execution', severity: 'medium', source: 'EDR', category: 'endpoint', asset: 'ast-003' },
  { title: 'Privilege escalation attempt', severity: 'high', source: 'SIEM', category: 'identity', asset: 'id-002' },
  { title: 'Suspicious outbound C2 pattern', severity: 'critical', source: 'NDR', category: 'network', asset: 'ast-001' },
  { title: 'Stale credential in use', severity: 'medium', source: 'Secrets Scanner', category: 'secrets', asset: 'cred-001' },
  { title: 'Policy violation: MFA bypass', severity: 'high', source: 'IdP', category: 'identity', asset: 'id-006' },
  { title: 'Anomalous data access volume', severity: 'medium', source: 'DLP', category: 'data', asset: 'ast-002' },
  { title: 'New device without posture check', severity: 'low', source: 'ZTNA', category: 'device', asset: 'ast-006' },
  { title: 'Threat intel match: known bad IP', severity: 'high', source: 'TI Feed', category: 'threat', asset: 'ast-005' }
];

for (let i = 0; i < 28; i++) {
  const t = alertTemplates[i % alertTemplates.length];
  const sev = t.severity;
  store.alerts.push({
    id: `alr-${String(i + 1).padStart(3, '0')}`,
    title: t.title,
    severity: sev,
    status: i < 4 ? 'new' : i < 10 ? 'triaging' : i < 18 ? 'investigating' : 'resolved',
    source: t.source,
    category: t.category,
    assetId: t.asset,
    riskScore: sev === 'critical' ? 85 + (i % 10) : sev === 'high' ? 60 + (i % 15) : sev === 'medium' ? 35 + (i % 20) : 10 + (i % 15),
    createdAt: hoursAgo(Math.floor(i * 2.5) + (i % 5)),
    updatedAt: minsAgo(i * 3),
    assignee: i % 3 === 0 ? 'Jordan Lee' : i % 3 === 1 ? 'Alex Rivera' : null,
    description: `Simulated detection: ${t.title}.`,
    mitre: ['T1078', 'T1110', 'T1059', 'T1048', 'T1071'][i % 5],
    aiSummary: `AI analysis (simulated): Pattern matches historical ${sev} activity.`
  });
}

store.incidents = [
  { id: 'inc-001', title: 'Suspected credential stuffing campaign', severity: 'high', status: 'investigating', createdAt: hoursAgo(18), updatedAt: minsAgo(40), owner: 'Jordan Lee', relatedAlerts: ['alr-001', 'alr-007'], timeline: [{ ts: hoursAgo(18), actor: 'system', action: 'Incident auto-created' }, { ts: hoursAgo(12), actor: 'Jordan Lee', action: 'Blocked source IPs' }], impact: 'Possible account takeover risk' },
  { id: 'inc-002', title: 'C2 beaconing from production web tier', severity: 'critical', status: 'contained', createdAt: hoursAgo(36), updatedAt: hoursAgo(4), owner: 'Alex Rivera', relatedAlerts: ['alr-005'], timeline: [{ ts: hoursAgo(36), actor: 'system', action: 'Critical alert escalated' }, { ts: hoursAgo(35), actor: 'Alex Rivera', action: 'Isolated host' }], impact: 'Temporary isolation of production web node' },
  { id: 'inc-003', title: 'Service account privilege anomaly', severity: 'medium', status: 'open', createdAt: hoursAgo(8), updatedAt: hoursAgo(2), owner: null, relatedAlerts: ['alr-004'], timeline: [{ ts: hoursAgo(8), actor: 'system', action: 'Incident created' }], impact: 'Elevated lateral movement risk' }
];

store.threatIntel = [
  { id: 'ti-001', type: 'ip', value: '185.220.101.45', confidence: 92, source: 'Aegis TI', tags: ['tor', 'c2'], firstSeen: hoursAgo(48), lastSeen: minsAgo(20), relatedAlerts: 2 },
  { id: 'ti-002', type: 'domain', value: 'update-cdn-check[.]net', confidence: 88, source: 'OSINT', tags: ['phishing'], firstSeen: hoursAgo(40), lastSeen: minsAgo(40), relatedAlerts: 1 },
  { id: 'ti-003', type: 'hash', value: 'e3b0c44298fc1c149afbf4c8996fb924...', confidence: 95, source: 'Malware DB', tags: ['trojan'], firstSeen: hoursAgo(30), lastSeen: minsAgo(60), relatedAlerts: 0 },
  { id: 'ti-004', type: 'ip', value: '45.142.212.220', confidence: 79, source: 'Partner Feed', tags: ['scanner'], firstSeen: hoursAgo(24), lastSeen: minsAgo(80), relatedAlerts: 0 }
];

const auditActions = ['user.login', 'alert.acknowledge', 'incident.update', 'policy.evaluate', 'credential.view', 'asset.scan'];
for (let i = 0; i < 40; i++) {
  store.auditLog.push({
    id: `aud-${String(i + 1).padStart(3, '0')}`,
    ts: hoursAgo(i * 0.7),
    actor: ['Alex Rivera', 'Jordan Lee', 'system', 'Sam Patel'][i % 4],
    action: auditActions[i % auditActions.length],
    resource: i % 2 === 0 ? `alr-${String((i % 10) + 1).padStart(3, '0')}` : `inc-00${(i % 3) + 1}`,
    ip: `10.20.${(i % 20) + 1}.${(i % 200) + 10}`,
    outcome: i % 11 === 0 ? 'denied' : 'success',
    details: 'Simulated audit entry'
  });
}

export function generateEvent() {
  const types = ['auth.success', 'auth.failure', 'network.connection', 'process.start', 'file.access', 'policy.check', 'dns.query'];
  const type = types[Math.floor(Math.random() * types.length)];
  return {
    id: uuid(),
    ts: new Date().toISOString(),
    type,
    source: ['EDR', 'IdP', 'Firewall', 'Proxy', 'CloudTrail'][Math.floor(Math.random() * 5)],
    severity: Math.random() > 0.85 ? 'high' : Math.random() > 0.6 ? 'medium' : 'low',
    message: `Simulated ${type} event`,
    assetId: store.assets[Math.floor(Math.random() * store.assets.length)].id,
    raw: { simulation: true }
  };
}

for (let i = 0; i < 50; i++) {
  const e = generateEvent();
  e.ts = minsAgo(50 - i);
  store.events.push(e);
}

export function addAudit(actor, action, resource, outcome = 'success', details = '', ip = '') {
  store.auditLog.unshift({
    id: `aud-${uuid().slice(0, 8)}`,
    ts: new Date().toISOString(),
    actor,
    action,
    resource,
    ip: ip || 'unknown',
    outcome,
    details
  });
  if (store.auditLog.length > 500) store.auditLog.pop();
}


const tenantBuckets = ['government', 'private', 'saas'];
for (const [name, items] of Object.entries({
  assets: store.assets,
  identities: store.identities,
  alerts: store.alerts,
  incidents: store.incidents,
  events: store.events,
  threatIntel: store.threatIntel,
  credentials: store.credentials,
  policies: store.policies
})) {
  items.forEach((item, index) => { if (!item.tenant) item.tenant = tenantBuckets[index % tenantBuckets.length]; });
}
