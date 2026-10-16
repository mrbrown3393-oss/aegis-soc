const API = '/api';

function getToken() {
  return localStorage.getItem('aegis_token');
}

export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(opts.headers as Record<string, string>)
  };
  const res = await fetch(`${API}${path}`, { ...opts, headers, credentials: 'include' });
  if (res.status === 401) {
    localStorage.removeItem('aegis_user');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const auth = {
  login: (email: string, password: string) =>
    api<{ mfaRequired?: boolean; user: import('../types').User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    }),
  me: () => api<import('../types').User>('/auth/me'),
  mfaSetup: () => api<{ secret: string; otpauth: string }>('/auth/mfa/setup'),
  mfaVerify: (code: string) => api<{ user: import('../types').User }>('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code }) }),
  logout: () => api('/auth/logout', { method: 'POST' })
};

export const dashboard = {
  overview: async (): Promise<import('../types').Overview> => {
    const [metrics, incidents, assets, threats] = await Promise.all([
      api<{ total_threats: number; open_incidents: number; critical: number; high: number; trend: { _id: string; count: number }[]; severity_distribution: Record<string, number> }>('/metrics/overview'),
      api<Record<string, unknown>[]>('/incidents'),
      api<Record<string, unknown>[]>('/assets'),
      api<Record<string, unknown>[]>('/threats?limit=100')
    ]);
    const activeIncidents = incidents.filter(i => String(i.status).toLowerCase() !== 'resolved').map(i => ({
      id: String(i.id ?? ''),
      title: String(i.title ?? 'Untitled incident'),
      severity: String(i.severity ?? 'unknown'),
      status: String(i.status ?? 'open'),
      createdAt: String(i.created_at ?? ''),
      updatedAt: String(i.updated_at ?? i.created_at ?? ''),
      owner: typeof i.assignee === 'string' ? i.assignee : null,
      relatedAlerts: [],
      timeline: [],
      impact: ''
    }));
    const recentAlerts = threats.map(t => ({
      id: String(t.id ?? ''),
      title: String(t.title ?? 'Untitled threat'),
      severity: String(t.severity ?? 'unknown') as import('../types').Alert['severity'],
      status: 'open',
      source: String(t.source_ip ?? ''),
      category: 'threat',
      assetId: String(t.affected_asset ?? ''),
      riskScore: Number(t.confidence ?? 0),
      createdAt: String(t.timestamp ?? ''),
      updatedAt: String(t.timestamp ?? ''),
      assignee: null,
      description: String(t.description ?? '')
    }));
    const severityCounts = metrics.severity_distribution ?? {};
    const critical = Number(severityCounts.critical ?? metrics.critical ?? 0);
    const high = Number(severityCounts.high ?? metrics.high ?? 0);
    return {
      simulation: false,
      generatedAt: new Date().toISOString(),
      kpis: {
        openAlerts: recentAlerts.length,
        criticalAlerts: critical,
        highAlerts: high,
        openIncidents: Number(metrics.open_incidents ?? activeIncidents.length),
        assetsMonitored: assets.length,
        identitiesMonitored: 0,
        avgIdentityRisk: 0,
        policyCoverage: 0,
        overallRiskScore: Math.min(100, critical * 10 + high * 5),
        riskLevel: critical > 0 ? 'critical' : high > 0 ? 'elevated' : 'low'
      },
      assetHealth: { healthy: 0, warning: 0, critical: 0 },
      recentAlerts: recentAlerts.slice(0, 10),
      activeIncidents: activeIncidents.slice(0, 10),
      health: {},
      threatIntelCount: Number(metrics.total_threats ?? recentAlerts.length),
      expiringCredentials: 0
    };
  },
  health: () => api('/auth/')
};

export const alerts = {
  list: async (params?: Record<string, string>) => {
    const query = new URLSearchParams({ limit: '100', ...(params ?? {}) }).toString();
    const rows = await api<Record<string, unknown>[]>(`/threats?${query}`);
    const data: import('../types').Alert[] = rows.map(t => ({
      id: String(t.id ?? ''),
      title: String(t.title ?? 'Untitled threat'),
      severity: String(t.severity ?? 'low') as import('../types').Alert['severity'],
      status: 'open',
      source: String(t.source_ip ?? ''),
      category: 'threat',
      assetId: String(t.affected_asset ?? ''),
      riskScore: Number(t.confidence ?? 0),
      createdAt: String(t.timestamp ?? ''),
      updatedAt: String(t.timestamp ?? ''),
      assignee: null,
      description: String(t.description ?? '')
    }));
    return { data, total: data.length };
  },
  update: (id: string, body: Partial<import('../types').Alert>) =>
    api(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
};

export const incidents = {
  list: async () => {
    const rows = await api<Record<string, unknown>[]>('/incidents');
    const data: import('../types').Incident[] = rows.map(i => ({
      id: String(i.id ?? ''),
      title: String(i.title ?? 'Untitled incident'),
      severity: String(i.severity ?? 'unknown'),
      status: String(i.status ?? 'open'),
      createdAt: String(i.created_at ?? ''),
      updatedAt: String(i.updated_at ?? i.created_at ?? ''),
      owner: typeof i.assignee === 'string' ? i.assignee : null,
      relatedAlerts: [],
      timeline: [],
      impact: ''
    }));
    return { data, total: data.length };
  },
  update: (id: string, body: Record<string, unknown>) =>
    api(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
};

export const assets = {
  list: async () => {
    const rows = await api<Record<string, unknown>[]>('/assets');
    const data: import('../types').Asset[] = rows.map(a => ({
      id: String(a.id ?? ''),
      name: String(a.name ?? 'Unnamed asset'),
      type: String(a.type ?? 'unknown'),
      os: String(a.os ?? 'Unknown'),
      ip: String(a.ip ?? ''),
      criticality: Number(a.risk_score ?? 0) >= 80 ? 'critical' : Number(a.risk_score ?? 0) >= 50 ? 'high' : 'medium',
      status: 'monitored',
      owner: '',
      lastSeen: String(a.last_seen ?? ''),
      tags: []
    }));
    return { data, total: data.length };
  },
  identities: () => api<{ data: import('../types').Identity[]; total: number }>('/assets/identities'),
  credentials: () => api<{ data: unknown[]; total: number }>('/assets/credentials'),
  policies: () => api<{ data: unknown[]; total: number }>('/assets/policies')
};

export const threat = {
  intel: () => api<{ data: unknown[]; total: number }>('/threat/intel'),
  events: (limit = 50) => api<{ data: unknown[]; total: number }>(`/threat/events?limit=${limit}`),
  audit: (limit = 50) => api<{ data: unknown[]; total: number }>(`/threat/audit?limit=${limit}`)
};

export const ai = {
  chat: (message: string, history?: { role: string; content: string }[]) =>
    api<{ reply: string; intent?: string; simulation: boolean; model?: string }>('/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, history })
    }),
  analyzeAlert: (id: string) => api(`/ai/analyze/alert/${id}`),
  status: () => api<{ name: string; status: string; mode: string; model?: string; note?: string; capabilities: string[] }>('/ai/status')
};
