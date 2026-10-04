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
  overview: () => api<import('../types').Overview>('/dashboard/overview'),
  health: () => api('/dashboard/health')
};

export const alerts = {
  list: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : '';
    return api<{ data: import('../types').Alert[]; total: number }>(`/alerts${q}`);
  },
  update: (id: string, body: Partial<import('../types').Alert>) =>
    api(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
};

export const incidents = {
  list: () => api<{ data: import('../types').Incident[]; total: number }>('/incidents'),
  update: (id: string, body: Record<string, unknown>) =>
    api(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
};

export const assets = {
  list: () => api<{ data: import('../types').Asset[]; total: number }>('/assets'),
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
