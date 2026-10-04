import { store } from '../data/store.js';
import { config } from '../config.js';

const SYSTEM_PERSONA = `You are Grok, embedded as the AI Security Analyst inside Aegis SOC.
Defensive cybersecurity only. No attack methods. Label simulation vs real data. Be concise and actionable.`;

function contextSnapshot() {
  const openAlerts = store.alerts.filter(a => !['resolved', 'dismissed'].includes(a.status));
  const critical = openAlerts.filter(a => a.severity === 'critical').length;
  const openInc = store.incidents.filter(i => !['closed', 'resolved'].includes(i.status)).length;
  const highRiskIds = store.identities.filter(i => i.riskScore >= 50).map(i => i.principal);
  const expiring = store.credentials.filter(c => c.status === 'expiring' || c.risk === 'critical');
  return {
    openAlerts: openAlerts.length,
    criticalAlerts: critical,
    openIncidents: openInc,
    highRiskIdentities: highRiskIds.slice(0, 5),
    expiringCredentials: expiring.map(c => c.name),
    policyAvg: policies.length ? Math.round(policies.reduce((s, p) => s + p.coverage, 0) / policies.length) : 0,
    recentAlertTitles: openAlerts.slice(0, 5).map(a => `[${a.severity}] ${a.title}`)
  };
}

function matchIntent(q) {
  const t = q.toLowerCase();
  if (/risk|posture|summar|overview|status/.test(t)) return 'risk';
  if (/critical|urgent|priorit|triage/.test(t)) return 'priority';
  if (/incident|contain|respond|playbook/.test(t)) return 'incident';
  if (/identity|mfa|privilege|account/.test(t)) return 'identity';
  if (/credential|secret|key|rotation/.test(t)) return 'credential';
  if (/policy|zero.?trust|compliance/.test(t)) return 'policy';
  if (/threat|ioc|indicator/.test(t)) return 'threat';
  if (/help|what can you|who are you/.test(t)) return 'help';
  return 'general';
}

function buildReply(intent, question, ctx) {
  if (intent === 'help') return "I'm **Grok**, your embedded AI Security Analyst.\nAsk about triage, risk, identities, credentials, or defensive incident response.";
  if (intent === 'priority') return `**Suggested triage**\n${ctx.recentAlertTitles.map((t,i)=>`${i+1}. ${t}`).join('\n') || 'No open alerts.'}`;
  if (intent === 'incident') return '**Defensive incident steps**\n1. Confirm scope\n2. Contain (isolate / revoke sessions)\n3. Preserve evidence\n4. Eradicate and rotate secrets\n5. Recover and document';
  if (intent === 'identity') return `**Identity risk**\n${ctx.highRiskIdentities.join(', ') || 'No elevated identities.'}`;
  if (intent === 'credential') return `**Credentials**\n${ctx.expiringCredentials.join(', ') || 'None flagged.'}`;
  if (intent === 'policy') return `**Policy coverage** ${ctx.policyAvg}%`;
  if (intent === 'threat') return 'Review Threat Intel IOCs, check internal sightings, and link related alerts.';
  return `**Current posture**\nOpen alerts: **${ctx.openAlerts}** (${ctx.criticalAlerts} critical)\nIncidents: **${ctx.openIncidents}**\nPolicy coverage: **${ctx.policyAvg}%**\n\n(Question: ${question.slice(0,120)})\n\n*— Grok · Aegis SOC*`;
}

export function hasLiveGrok() {
  return Boolean(config.XAI_API_KEY && config.XAI_API_KEY.trim().length > 8);
}

export function analystStatus() {
  const live = hasLiveGrok();
  return {
    name: 'Grok Analyst',
    status: 'online',
    mode: live ? 'live' : 'simulation',
    model: live ? config.XAI_MODEL : 'Grok-Analyst-Sim-v1',
    capabilities: ['SOC Q&A', 'Alert prioritization', 'Defensive IR guidance', 'Identity & credential review'],
    note: live ? `Live xAI Grok (${config.XAI_MODEL}). Telemetry is still simulated.` : 'Local co-pilot. Set XAI_API_KEY for live Grok.'
  };
}

async function callXai(messages) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.XAI_TIMEOUT_MS);
  try {
    const res = await fetch(`${config.XAI_API_BASE.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.XAI_API_KEY}` },
      body: JSON.stringify({ model: config.XAI_MODEL, temperature: 0.3, messages }),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`xAI HTTP ${res.status}`);
    const data = await res.json();
    const content = data?.choices?.[0]?.message?.content;
    if (!content) throw new Error('Empty xAI response');
    return String(content);
  } finally {
    clearTimeout(timer);
  }
}

export function analyzeAlert(alertId, user) {
  const alert = store.alerts.find(a => a.id === alertId && (user.role === 'admin' || user.role === 'owner' || a.tenant === user.tenant));
  if (!alert) return { error: 'Alert not found' };
  return { alertId, severity: alert.severity, summary: alert.aiSummary || alert.description, mitre: alert.mitre, simulation: true };
}

export async function chat(message, history = [], user) {
  const q = String(message || '').trim().slice(0, 2000);
  if (!q) return { reply: 'Ask me anything about the current security posture.', simulation: !hasLiveGrok() };
  const ctx = contextSnapshot(user);
  const intent = matchIntent(q);
  const contextUsed = { openAlerts: ctx.openAlerts, criticalAlerts: ctx.criticalAlerts, openIncidents: ctx.openIncidents };
  if (hasLiveGrok()) {
    try {
      const hist = Array.isArray(history) ? history.slice(-12) : [];
      const messages = [
        { role: 'system', content: SYSTEM_PERSONA },
        { role: 'system', content: `SOC snapshot: ${JSON.stringify(ctx)}` },
        ...hist.map(h => ({ role: h.role === 'assistant' ? 'assistant' : 'user', content: String(h.content || '').slice(0, 2000) })),
        { role: 'user', content: q }
      ];
      const reply = await callXai(messages);
      return { reply, intent, contextUsed, simulation: false, live: true, model: config.XAI_MODEL };
    } catch {
      return { reply: `${buildReply(intent, q, ctx)}\n\n_Live Grok API unavailable; local fallback._`, intent, contextUsed, simulation: true, live: false, fallback: true, model: 'Grok-Analyst-Sim-v1 (fallback)' };
    }
  }
  return { reply: buildReply(intent, q, ctx), intent, contextUsed, simulation: true, live: false, model: 'Grok-Analyst-Sim-v1' };
}
