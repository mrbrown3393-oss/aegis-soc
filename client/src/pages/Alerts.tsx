import { useEffect, useState } from 'react';
import { alerts as alertsApi } from '../lib/api';
import type { Alert } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow } from 'date-fns';
import { Search, Filter } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export default function Alerts() {
  const { user } = useAuth();
  const [list, setList] = useState<Alert[]>([]);
  const [filter, setFilter] = useState({ status: '', severity: '', q: '' });
  const [selected, setSelected] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  async function load() {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (filter.status) params.status = filter.status;
      if (filter.severity) params.severity = filter.severity;
      if (filter.q) params.q = filter.q;
      const res = await alertsApi.list(params);
      setList(res.data);
    } finally { setLoading(false); }
  }
  useEffect(() => { load(); }, [filter.status, filter.severity]);
  async function updateStatus(id: string, status: string) {
    await alertsApi.update(id, { status });
    load();
    if (selected?.id === id) setSelected({ ...selected, status });
  }
  const canAct = user?.role === 'admin' || user?.role === 'analyst';
  return (
    <div className="space-y-4">
      <div><h1 className="text-xl font-semibold">Alert Triage</h1><p className="text-sm text-slate-500">Investigate, assign, and resolve security alerts</p></div>
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input className="input pl-9" placeholder="Search alerts…" value={filter.q} onChange={e => setFilter(f => ({ ...f, q: e.target.value }))} onKeyDown={e => e.key === 'Enter' && load()} />
        </div>
        <select className="input w-auto" value={filter.severity} onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}>
          <option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <select className="input w-auto" value={filter.status} onChange={e => setFilter(f => ({ ...f, status: e.target.value }))}>
          <option value="">All statuses</option><option value="new">New</option><option value="triaging">Triaging</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option>
        </select>
        <button className="btn-primary" onClick={load}><Filter className="w-4 h-4" /> Apply</button>
      </div>
      <div className="grid lg:grid-cols-5 gap-4">
        <div className="lg:col-span-3 card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-800"><tr className="text-left text-xs text-slate-500 border-b border-surface-600"><th className="p-3">Title</th><th className="p-3">Sev</th><th className="p-3">Status</th><th className="p-3">Risk</th></tr></thead>
            <tbody>
              {loading ? <tr><td colSpan={4} className="p-6 text-center text-slate-500">Loading…</td></tr> : list.map(a => (
                <tr key={a.id} onClick={() => setSelected(a)} className={`border-b border-surface-700/40 cursor-pointer hover:bg-surface-700/40 ${selected?.id === a.id ? 'bg-aegis-600/10' : ''}`}>
                  <td className="p-3 max-w-[220px] truncate">{a.title}</td>
                  <td className="p-3"><SeverityBadge value={a.severity} /></td>
                  <td className="p-3"><SeverityBadge value={a.status} /></td>
                  <td className="p-3 font-mono text-xs">{a.riskScore}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="lg:col-span-2 card p-4">
          {selected ? (
            <div className="space-y-4">
              <h2 className="font-semibold">{selected.title}</h2>
              <div className="flex flex-wrap gap-2"><SeverityBadge value={selected.severity} /><SeverityBadge value={selected.status} /></div>
              <p className="text-sm text-slate-400">{selected.description}</p>
              {selected.aiSummary && <div className="rounded-lg bg-aegis-600/10 border border-aegis-600/20 p-3 text-sm text-aegis-200"><div className="text-xs font-medium text-aegis-400 mb-1">AI-Assisted Analysis</div>{selected.aiSummary}</div>}
              {canAct && (
                <div className="flex flex-wrap gap-2 pt-2 border-t border-surface-600">
                  <button className="btn-primary text-xs" onClick={() => updateStatus(selected.id, 'triaging')}>Start Triage</button>
                  <button className="btn-ghost text-xs border border-surface-500" onClick={() => updateStatus(selected.id, 'investigating')}>Investigate</button>
                  <button className="btn-ghost text-xs border border-emerald-500/30 text-emerald-400" onClick={() => updateStatus(selected.id, 'resolved')}>Resolve</button>
                </div>
              )}
              <div className="text-xs text-slate-500">{formatDistanceToNow(new Date(selected.createdAt), { addSuffix: true })}</div>
            </div>
          ) : <div className="text-slate-500 text-sm h-40 flex items-center justify-center">Select an alert to inspect</div>}
        </div>
      </div>
    </div>
  );
}
