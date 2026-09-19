import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, AlertTriangle, Server, Users, Shield, Activity, Key, FileCheck, TrendingUp } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { dashboard } from '../lib/api';
import type { Overview as OverviewData } from '../types';
import KPI from '../components/KPI';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow } from 'date-fns';

export default function Overview() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const d = await dashboard.overview();
        if (active) setData(d);
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : 'Failed to load');
      }
    }
    load();
    const t = setInterval(load, 15000);
    return () => { active = false; clearInterval(t); };
  }, []);
  if (error) return <div className="text-red-400">{error}</div>;
  if (!data) return <div className="text-slate-500 animate-pulse">Loading executive overview…</div>;
  const { kpis, assetHealth, recentAlerts, activeIncidents, health } = data;
  const riskColor = kpis.riskLevel === 'critical' ? 'text-red-400' : kpis.riskLevel === 'elevated' ? 'text-orange-400' : kpis.riskLevel === 'moderate' ? 'text-amber-400' : 'text-emerald-400';
  const healthData = Object.entries(health).map(([k, v]) => ({ name: k, status: (v as { status: string }).status }));
  const assetPie = [
    { name: 'Healthy', value: assetHealth.healthy, color: '#34d399' },
    { name: 'Warning', value: assetHealth.warning, color: '#fbbf24' },
    { name: 'Critical', value: assetHealth.critical || 0, color: '#f87171' }
  ];
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Executive Overview</h1>
          <p className="text-sm text-slate-500 mt-0.5">Zero-trust posture · Updated {formatDistanceToNow(new Date(data.generatedAt), { addSuffix: true })}</p>
        </div>
        <div className="card px-4 py-2 flex items-center gap-3">
          <TrendingUp className={riskColor} />
          <div>
            <div className="text-[10px] uppercase text-slate-500 tracking-wider">Org Risk Score</div>
            <div className={`text-xl font-bold tabular-nums ${riskColor}`}>{kpis.overallRiskScore}<span className="text-sm font-normal ml-1.5 capitalize">{kpis.riskLevel}</span></div>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <KPI label="Open Alerts" value={kpis.openAlerts} icon={ShieldAlert} accent={kpis.criticalAlerts > 0 ? 'danger' : 'default'} />
        <KPI label="Critical" value={kpis.criticalAlerts} icon={AlertTriangle} accent="danger" />
        <KPI label="Incidents" value={kpis.openIncidents} icon={AlertTriangle} accent={kpis.openIncidents > 1 ? 'warn' : 'default'} />
        <KPI label="Assets" value={kpis.assetsMonitored} icon={Server} accent="ok" />
        <KPI label="Identities" value={kpis.identitiesMonitored} icon={Users} />
        <KPI label="Policy Coverage" value={`${kpis.policyCoverage}%`} icon={FileCheck} accent="ok" />
      </div>
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="card p-4 lg:col-span-2">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-aegis-400" /> Recent Open Alerts</h2>
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-slate-500 border-b border-surface-600"><th className="pb-2">Alert</th><th className="pb-2">Severity</th><th className="pb-2">Status</th><th className="pb-2">Source</th></tr></thead>
            <tbody>
              {recentAlerts.map(a => (
                <tr key={a.id} className="border-b border-surface-700/50">
                  <td className="py-2.5"><Link to="/alerts" className="hover:text-aegis-300">{a.title}</Link></td>
                  <td><SeverityBadge value={a.severity} /></td>
                  <td><SeverityBadge value={a.status} /></td>
                  <td className="text-slate-400 font-mono text-xs">{a.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="space-y-4">
          <div className="card p-4">
            <h2 className="text-sm font-semibold mb-3">Asset Health</h2>
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={assetPie} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={60} paddingAngle={3}>
                    {assetPie.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#1a2234', border: '1px solid #2d3a54', borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="card p-4">
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2"><Activity className="w-4 h-4 text-aegis-400" /> Platform Health</h2>
            <div className="space-y-2">{healthData.map(h => (<div key={h.name} className="flex items-center justify-between text-sm"><span className="text-slate-400 capitalize">{h.name}</span><SeverityBadge value={h.status} /></div>))}</div>
          </div>
        </div>
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="card p-4">
          <h2 className="text-sm font-semibold mb-3">Active Incidents</h2>
          {activeIncidents.map(inc => (
            <div key={inc.id} className="p-3 mb-2 rounded-lg bg-surface-900/50 border border-surface-600">
              <div className="flex justify-between gap-2"><div className="font-medium text-sm">{inc.title}</div><SeverityBadge value={inc.severity} /></div>
              <div className="mt-1.5"><SeverityBadge value={inc.status} /></div>
            </div>
          ))}
        </div>
        <div className="card p-4">
          <h2 className="text-sm font-semibold mb-3">Alert Pressure</h2>
          <div className="h-40">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={[{ name: 'Critical', count: kpis.criticalAlerts }, { name: 'High', count: kpis.highAlerts }, { name: 'Open', count: kpis.openAlerts }]}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#1a2234', border: '1px solid #2d3a54', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="#0c8ce9" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card p-3 flex items-center gap-3"><Key className="w-5 h-5 text-amber-400" /><div><div className="text-xs text-slate-500">Expiring Credentials</div><div className="text-lg font-semibold">{data.expiringCredentials}</div></div></div>
        <div className="card p-3 flex items-center gap-3"><Shield className="w-5 h-5 text-aegis-400" /><div><div className="text-xs text-slate-500">Threat Intel IOCs</div><div className="text-lg font-semibold">{data.threatIntelCount}</div></div></div>
        <div className="card p-3 flex items-center gap-3"><Users className="w-5 h-5 text-violet-400" /><div><div className="text-xs text-slate-500">Avg Identity Risk</div><div className="text-lg font-semibold">{kpis.avgIdentityRisk}</div></div></div>
        <div className="card p-3 flex items-center gap-3"><FileCheck className="w-5 h-5 text-emerald-400" /><div><div className="text-xs text-slate-500">Policy Coverage</div><div className="text-lg font-semibold">{kpis.policyCoverage}%</div></div></div>
      </div>
    </div>
  );
}
