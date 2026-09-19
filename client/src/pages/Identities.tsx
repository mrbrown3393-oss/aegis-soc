import { useEffect, useState } from 'react';
import { assets as api } from '../lib/api';
import type { Identity } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow } from 'date-fns';

function riskLevel(score: number) {
  if (score >= 60) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

export default function Identities() {
  const [list, setList] = useState<Identity[]>([]);
  useEffect(() => { api.identities().then(r => setList(r.data)); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Identity Monitoring</h1>
        <p className="text-sm text-slate-500">Users, service accounts, and privilege risk</p>
      </div>
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-slate-500 border-b border-surface-600">
              <th className="p-3 font-medium">Principal</th>
              <th className="p-3 font-medium">Type</th>
              <th className="p-3 font-medium">Provider</th>
              <th className="p-3 font-medium">Risk</th>
              <th className="p-3 font-medium">MFA</th>
              <th className="p-3 font-medium">Privileges</th>
              <th className="p-3 font-medium">Anomalies</th>
              <th className="p-3 font-medium">Last Auth</th>
            </tr>
          </thead>
          <tbody>
            {list.map(i => (
              <tr key={i.id} className="border-b border-surface-700/40 hover:bg-surface-700/30">
                <td className="p-3 font-medium font-mono text-xs">{i.principal}</td>
                <td className="p-3 capitalize">{i.type}</td>
                <td className="p-3 text-slate-400">{i.provider}</td>
                <td className="p-3"><div className="flex items-center gap-2"><span className="font-mono text-xs w-6">{i.riskScore}</span><SeverityBadge value={riskLevel(i.riskScore)} /></div></td>
                <td className="p-3">{i.mfa ? <SeverityBadge value="enforced" /> : <span className="text-slate-500 text-xs">No</span>}</td>
                <td className="p-3 capitalize text-slate-400">{i.privileges}</td>
                <td className="p-3">{i.anomalies > 0 ? <span className="text-amber-400">{i.anomalies}</span> : 0}</td>
                <td className="p-3 text-xs text-slate-500">{formatDistanceToNow(new Date(i.lastAuth), { addSuffix: true })}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
