import { useEffect, useState } from 'react';
import { assets as api } from '../lib/api';
import type { Asset } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow } from 'date-fns';

export default function Assets() {
  const [list, setList] = useState<Asset[]>([]);
  useEffect(() => { api.list().then(r => setList(r.data)); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Asset Inventory</h1>
        <p className="text-sm text-slate-500">Continuous monitoring of infrastructure and endpoints</p>
      </div>
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 border-b border-surface-600">
                <th className="p-3 font-medium">Name</th>
                <th className="p-3 font-medium">Type</th>
                <th className="p-3 font-medium">OS / Platform</th>
                <th className="p-3 font-medium">IP</th>
                <th className="p-3 font-medium">Criticality</th>
                <th className="p-3 font-medium">Status</th>
                <th className="p-3 font-medium">Owner</th>
                <th className="p-3 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {list.map(a => (
                <tr key={a.id} className="border-b border-surface-700/40 hover:bg-surface-700/30">
                  <td className="p-3 font-medium">{a.name}</td>
                  <td className="p-3 capitalize text-slate-400">{a.type}</td>
                  <td className="p-3 text-slate-400">{a.os}</td>
                  <td className="p-3 font-mono text-xs">{a.ip}</td>
                  <td className="p-3"><SeverityBadge value={a.criticality} /></td>
                  <td className="p-3"><SeverityBadge value={a.status} /></td>
                  <td className="p-3 text-slate-400">{a.owner}</td>
                  <td className="p-3 text-xs text-slate-500">{formatDistanceToNow(new Date(a.lastSeen), { addSuffix: true })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
