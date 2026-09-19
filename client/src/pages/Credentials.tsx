import { useEffect, useState } from 'react';
import { assets as api } from '../lib/api';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow } from 'date-fns';

interface Cred {
  id: string; name: string; type: string; owner: string; status: string;
  created: string; expires: string | null; lastRotated: string; risk: string; vault: string;
}

export default function Credentials() {
  const [list, setList] = useState<Cred[]>([]);
  useEffect(() => { api.credentials().then(r => setList(r.data as Cred[])); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Credential Lifecycle</h1>
        <p className="text-sm text-slate-500">Secrets, API keys, and rotation posture</p>
      </div>
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-slate-500 border-b border-surface-600">
              <th className="p-3 font-medium">Name</th>
              <th className="p-3 font-medium">Type</th>
              <th className="p-3 font-medium">Owner</th>
              <th className="p-3 font-medium">Status</th>
              <th className="p-3 font-medium">Risk</th>
              <th className="p-3 font-medium">Vault</th>
              <th className="p-3 font-medium">Last Rotated</th>
            </tr>
          </thead>
          <tbody>
            {list.map(c => (
              <tr key={c.id} className="border-b border-surface-700/40 hover:bg-surface-700/30">
                <td className="p-3 font-medium font-mono text-xs">{c.name}</td>
                <td className="p-3 capitalize text-slate-400">{c.type.replace('_', ' ')}</td>
                <td className="p-3 text-slate-400">{c.owner}</td>
                <td className="p-3"><SeverityBadge value={c.status} /></td>
                <td className="p-3"><SeverityBadge value={c.risk} /></td>
                <td className="p-3 text-slate-400">{c.vault}</td>
                <td className="p-3 text-xs text-slate-500">{formatDistanceToNow(new Date(c.lastRotated), { addSuffix: true })}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
