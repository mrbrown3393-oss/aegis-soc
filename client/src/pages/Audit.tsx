import { useEffect, useState } from 'react';
import { threat as api } from '../lib/api';
import { format } from 'date-fns';

interface AuditEntry {
  id: string; ts: string; actor: string; action: string; resource: string;
  ip: string; outcome: string; details: string;
}

export default function Audit() {
  const [list, setList] = useState<AuditEntry[]>([]);
  useEffect(() => { api.audit(80).then(r => setList(r.data as AuditEntry[])); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Audit Log</h1>
        <p className="text-sm text-slate-500">Immutable record of platform actions (simulated)</p>
      </div>
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-slate-500 border-b border-surface-600">
              <th className="p-3 font-medium">Timestamp</th>
              <th className="p-3 font-medium">Actor</th>
              <th className="p-3 font-medium">Action</th>
              <th className="p-3 font-medium">Resource</th>
              <th className="p-3 font-medium">IP</th>
              <th className="p-3 font-medium">Outcome</th>
            </tr>
          </thead>
          <tbody>
            {list.map(a => (
              <tr key={a.id} className="border-b border-surface-700/40 hover:bg-surface-700/30">
                <td className="p-3 font-mono text-xs text-slate-500 whitespace-nowrap">{format(new Date(a.ts), 'yyyy-MM-dd HH:mm:ss')}</td>
                <td className="p-3">{a.actor}</td>
                <td className="p-3 font-mono text-xs text-aegis-300">{a.action}</td>
                <td className="p-3 font-mono text-xs text-slate-400">{a.resource}</td>
                <td className="p-3 font-mono text-xs text-slate-500">{a.ip}</td>
                <td className="p-3"><span className={a.outcome === 'success' ? 'text-emerald-400' : 'text-red-400'}>{a.outcome}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
