import { useEffect, useState } from 'react';
import { threat as api } from '../lib/api';
import { formatDistanceToNow } from 'date-fns';

interface IOC {
  id: string; type: string; value: string; confidence: number;
  source: string; tags: string[]; firstSeen: string; lastSeen: string; relatedAlerts: number;
}

export default function ThreatIntel() {
  const [list, setList] = useState<IOC[]>([]);
  useEffect(() => { api.intel().then(r => setList(r.data as IOC[])); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Threat Intelligence</h1>
        <p className="text-sm text-slate-500">Ingested IOCs and external feed correlation (simulated)</p>
      </div>
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-slate-500 border-b border-surface-600">
              <th className="p-3 font-medium">Type</th>
              <th className="p-3 font-medium">Value</th>
              <th className="p-3 font-medium">Confidence</th>
              <th className="p-3 font-medium">Source</th>
              <th className="p-3 font-medium">Tags</th>
              <th className="p-3 font-medium">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {list.map(i => (
              <tr key={i.id} className="border-b border-surface-700/40 hover:bg-surface-700/30">
                <td className="p-3 uppercase text-xs font-mono text-aegis-400">{i.type}</td>
                <td className="p-3 font-mono text-xs break-all max-w-xs">{i.value}</td>
                <td className="p-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-surface-600 rounded-full overflow-hidden">
                      <div className="h-full bg-aegis-500 rounded-full" style={{ width: `${i.confidence}%` }} />
                    </div>
                    <span className="font-mono text-xs">{i.confidence}%</span>
                  </div>
                </td>
                <td className="p-3 text-slate-400">{i.source}</td>
                <td className="p-3"><div className="flex flex-wrap gap-1">{i.tags.map(t => (<span key={t} className="badge bg-surface-600 text-slate-300 border border-surface-500">{t}</span>))}</div></td>
                <td className="p-3 text-xs text-slate-500">{formatDistanceToNow(new Date(i.lastSeen), { addSuffix: true })}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
