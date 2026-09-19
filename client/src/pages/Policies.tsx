import { useEffect, useState } from 'react';
import { assets as api } from '../lib/api';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow } from 'date-fns';

interface Policy {
  id: string; name: string; category: string; status: string;
  coverage: number; violations: number; lastEval: string;
}

export default function Policies() {
  const [list, setList] = useState<Policy[]>([]);
  useEffect(() => { api.policies().then(r => setList(r.data as Policy[])); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Policy Enforcement</h1>
        <p className="text-sm text-slate-500">Zero-trust and compliance policy posture</p>
      </div>
      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-3">
        {list.map(p => (
          <div key={p.id} className="card p-4">
            <div className="flex items-start justify-between gap-2">
              <h3 className="font-medium text-sm">{p.name}</h3>
              <SeverityBadge value={p.status} />
            </div>
            <div className="text-xs text-slate-500 capitalize mt-1">{p.category}</div>
            <div className="mt-3">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-500">Coverage</span>
                <span className="font-mono">{p.coverage}%</span>
              </div>
              <div className="h-1.5 bg-surface-600 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${p.coverage >= 90 ? 'bg-emerald-500' : p.coverage >= 70 ? 'bg-aegis-500' : 'bg-amber-500'}`} style={{ width: `${p.coverage}%` }} />
              </div>
            </div>
            <div className="flex justify-between text-xs mt-3 text-slate-500">
              <span>{p.violations} violations</span>
              <span>Eval {formatDistanceToNow(new Date(p.lastEval), { addSuffix: true })}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
