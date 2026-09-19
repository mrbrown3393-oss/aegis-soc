import { useEffect, useState } from 'react';
import { incidents as api } from '../lib/api';
import type { Incident } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import { formatDistanceToNow, format } from 'date-fns';

export default function Incidents() {
  const [list, setList] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<Incident | null>(null);
  useEffect(() => { api.list().then(r => setList(r.data)); }, []);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Incident Management</h1>
        <p className="text-sm text-slate-500">Track and coordinate response to security incidents</p>
      </div>
      <div className="grid lg:grid-cols-5 gap-4">
        <div className="lg:col-span-2 space-y-2">
          {list.map(inc => (
            <button key={inc.id} onClick={() => setSelected(inc)} className={`w-full text-left card p-4 transition-colors hover:border-aegis-600/40 ${selected?.id === inc.id ? 'border-aegis-600/50 bg-aegis-600/5' : ''}`}>
              <div className="flex items-start justify-between gap-2">
                <div className="font-medium text-sm">{inc.title}</div>
                <SeverityBadge value={inc.severity} />
              </div>
              <div className="flex items-center gap-2 mt-2 text-xs text-slate-500">
                <SeverityBadge value={inc.status} />
                <span>{inc.owner || 'Unassigned'}</span>
                <span>·</span>
                <span>{formatDistanceToNow(new Date(inc.updatedAt), { addSuffix: true })}</span>
              </div>
            </button>
          ))}
        </div>
        <div className="lg:col-span-3 card p-5">
          {selected ? (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold">{selected.title}</h2>
                <div className="flex flex-wrap gap-2 mt-2">
                  <SeverityBadge value={selected.severity} />
                  <SeverityBadge value={selected.status} />
                  <span className="badge bg-surface-600 text-slate-300 border border-surface-500">{selected.id}</span>
                </div>
              </div>
              <p className="text-sm text-slate-400">{selected.impact}</p>
              <div className="text-sm">
                <span className="text-slate-500">Owner:</span> {selected.owner || 'Unassigned'}
                <span className="mx-2 text-slate-600">·</span>
                <span className="text-slate-500">Related alerts:</span> {selected.relatedAlerts.join(', ')}
              </div>
              <div>
                <h3 className="text-sm font-semibold mb-3">Timeline</h3>
                <div className="space-y-3 relative before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-surface-600">
                  {selected.timeline.map((t, i) => (
                    <div key={i} className="pl-6 relative">
                      <div className="absolute left-0 top-1.5 w-4 h-4 rounded-full bg-surface-700 border-2 border-aegis-500" />
                      <div className="text-xs text-slate-500 font-mono">{format(new Date(t.ts), 'MMM d, HH:mm')} · {t.actor}</div>
                      <div className="text-sm mt-0.5">{t.action}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-slate-500 text-sm">Select an incident</div>
          )}
        </div>
      </div>
    </div>
  );
}
