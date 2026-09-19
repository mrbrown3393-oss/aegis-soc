import { useEffect, useState, useRef } from 'react';
import { threat as api } from '../lib/api';
import SeverityBadge from '../components/SeverityBadge';
import { format } from 'date-fns';
import { Activity } from 'lucide-react';

interface Event {
  id: string; ts: string; type: string; source: string; severity: string; message: string; assetId: string;
}

export default function Events() {
  const [events, setEvents] = useState<Event[]>([]);
  const [live, setLive] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => { api.events(80).then(r => setEvents((r.data as Event[]).reverse())); }, []);
  useEffect(() => {
    if (!live) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${proto}://${window.location.host}/ws`;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(wsUrl);
      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          if (data.type === 'event') setEvents(prev => [...prev.slice(-99), data.data]);
        } catch { /* ignore */ }
      };
    } catch { /* fallback */ }
    const poll = setInterval(() => {
      if (!live) return;
      api.events(20).then(r => {
        setEvents(prev => {
          const ids = new Set(prev.map(e => e.id));
          const fresh = (r.data as Event[]).filter(e => !ids.has(e.id));
          if (!fresh.length) return prev;
          return [...prev, ...fresh.reverse()].slice(-100);
        });
      }).catch(() => {});
    }, 8000);
    return () => { clearInterval(poll); try { ws?.close(); } catch { /* */ } };
  }, [live]);
  useEffect(() => { if (live) bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [events, live]);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Live Security Events</h1>
          <p className="text-sm text-slate-500">Streaming simulated telemetry from collectors</p>
        </div>
        <button className={`btn text-xs ${live ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : 'btn-ghost border border-surface-500'}`} onClick={() => setLive(l => !l)}>
          <Activity className={`w-3.5 h-3.5 ${live ? 'animate-pulse' : ''}`} />
          {live ? 'Live' : 'Paused'}
        </button>
      </div>
      <div className="card p-0 overflow-hidden">
        <div className="max-h-[calc(100vh-200px)] overflow-y-auto font-mono text-xs">
          {events.map(e => (
            <div key={e.id} className="flex items-start gap-3 px-4 py-2 border-b border-surface-700/40 hover:bg-surface-700/20">
              <span className="text-slate-600 shrink-0 w-36">{format(new Date(e.ts), 'HH:mm:ss.SSS')}</span>
              <SeverityBadge value={e.severity} />
              <span className="text-aegis-400 shrink-0 w-28">{e.source}</span>
              <span className="text-slate-400 shrink-0 w-32">{e.type}</span>
              <span className="text-slate-300 flex-1 truncate">{e.message}</span>
              <span className="text-slate-600 shrink-0">{e.assetId}</span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}
