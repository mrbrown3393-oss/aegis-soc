import { useEffect, useRef, useState, FormEvent } from 'react';
import { ai } from '../lib/api';
import { Sparkles, Send, Bot, User, Loader2 } from 'lucide-react';

interface Msg { role: 'user' | 'assistant'; content: string; }
const STARTERS = ['What should I triage first?', 'Summarize current risk posture', 'Explain identity risks', 'Which credentials need rotation?', 'Walk me through defensive incident response'];

function renderMarkdownLite(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => part.startsWith('**') && part.endsWith('**') ? <strong key={i} className="text-slate-100 font-semibold">{part.slice(2, -2)}</strong> : <span key={i}>{part}</span>);
}

export default function GrokAnalyst() {
  const [messages, setMessages] = useState<Msg[]>([{ role: 'assistant', content: "Hey — I'm **Grok**, your embedded AI Security Analyst in Aegis SOC.\n\nAsk me what to prioritize, or pick a starter below." }]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('online');
  const [mode, setMode] = useState('simulation');
  const [model, setModel] = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => { ai.status().then(s => { setStatus(s.status); setMode(s.mode || 'simulation'); setModel(s.model || ''); }).catch(() => setStatus('unknown')); }, []);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, loading]);
  async function send(text: string) {
    const q = text.trim();
    if (!q || loading) return;
    const next: Msg[] = [...messages, { role: 'user', content: q }];
    setMessages(next); setInput(''); setLoading(true);
    try {
      const history = next.slice(-10).map(m => ({ role: m.role, content: m.content }));
      const res = await ai.chat(q, history);
      setMessages(m => [...m, { role: 'assistant', content: res.reply }]);
    } catch {
      setMessages(m => [...m, { role: 'assistant', content: 'Sorry — analyst service error. Is the API running?' }]);
    } finally { setLoading(false); }
  }
  function onSubmit(e: FormEvent) { e.preventDefault(); send(input); }
  return (
    <div className="flex flex-col h-[calc(100vh-7rem)] max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-aegis-500 to-violet-600 flex items-center justify-center shadow-glow"><Sparkles className="w-5 h-5 text-white" /></div>
          <div>
            <h1 className="text-xl font-semibold">Grok Analyst</h1>
            <p className="text-xs text-slate-500">AI Security Co-Pilot · {status} · {mode === 'live' ? 'Live xAI' : 'Simulation'}{model ? ` · ${model}` : ''}</p>
          </div>
        </div>
        <span className={`badge border ${mode === 'live' ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/25' : 'bg-violet-500/15 text-violet-300 border-violet-500/25'}`}>{mode === 'live' ? 'Live Grok API' : 'Local Grok Analyst'}</span>
      </div>
      <div className="card flex-1 flex flex-col overflow-hidden min-h-0">
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : ''}`}>
              {m.role === 'assistant' && <div className="w-8 h-8 rounded-lg bg-violet-600/30 flex items-center justify-center shrink-0"><Bot className="w-4 h-4 text-violet-300" /></div>}
              <div className={`max-w-[85%] rounded-2xl px-4 py-2.5 text-sm whitespace-pre-wrap ${m.role === 'user' ? 'bg-aegis-600 text-white' : 'bg-surface-700/80 text-slate-200 border border-surface-600'}`}>{m.role === 'assistant' ? renderMarkdownLite(m.content) : m.content}</div>
              {m.role === 'user' && <div className="w-8 h-8 rounded-lg bg-aegis-600/30 flex items-center justify-center shrink-0"><User className="w-4 h-4 text-aegis-300" /></div>}
            </div>
          ))}
          {loading && <div className="flex gap-3"><Loader2 className="w-4 h-4 text-violet-300 animate-spin" /><span className="text-sm text-slate-400">Analyzing SOC context…</span></div>}
          <div ref={bottomRef} />
        </div>
        {messages.length <= 2 && <div className="px-4 pb-2 flex flex-wrap gap-2">{STARTERS.map(s => <button key={s} type="button" onClick={() => send(s)} className="text-xs px-3 py-1.5 rounded-full border border-surface-500 text-slate-400 hover:text-aegis-300">{s}</button>)}</div>}
        <form onSubmit={onSubmit} className="p-3 border-t border-surface-600 flex gap-2">
          <input className="input flex-1" placeholder="Ask Grok about alerts, risk, identities…" value={input} onChange={e => setInput(e.target.value)} disabled={loading} maxLength={2000} />
          <button type="submit" className="btn-primary px-4" disabled={loading || !input.trim()}><Send className="w-4 h-4" /></button>
        </form>
      </div>
    </div>
  );
}
