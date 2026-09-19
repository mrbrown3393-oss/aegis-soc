import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertCircle } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('admin@aegis.demo');
  const [password, setPassword] = useState('AegisDemo2026!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-surface-900 via-surface-800 to-aegis-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex w-14 h-14 rounded-2xl bg-aegis-600 items-center justify-center shadow-glow mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Aegis SOC</h1>
          <p className="text-slate-400 text-sm mt-1">Zero-Trust Security Operations Platform</p>
        </div>
        <form onSubmit={handleSubmit} className="card p-6 space-y-4">
          <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-xs text-amber-200/90">
            <strong>Simulation mode</strong> — All data is synthetic. No real systems are accessed.
          </div>
          {error && (
            <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              <AlertCircle className="w-4 h-4 shrink-0" /> {error}
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Email</label>
            <input type="email" className="input" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="username" />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Password</label>
            <input type="password" className="input" value={password} onChange={e => setPassword(e.target.value)} required autoComplete="current-password" />
          </div>
          <button type="submit" className="btn-primary w-full py-2.5" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
          <div className="text-[11px] text-slate-500 space-y-1 pt-2 border-t border-surface-600">
            <p className="font-medium text-slate-400">Demo accounts (password: AegisDemo2026!)</p>
            <p>admin@aegis.demo · analyst@aegis.demo · viewer@aegis.demo</p>
          </div>
        </form>
      </div>
    </div>
  );
}
