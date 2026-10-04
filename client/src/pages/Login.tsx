import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertCircle } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { auth as authApi } from '../lib/api';

export default function Login() {
  const { login, verifyMfa, mfaPending } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [setupSecret, setSetupSecret] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handlePassword(e: FormEvent) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      const complete = await login(email, password);
      if (complete) navigate('/');
      else {
        const setup = await authApi.mfaSetup();
        setSetupSecret(setup.secret);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally { setLoading(false); }
  }

  async function handleMfa(e: FormEvent) {
    e.preventDefault(); setError(''); setLoading(true);
    try { await verifyMfa(code); navigate('/'); }
    catch (err) { setError(err instanceof Error ? err.message : 'MFA verification failed'); }
    finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-surface-900 via-surface-800 to-aegis-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex w-14 h-14 rounded-2xl bg-aegis-600 items-center justify-center shadow-glow mb-4"><Shield className="w-8 h-8 text-white" /></div>
          <h1 className="text-2xl font-bold tracking-tight">Aegis SOC</h1>
          <p className="text-slate-400 text-sm mt-1">Zero-Trust Security Operations Platform</p>
        </div>
        <form onSubmit={mfaPending ? handleMfa : handlePassword} className="card p-6 space-y-4">
          <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-xs text-amber-200/90">
            <strong>Simulation mode</strong> — telemetry is synthetic; authentication controls are enforced.
          </div>
          {error && <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2"><AlertCircle className="w-4 h-4 shrink-0" /> {error}</div>}
          {!mfaPending ? <>
            <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Email</label><input type="email" className="input" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="username" /></div>
            <div><label className="block text-xs font-medium text-slate-400 mb-1.5">Password</label><input type="password" className="input" value={password} onChange={e => setPassword(e.target.value)} required autoComplete="current-password" /></div>
            <button type="submit" className="btn-primary w-full py-2.5" disabled={loading}>{loading ? 'Checking…' : 'Continue'}</button>
          </> : <>
            <div className="text-sm text-slate-300">Enter the 6-digit code from your authenticator app.</div>
            {setupSecret && <div className="rounded-lg bg-slate-900/60 border border-slate-700 p-3 text-xs text-slate-300">First-time setup secret: <code className="break-all">{setupSecret}</code><div className="mt-1 text-slate-500">Add this secret to a TOTP authenticator, then enter the current code.</div></div>}
            <input inputMode="numeric" pattern="\d{6}" maxLength={6} className="input tracking-[0.5em] text-center" value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} required autoComplete="one-time-code" aria-label="MFA code" />
            <button type="submit" className="btn-primary w-full py-2.5" disabled={loading}>{loading ? 'Verifying…' : 'Verify MFA'}</button>
          </>}
        </form>
      </div>
    </div>
  );
}
