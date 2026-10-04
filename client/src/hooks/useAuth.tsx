import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { auth as authApi } from '../lib/api';
import type { User } from '../types';

interface AuthCtx {
  user: User | null;
  loading: boolean;
  mfaPending: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  verifyMfa: (code: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [mfaPending, setMfaPending] = useState(false);

  useEffect(() => {
    authApi.me().then(u => setUser(u)).catch(() => setUser(null)).finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const result = await authApi.login(email, password);
    if (result.mfaRequired) {
      setMfaPending(true);
      return false;
    }
    setUser(result.user);
    return true;
  }

  async function verifyMfa(code: string) {
    const result = await authApi.mfaVerify(code);
    setUser(result.user);
    setMfaPending(false);
  }

  async function logout() {
    try { await authApi.logout(); } catch { /* session may already be expired */ }
    localStorage.removeItem('aegis_user');
    setUser(null);
    setMfaPending(false);
  }

  return <Ctx.Provider value={{ user, loading, mfaPending, login, verifyMfa, logout }}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useAuth outside provider');
  return ctx;
}
