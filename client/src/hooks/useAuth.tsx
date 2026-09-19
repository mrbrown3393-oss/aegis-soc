import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { auth as authApi } from '../lib/api';
import type { User } from '../types';

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('aegis_token');
    if (!token) {
      setLoading(false);
      return;
    }
    authApi.me()
      .then(u => setUser(u))
      .catch(() => {
        localStorage.removeItem('aegis_token');
        localStorage.removeItem('aegis_user');
      })
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const { token, user } = await authApi.login(email, password);
    localStorage.setItem('aegis_token', token);
    localStorage.setItem('aegis_user', JSON.stringify(user));
    setUser(user);
  }

  async function logout() {
    try { await authApi.logout(); } catch { /* ignore */ }
    localStorage.removeItem('aegis_token');
    localStorage.removeItem('aegis_user');
    setUser(null);
  }

  return (
    <Ctx.Provider value={{ user, loading, login, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useAuth outside provider');
  return ctx;
}
