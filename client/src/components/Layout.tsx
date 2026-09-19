import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, ShieldAlert, AlertTriangle, Server, Users,
  Key, FileText, Activity, Globe, ScrollText, LogOut, Shield, Menu, X, Sparkles
} from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import clsx from 'clsx';

const nav = [
  { to: '/', label: 'Executive Overview', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alert Triage', icon: ShieldAlert },
  { to: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { to: '/assets', label: 'Assets', icon: Server },
  { to: '/identities', label: 'Identities', icon: Users },
  { to: '/credentials', label: 'Credentials', icon: Key },
  { to: '/policies', label: 'Policies', icon: FileText },
  { to: '/threat-intel', label: 'Threat Intel', icon: Globe },
  { to: '/events', label: 'Live Events', icon: Activity },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
  { to: '/grok', label: 'Grok Analyst', icon: Sparkles }
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <aside className={clsx(
        'fixed inset-y-0 left-0 z-40 w-64 bg-surface-800 border-r border-surface-600 flex flex-col transition-transform lg:static lg:translate-x-0',
        open ? 'translate-x-0' : '-translate-x-full'
      )}>
        <div className="flex items-center gap-3 px-5 py-4 border-b border-surface-600">
          <div className="w-9 h-9 rounded-lg bg-aegis-600 flex items-center justify-center shadow-glow">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="font-semibold text-sm tracking-tight">Aegis SOC</div>
            <div className="text-[10px] text-aegis-400 font-mono uppercase tracking-wider">Zero-Trust · Simulation</div>
          </div>
          <button className="ml-auto lg:hidden" onClick={() => setOpen(false)}>
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>
        <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-0.5">
          {nav.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              onClick={() => setOpen(false)}
              className={({ isActive }) => clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-aegis-600/20 text-aegis-300 border border-aegis-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-surface-700'
              )}
            >
              <item.icon className="w-4 h-4 shrink-0" />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-surface-600">
          <div className="px-3 py-2 mb-1">
            <div className="text-sm font-medium truncate">{user?.name}</div>
            <div className="text-xs text-slate-500 truncate">{user?.role} · {user?.department}</div>
          </div>
          <button onClick={handleLogout} className="btn-ghost w-full justify-start text-slate-400">
            <LogOut className="w-4 h-4" /> Sign out
          </button>
        </div>
      </aside>
      {open && (
        <div className="fixed inset-0 bg-black/50 z-30 lg:hidden" onClick={() => setOpen(false)} />
      )}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="h-14 border-b border-surface-600 bg-surface-800/80 backdrop-blur flex items-center px-4 gap-3 shrink-0">
          <button className="lg:hidden btn-ghost p-2" onClick={() => setOpen(true)}>
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex-1" />
          <span className="badge bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse" />
            Live Simulation
          </span>
        </header>
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
