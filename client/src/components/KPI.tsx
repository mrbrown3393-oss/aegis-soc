import { LucideIcon } from 'lucide-react';
import clsx from 'clsx';

interface Props {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  accent?: 'default' | 'danger' | 'warn' | 'ok';
}

export default function KPI({ label, value, icon: Icon, trend, accent = 'default' }: Props) {
  const colors = {
    default: 'text-aegis-400 bg-aegis-500/10',
    danger: 'text-red-400 bg-red-500/10',
    warn: 'text-amber-400 bg-amber-500/10',
    ok: 'text-emerald-400 bg-emerald-500/10'
  };
  return (
    <div className="card p-4 flex items-start gap-3">
      <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center shrink-0', colors[accent])}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="min-w-0">
        <div className="text-xs text-slate-500 font-medium uppercase tracking-wide">{label}</div>
        <div className="text-2xl font-semibold mt-0.5 tabular-nums">{value}</div>
        {trend && <div className="text-xs text-slate-500 mt-0.5">{trend}</div>}
      </div>
    </div>
  );
}
